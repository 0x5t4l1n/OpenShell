// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration protocol of one streamed-apply supervisor session.
//!
//! The first connection prepares the startup policy against the workload
//! image. Every session then starts from a bootstrap update, and afterwards
//! holds at most one unacknowledged update. Session lifecycle and relays stay
//! in `supervisor_session`.

use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::time::{Duration, Instant};

use metrics::{counter, histogram};
use openshell_core::proto::{
    ConfigApplyOutcome, ConfigUpdate, ConfigUpdateResult, GatewayMessage, PolicyLoadResult,
    PolicySource, Sandbox, SandboxConfigRevision, SandboxConfigSnapshot,
    SandboxConfigurationAdmission, SandboxPolicy, StartupConfigCandidate, SupervisorHello,
    SupervisorMessage, gateway_message, startup_config_prepared, supervisor_message,
};
use prost::Message;
use tokio::sync::mpsc;
use tonic::Status;
use tracing::{debug, warn};
use uuid::Uuid;

use super::result_writer::{self, PolicyResult};
use super::{
    ConfigSlots, DeliveryDisposition, MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES, SupervisorConfig,
};
use crate::ServerState;
use crate::auth::principal::Principal;
use crate::grpc::policy::{
    build_provider_environment_snapshot_from_inputs, build_sandbox_config_snapshot,
    build_sandbox_config_snapshot_from_inputs, load_sandbox_config_inputs,
};
use crate::supervisor_session::{AcceptedSession, SupervisorSessionRegistry};

/// Streamed-apply supervisors start from the bootstrap, so allow a slow
/// credential resolution before rejecting the session. Session setup does not
/// hold a delivery build slot.
const CONFIG_BOOTSTRAP_BUILD_TIMEOUT: Duration = Duration::from_secs(45);
/// How long an invalid image policy waits for an operator to store a gateway
/// policy before the startup session is rejected.
const STARTUP_POLICY_REPAIR_TIMEOUT: Duration = Duration::from_mins(5);
/// How often a startup waiting for a policy repair checks again. Only
/// sandbox changes on this gateway wake it, so this picks up a global policy
/// or a change saved on another replica.
const STARTUP_POLICY_REPAIR_RECHECK: Duration = Duration::from_secs(1);
/// How long a session holds newer configuration while waiting for the
/// supervisor to acknowledge the update it already has.
const CONFIG_ACK_TIMEOUT: Duration = Duration::from_mins(1);

#[cfg(test)]
static FAIL_NEXT_ADMISSION_PERSISTENCE_FOR_SANDBOX: std::sync::LazyLock<Mutex<Option<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

/// Sandboxes whose startup build found no gateway policy and began waiting
/// for a repair.
#[cfg(test)]
static STARTUP_REPAIR_WAITS: std::sync::LazyLock<Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

// ---------------------------------------------------------------------------
// Configuration identity
// ---------------------------------------------------------------------------

/// Identifies a configuration the supervisor already has. The sandbox
/// configuration names its provider environment by revision, attachment
/// epoch, and policy hash, so it identifies the whole update.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ConfigFingerprint {
    revision: SandboxConfigRevision,
    provider_env_revision: u64,
    provider_attachment_epoch: String,
    policy_hash: String,
}

impl ConfigFingerprint {
    fn of(snapshot: &SandboxConfigSnapshot) -> Self {
        Self {
            revision: SandboxConfigRevision {
                config_revision: snapshot.config_revision,
                policy_version: snapshot.version,
                policy_source: snapshot.policy_source,
                global_policy_version: snapshot.global_policy_version,
                settings_revision: snapshot.settings_revision,
            },
            provider_env_revision: snapshot.provider_env_revision,
            provider_attachment_epoch: snapshot.provider_attachment_epoch.clone(),
            policy_hash: snapshot.policy_hash.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-session delivery state
// ---------------------------------------------------------------------------

/// Delivery state of a session that applies and acknowledges streamed
/// configuration. One update is in flight at a time, starting with the
/// bootstrap.
#[derive(Debug)]
pub struct ConfigSessionState {
    slots: Arc<ConfigSlots>,
    in_flight: Option<InFlightConfigUpdate>,
    /// Newest configuration built while an update was in flight.
    pending: Option<SupervisorConfig>,
    /// The configuration the supervisor last applied.
    acknowledged: Option<ConfigFingerprint>,
}

#[derive(Debug)]
struct InFlightConfigUpdate {
    update_id: String,
    fingerprint: ConfigFingerprint,
    admission: SandboxConfigurationAdmission,
    /// The session's bootstrap. It stays in flight until its result arrives
    /// or the session closes.
    bootstrap: bool,
    sent_at: Instant,
}

/// The bootstrap a session is accepted with, in flight from the start.
#[derive(Debug)]
pub struct BootstrapInFlight(InFlightConfigUpdate);

struct CompletedConfigUpdate {
    update_id: String,
    fingerprint: ConfigFingerprint,
    outcome: ConfigApplyOutcome,
    admission: SandboxConfigurationAdmission,
    bootstrap: bool,
    sent_at: Instant,
}

/// An update to queue on the session stream once the registry lock is
/// released.
struct Outgoing {
    slots: Arc<ConfigSlots>,
    message: GatewayMessage,
}

impl Outgoing {
    /// Returns true when an unsent update was replaced.
    fn send(self) -> bool {
        self.slots.replace(self.message)
    }
}

impl ConfigSessionState {
    pub fn new(slots: Arc<ConfigSlots>) -> Self {
        Self {
            slots,
            in_flight: None,
            pending: None,
            acknowledged: None,
        }
    }

    fn deliver(&mut self, config: SupervisorConfig) -> Result<Outgoing, DeliveryDisposition> {
        if self.in_flight.is_none()
            && self.acknowledged.as_ref() == Some(&ConfigFingerprint::of(&config.sandbox_config))
        {
            return Err(DeliveryDisposition::SuppressedUnchanged);
        }
        // Hold the configuration until the supervisor answers the update it
        // already has, bounded so a lost result cannot stall the session.
        if self
            .in_flight
            .as_ref()
            .is_some_and(|update| update.bootstrap || update.sent_at.elapsed() < CONFIG_ACK_TIMEOUT)
        {
            self.pending = Some(config);
            return Err(DeliveryDisposition::Coalesced);
        }
        self.pending = None;
        self.send(config)
    }

    fn send(&mut self, config: SupervisorConfig) -> Result<Outgoing, DeliveryDisposition> {
        let (update, in_flight) = build_config_update(config, false);
        let message = GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigUpdate(update)),
        };
        if message.encoded_len() > MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES {
            return Err(DeliveryDisposition::PayloadTooLarge);
        }
        self.in_flight = Some(in_flight);
        Ok(Outgoing {
            slots: Arc::clone(&self.slots),
            message,
        })
    }

    fn complete(&self, result: &ConfigUpdateResult) -> Result<CompletedConfigUpdate, Status> {
        let in_flight = self
            .in_flight
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("no update is in flight"))?;
        if in_flight.update_id != result.update_id {
            return Err(Status::invalid_argument(
                "configuration result does not match the in-flight update",
            ));
        }
        let outcome = ConfigApplyOutcome::try_from(result.outcome)
            .ok()
            .filter(|outcome| *outcome != ConfigApplyOutcome::Unspecified)
            .ok_or_else(|| Status::invalid_argument("configuration result outcome is required"))?;
        Ok(CompletedConfigUpdate {
            update_id: in_flight.update_id.clone(),
            fingerprint: in_flight.fingerprint.clone(),
            outcome,
            admission: in_flight.admission.clone(),
            bootstrap: in_flight.bootstrap,
            sent_at: in_flight.sent_at,
        })
    }

    /// Finish the update in flight and release configuration held behind
    /// it, unless the supervisor already has that configuration.
    fn finalize(
        &mut self,
        completed: &CompletedConfigUpdate,
        acknowledge: bool,
    ) -> Option<Outgoing> {
        if self
            .in_flight
            .as_ref()
            .is_none_or(|update| update.update_id != completed.update_id)
        {
            return None;
        }
        self.in_flight = None;
        if acknowledge && outcome_acknowledges_revision(completed.outcome) {
            self.acknowledged = Some(completed.fingerprint.clone());
        }
        let pending = self.pending.take()?;
        if self.acknowledged.as_ref() == Some(&ConfigFingerprint::of(&pending.sandbox_config)) {
            return None;
        }
        self.send(pending).ok()
    }

    /// Forget the acknowledged configuration, so the next delivery is sent
    /// even if unchanged.
    fn reopen(&mut self) {
        self.acknowledged = None;
    }
}

impl SupervisorSessionRegistry {
    /// Hand a configuration to the session it was built for. A replacement
    /// session received its own bootstrap and must not receive an older
    /// build.
    pub(crate) fn deliver_config(
        &self,
        sandbox_id: &str,
        session_id: &str,
        config: SupervisorConfig,
    ) -> DeliveryDisposition {
        let delivery = self.with_config_session(sandbox_id, session_id, |session| {
            session.map_or(Err(DeliveryDisposition::UnsupportedSession), |session| {
                session.deliver(config)
            })
        });
        match delivery {
            None => DeliveryDisposition::NoActiveSession,
            Some(Err(disposition)) => disposition,
            Some(Ok(outgoing)) => {
                if outgoing.send() {
                    DeliveryDisposition::Replaced
                } else {
                    DeliveryDisposition::Queued
                }
            }
        }
    }

    /// Hold configuration updates for a session until the bootstrap it was
    /// accepted with is answered.
    pub(crate) fn begin_config_bootstrap(
        &self,
        sandbox_id: &str,
        session_id: &str,
        bootstrap: BootstrapInFlight,
    ) {
        self.with_config_session(sandbox_id, session_id, |session| {
            if let Some(session) = session {
                session.in_flight = Some(bootstrap.0);
            }
        });
    }

    fn complete_config_update(
        &self,
        sandbox_id: &str,
        session_id: &str,
        result: &ConfigUpdateResult,
    ) -> Result<CompletedConfigUpdate, Status> {
        self.with_config_session(sandbox_id, session_id, |session| {
            session.map(|session| session.complete(result))
        })
        .flatten()
        .unwrap_or_else(|| {
            Err(Status::failed_precondition(
                "obsolete supervisor session result",
            ))
        })
    }

    /// Finish a validated update after all durable side effects have either
    /// succeeded or failed. Keeping the update in flight until this point
    /// prevents reconciliation from treating a locally reported result as an
    /// acknowledgement before its admission is durable.
    fn finalize_config_update(
        &self,
        sandbox_id: &str,
        session_id: &str,
        completed: &CompletedConfigUpdate,
        acknowledge: bool,
    ) {
        if let Some(outgoing) = self
            .with_config_session(sandbox_id, session_id, |session| {
                session.and_then(|session| session.finalize(completed, acknowledge))
            })
            .flatten()
        {
            outgoing.send();
        }
    }

    /// Let reconciliation redeliver an acknowledged configuration whose
    /// result was never persisted, so the supervisor reports the result
    /// again. The supervisor answers unchanged configuration as a duplicate.
    pub(super) fn reopen_config(&self, sandbox_id: &str, session_id: &str) {
        self.with_config_session(sandbox_id, session_id, |session| {
            if let Some(session) = session {
                session.reopen();
            }
        });
    }
}

fn build_config_update(
    config: SupervisorConfig,
    bootstrap: bool,
) -> (ConfigUpdate, InFlightConfigUpdate) {
    let update_id = Uuid::new_v4().to_string();
    let in_flight = InFlightConfigUpdate {
        update_id: update_id.clone(),
        fingerprint: ConfigFingerprint::of(&config.sandbox_config),
        admission: expected_configuration_admission(&config.sandbox_config),
        bootstrap,
        sent_at: Instant::now(),
    };
    let update = ConfigUpdate {
        update_id,
        sandbox_config: Some(config.sandbox_config),
        provider_environment: Some(config.provider_environment),
    };
    (update, in_flight)
}

/// The update a session is accepted with, and its in-flight state for
/// [`SupervisorSessionRegistry::begin_config_bootstrap`].
pub fn bootstrap_update(config: SupervisorConfig) -> (ConfigUpdate, BootstrapInFlight) {
    let (update, in_flight) = build_config_update(config, true);
    (update, BootstrapInFlight(in_flight))
}

// ---------------------------------------------------------------------------
// Results and admission
// ---------------------------------------------------------------------------

fn outcome_acknowledges_revision(outcome: ConfigApplyOutcome) -> bool {
    matches!(
        outcome,
        ConfigApplyOutcome::Applied
            | ConfigApplyOutcome::IgnoredDuplicate
            | ConfigApplyOutcome::RetainedLocalOverride
            | ConfigApplyOutcome::Degraded
    )
}

fn expected_configuration_admission(
    snapshot: &SandboxConfigSnapshot,
) -> SandboxConfigurationAdmission {
    use openshell_core::proto::ConfigurationAdmissionState;

    SandboxConfigurationAdmission {
        instance_id: snapshot.configuration_instance_id.clone(),
        state: if snapshot.configuration_admitted {
            ConfigurationAdmissionState::Accepted.into()
        } else {
            ConfigurationAdmissionState::Rejected.into()
        },
        policy_version: snapshot.version,
        policy_hash: snapshot.policy_hash.clone(),
        config_revision: snapshot.config_revision,
        provider_env_revision: snapshot.provider_env_revision,
        error: snapshot.configuration_error.clone(),
    }
}

fn validate_configuration_admission(
    reported: Option<&SandboxConfigurationAdmission>,
    expected: &SandboxConfigurationAdmission,
    outcome: ConfigApplyOutcome,
) -> Result<SandboxConfigurationAdmission, Status> {
    use openshell_core::proto::ConfigurationAdmissionState;

    let reported = reported.ok_or_else(|| {
        Status::invalid_argument("sandbox configuration admission result is required")
    })?;
    if reported.instance_id != expected.instance_id
        || reported.policy_version != expected.policy_version
        || reported.policy_hash != expected.policy_hash
        || reported.config_revision != expected.config_revision
        || reported.provider_env_revision != expected.provider_env_revision
    {
        return Err(Status::invalid_argument(
            "configuration admission does not match the delivered generation",
        ));
    }
    let expected_state = ConfigurationAdmissionState::try_from(expected.state).unwrap_or_default();
    let reported_state = ConfigurationAdmissionState::try_from(reported.state).unwrap_or_default();
    if expected_state == ConfigurationAdmissionState::Rejected {
        if reported_state != ConfigurationAdmissionState::Rejected {
            return Err(Status::invalid_argument(
                "rejected gateway configuration was reported as accepted",
            ));
        }
        return Ok(expected.clone());
    }
    if outcome_acknowledges_revision(outcome)
        && reported_state == ConfigurationAdmissionState::Accepted
    {
        let mut admission = expected.clone();
        admission.error.clear();
        return Ok(admission);
    }
    if reported_state == ConfigurationAdmissionState::Rejected {
        let mut admission = expected.clone();
        admission.state = ConfigurationAdmissionState::Rejected.into();
        admission.error = "effective configuration could not be activated".to_string();
        return Ok(admission);
    }
    Err(Status::invalid_argument(
        "configuration admission is inconsistent with the apply result",
    ))
}

/// Record the result of the update in flight, including the bootstrap.
/// Nothing is persisted for an invalid result. Returns false when the
/// session must close: a bootstrap whose result is invalid or whose
/// admission could not be persisted.
pub async fn handle_config_update_result(
    session: &AcceptedSession,
    result: &ConfigUpdateResult,
) -> bool {
    let AcceptedSession {
        state,
        sandbox_id,
        session_id,
        ..
    } = session;
    let registry = &state.supervisor_sessions;
    let completed = match registry.complete_config_update(sandbox_id, session_id, result) {
        Ok(completed) => completed,
        Err(error) => {
            debug!(
                sandbox_id,
                session_id,
                error = %error,
                "ignored unmatched supervisor configuration result"
            );
            return true;
        }
    };
    histogram!(
        crate::gateway_metrics::SUPERVISOR_CONFIG_APPLY_DURATION_SECONDS,
        "outcome" => completed.outcome.as_str_name(),
    )
    .record(completed.sent_at.elapsed().as_secs_f64());
    record_apply_result(sandbox_id, completed.outcome, result);
    let admission = match validate_configuration_admission(
        result.admission.as_ref(),
        &completed.admission,
        completed.outcome,
    ) {
        Ok(admission) => admission,
        Err(error) => {
            warn!(
                sandbox_id,
                session_id,
                error = %error,
                "supervisor configuration result did not match the delivered update"
            );
            registry.finalize_config_update(sandbox_id, session_id, &completed, false);
            return !completed.bootstrap;
        }
    };
    let recorded = match record_or_queue_policy_result(
        state,
        sandbox_id,
        session_id,
        result.policy_load.as_ref(),
    )
    .await
    {
        Ok(()) => true,
        Err(error) => {
            warn!(
                sandbox_id,
                session_id,
                error = %error,
                "failed to persist supervisor policy result"
            );
            false
        }
    };
    let admitted = persist_and_ack_admission(session, &admission).await != AdmissionAck::Failed;
    registry.finalize_config_update(sandbox_id, session_id, &completed, recorded && admitted);
    admitted || !completed.bootstrap
}

/// Count and log an update result.
fn record_apply_result(sandbox_id: &str, outcome: ConfigApplyOutcome, result: &ConfigUpdateResult) {
    counter!(
        "openshell_supervisor_config_apply_results_total",
        "outcome" => outcome.as_str_name(),
    )
    .increment(1);
    if !outcome_acknowledges_revision(outcome) {
        let failure = result.failure.as_ref();
        warn!(
            sandbox_id,
            outcome = outcome.as_str_name(),
            failure_code = failure.map_or("", |failure| failure.code.as_str()),
            failure = failure
                .map(|failure| failure.message.chars().take(1024).collect::<String>())
                .unwrap_or_default(),
            "supervisor failed to apply pushed configuration"
        );
    }
}

/// Record the sandbox policy load result an update reported. A running
/// workload's result is queued for the result writer, so a fleet-wide
/// fanout does not queue every session on the compute sandbox lock ahead of
/// user mutations.
async fn record_or_queue_policy_result(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    policy_load: Option<&PolicyLoadResult>,
) -> Result<(), Status> {
    let Some(policy_load) = policy_load else {
        return Ok(());
    };
    let policy = PolicyResult {
        version: policy_load.version,
        loaded: policy_load.loaded,
        error: (!policy_load.loaded).then(|| policy_load.error.clone()),
    };
    if !state.supervisor_sessions.is_runtime_ready(sandbox_id) {
        return crate::grpc::policy::record_policy_apply_result(
            state,
            sandbox_id,
            policy.version,
            policy.loaded,
            policy.error.as_deref(),
            "stream",
        )
        .await;
    }
    result_writer::queue_policy_result(state, sandbox_id, session_id, policy);
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum AdmissionAck {
    /// Persisted and sent to the supervisor.
    Acknowledged,
    /// Withheld because a newer generation was committed before the workload
    /// started. That generation's own admission unlocks startup.
    Superseded,
    Failed,
}

async fn persist_and_ack_admission(
    session: &AcceptedSession,
    admission: &SandboxConfigurationAdmission,
) -> AdmissionAck {
    use openshell_core::proto::ConfigurationAdmissionState;

    let AcceptedSession {
        state,
        sandbox_id,
        session_id,
        instance_id,
        ..
    } = session;
    if !state
        .supervisor_sessions
        .is_current_session(sandbox_id, session_id)
    {
        return AdmissionAck::Failed;
    }
    #[cfg(test)]
    {
        let mut failure_target = FAIL_NEXT_ADMISSION_PERSISTENCE_FOR_SANDBOX.lock().unwrap();
        if failure_target.as_deref() == Some(sandbox_id.as_str()) {
            failure_target.take();
            return AdmissionAck::Failed;
        }
    }
    // A running workload's admission no longer gates startup. Acknowledge it
    // now and let the result writer persist it, so a fanout does not queue
    // every session on the compute sandbox lock ahead of user mutations.
    if state.supervisor_sessions.is_runtime_ready(sandbox_id) {
        result_writer::queue_admission(state, sandbox_id, session_id, instance_id, admission);
        return send_admission(session, admission).await;
    }
    // Accepted admission lets a pending workload start, so it must name the
    // current generation, as a polling startup report must. A running
    // workload already has a configuration, and later updates follow it.
    if admission.state == i32::from(ConfigurationAdmissionState::Accepted)
        && !state.supervisor_sessions.is_runtime_ready(sandbox_id)
    {
        match admission_is_current(state, sandbox_id, admission).await {
            Ok(true) => {}
            Ok(false) => {
                debug!(
                    sandbox_id,
                    session_id,
                    config_revision = admission.config_revision,
                    "withheld startup admission for a superseded configuration"
                );
                super::publish_sandbox(state, sandbox_id);
                return AdmissionAck::Superseded;
            }
            Err(error) => {
                warn!(sandbox_id, session_id, error = %error, "failed to verify supervisor configuration admission");
                return AdmissionAck::Failed;
            }
        }
    }
    if let Err(error) = state
        .compute
        .supervisor_session_admission(sandbox_id, instance_id, admission)
        .await
    {
        warn!(sandbox_id, session_id, error = %error, "failed to persist supervisor configuration admission");
        return AdmissionAck::Failed;
    }
    send_admission(session, admission).await
}

async fn send_admission(
    session: &AcceptedSession,
    admission: &SandboxConfigurationAdmission,
) -> AdmissionAck {
    if session
        .control
        .send(GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigurationAdmission(
                admission.clone(),
            )),
        })
        .await
        .is_err()
    {
        return AdmissionAck::Failed;
    }
    session
        .state
        .telemetry
        .sandbox_session_connected(&session.sandbox_id);
    AdmissionAck::Acknowledged
}

/// Whether `admission` names the generation the gateway would deliver now.
async fn admission_is_current(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    admission: &SandboxConfigurationAdmission,
) -> Result<bool, Status> {
    let sandbox = state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let snapshot = tokio::time::timeout(
        CONFIG_BOOTSTRAP_BUILD_TIMEOUT,
        build_sandbox_config_snapshot(state, &sandbox),
    )
    .await
    .map_err(|_| Status::deadline_exceeded("configuration admission check timed out"))??;
    Ok(snapshot.configuration_admitted
        && (
            admission.policy_version,
            &admission.policy_hash,
            admission.config_revision,
            admission.provider_env_revision,
        ) == (
            snapshot.version,
            &snapshot.policy_hash,
            snapshot.config_revision,
            snapshot.provider_env_revision,
        ))
}

// ---------------------------------------------------------------------------
// Bootstrap and startup preparation
// ---------------------------------------------------------------------------

/// Build both parts of a session's configuration from one load of their
/// inputs.
async fn build_config_bootstrap(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
) -> Result<SupervisorConfig, Status> {
    tokio::time::timeout(CONFIG_BOOTSTRAP_BUILD_TIMEOUT, async {
        let inputs = load_sandbox_config_inputs(state, sandbox.clone()).await?;
        let (sandbox_config, provider_environment) = tokio::join!(
            build_sandbox_config_snapshot_from_inputs(state, &inputs),
            build_provider_environment_snapshot_from_inputs(state, &inputs, true, true),
        );
        Ok(SupervisorConfig {
            sandbox_config: sandbox_config?,
            provider_environment: provider_environment?,
        })
    })
    .await
    .map_err(|_| Status::deadline_exceeded("supervisor configuration bootstrap timed out"))?
}

/// Image policy discovery reported by a supervisor's first connection.
pub enum ImagePolicyAdmission {
    Missing,
    Invalid,
    Policy(Box<SandboxPolicy>),
}

pub fn image_policy_admission(hello: &SupervisorHello) -> Result<ImagePolicyAdmission, Status> {
    use openshell_core::proto::image_policy_discovery::Result as DiscoveryResult;

    let Some(discovery) = hello.image_policy_discovery.as_ref() else {
        return Ok(ImagePolicyAdmission::Missing);
    };
    match discovery.result.as_ref() {
        Some(DiscoveryResult::Missing(())) => Ok(ImagePolicyAdmission::Missing),
        Some(DiscoveryResult::Invalid(())) => Ok(ImagePolicyAdmission::Invalid),
        Some(DiscoveryResult::Policy(policy)) => {
            Ok(ImagePolicyAdmission::Policy(Box::new(policy.clone())))
        }
        None => Err(Status::invalid_argument(
            "image policy discovery result is required",
        )),
    }
}

/// Build the authoritative bootstrap for a streamed-apply session.
///
/// An invalid image policy cannot become the startup baseline, so the build
/// waits for an operator to store a gateway policy, bounded by
/// `STARTUP_POLICY_REPAIR_TIMEOUT`. It checks again on every change to the
/// sandbox and at least every `STARTUP_POLICY_REPAIR_RECHECK`.
pub async fn build_session_bootstrap(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    image_policy_admission: &ImagePolicyAdmission,
) -> Result<SupervisorConfig, Status> {
    let waits_for_repair = matches!(image_policy_admission, ImagePolicyAdmission::Invalid);
    let mut repair_updates =
        waits_for_repair.then(|| state.sandbox_watch_bus.subscribe(sandbox_id));
    let repair_deadline = tokio::time::Instant::now() + STARTUP_POLICY_REPAIR_TIMEOUT;
    // The last reason logged for waiting: no gateway policy yet (`None`) or a
    // build error. Rechecks log only a new reason.
    let mut logged_wait: Option<Option<tonic::Code>> = None;
    loop {
        let current_sandbox =
            crate::supervisor_session::require_persisted_sandbox(&state.store, sandbox_id).await?;
        match build_config_bootstrap(state, &current_sandbox).await {
            Ok(bootstrap) => {
                let has_gateway_policy = bootstrap.sandbox_config.policy.is_some();
                if !waits_for_repair || has_gateway_policy {
                    counter!(
                        "openshell_supervisor_config_bootstrap_total",
                        "outcome" => "built"
                    )
                    .increment(1);
                    return Ok(bootstrap);
                }
                if logged_wait.replace(None) != Some(None) {
                    warn!(
                        sandbox_id = %sandbox_id,
                        "invalid image policy rejected; waiting for a gateway policy repair"
                    );
                }
            }
            Err(error) if waits_for_repair => {
                if logged_wait.replace(Some(error.code())) != Some(Some(error.code())) {
                    warn!(
                        sandbox_id = %sandbox_id,
                        error_code = ?error.code(),
                        "invalid image policy rejected; waiting for configuration repair"
                    );
                }
            }
            Err(error) => {
                counter!(
                    "openshell_supervisor_config_bootstrap_total",
                    "outcome" => "build_failed"
                )
                .increment(1);
                warn!(
                    sandbox_id = %sandbox_id,
                    error_code = ?error.code(),
                    "failed to build supervisor configuration bootstrap"
                );
                return Err(error);
            }
        }

        if tokio::time::Instant::now() >= repair_deadline {
            return Err(Status::deadline_exceeded(
                "image policy repair window expired",
            ));
        }
        #[cfg(test)]
        STARTUP_REPAIR_WAITS
            .lock()
            .unwrap()
            .insert(sandbox_id.to_string());
        let updates = repair_updates
            .as_mut()
            .expect("only an invalid image policy waits for repair");
        let recheck_at =
            repair_deadline.min(tokio::time::Instant::now() + STARTUP_POLICY_REPAIR_RECHECK);
        match tokio::time::timeout_at(recheck_at, updates.recv()).await {
            Ok(Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) | Err(_) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                return Err(Status::aborted(
                    "sandbox configuration watch closed during startup repair",
                ));
            }
        }
    }
}

/// A startup policy offered to a supervisor's first connection for
/// preparation against its workload image.
pub struct StartupCandidate {
    candidate_id: String,
    policy: SandboxPolicy,
    gateway_has_policy: bool,
}

/// Offer the gateway-selected policy, or the image policy when the gateway
/// has none, before the bootstrap is final.
pub async fn send_startup_candidate(
    tx: &mpsc::Sender<GatewayMessage>,
    gateway_snapshot: Option<&SandboxConfigSnapshot>,
    image_policy_admission: ImagePolicyAdmission,
) -> Result<StartupCandidate, Status> {
    let gateway_policy = gateway_snapshot.and_then(|snapshot| snapshot.policy.clone());
    let gateway_has_policy = gateway_policy.is_some();
    let policy = gateway_policy
        .or_else(|| match image_policy_admission {
            ImagePolicyAdmission::Policy(policy) => Some(*policy),
            ImagePolicyAdmission::Missing => Some(openshell_policy::restrictive_default_policy()),
            ImagePolicyAdmission::Invalid => None,
        })
        .ok_or_else(|| Status::failed_precondition("startup policy candidate is missing"))?;
    let (policy_hash, policy_source, policy_version) =
        gateway_snapshot.filter(|_| gateway_has_policy).map_or_else(
            || {
                (
                    openshell_core::policy_identity::deterministic_policy_hash(&policy),
                    PolicySource::Sandbox.into(),
                    0,
                )
            },
            |snapshot| {
                (
                    snapshot.policy_hash.clone(),
                    snapshot.policy_source,
                    snapshot.version,
                )
            },
        );
    let candidate_id = Uuid::new_v4().to_string();
    let candidate = GatewayMessage {
        payload: Some(gateway_message::Payload::StartupConfigCandidate(
            StartupConfigCandidate {
                candidate_id: candidate_id.clone(),
                policy_hash,
                policy_source,
                policy_version,
                policy: Some(policy.clone()),
            },
        )),
    };
    if candidate.encoded_len() > MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES {
        return Err(Status::resource_exhausted(
            "startup configuration candidate exceeds the stream message limit",
        ));
    }
    tx.send(candidate)
        .await
        .map_err(|_| Status::internal("failed to send startup configuration candidate"))?;
    Ok(StartupCandidate {
        candidate_id,
        policy,
        gateway_has_policy,
    })
}

impl StartupCandidate {
    /// Wait for the supervisor's prepared policy, persist it unless it is the
    /// unchanged gateway policy, and build the bootstrap from the result.
    pub async fn finish(
        self,
        state: &Arc<ServerState>,
        principal: Option<Principal>,
        sandbox: &Sandbox,
        inbound: &mut tonic::Streaming<SupervisorMessage>,
    ) -> Result<SupervisorConfig, Status> {
        use crate::persistence::ObjectId;

        let prepared = tokio::time::timeout(CONFIG_BOOTSTRAP_BUILD_TIMEOUT, inbound.message())
            .await
            .map_err(|_| Status::deadline_exceeded("startup configuration preparation timed out"))??
            .ok_or_else(|| Status::aborted("supervisor disconnected during startup preparation"))?;
        let Some(supervisor_message::Payload::StartupConfigPrepared(prepared)) = prepared.payload
        else {
            return Err(Status::invalid_argument("expected StartupConfigPrepared"));
        };
        if prepared.candidate_id != self.candidate_id {
            return Err(Status::failed_precondition(
                "startup configuration candidate ID does not match",
            ));
        }

        let policy_to_persist = match prepared.result {
            Some(startup_config_prepared::Result::Unchanged(())) => {
                (!self.gateway_has_policy).then_some(self.policy)
            }
            Some(startup_config_prepared::Result::PreparedPolicy(policy)) => Some(policy),
            Some(startup_config_prepared::Result::Failure(failure)) => {
                return Err(Status::failed_precondition(format!(
                    "supervisor could not prepare startup policy: {}: {}",
                    failure.code, failure.message
                )));
            }
            None => {
                return Err(Status::invalid_argument(
                    "startup configuration result is required",
                ));
            }
        };

        if let Some(policy) = policy_to_persist {
            let principal = principal.ok_or_else(|| {
                Status::unauthenticated(
                    "startup policy preparation requires an authenticated supervisor",
                )
            })?;
            crate::grpc::policy::persist_supervisor_startup_policy(
                state, principal, sandbox, policy,
            )
            .await?;
        }

        let sandbox =
            crate::supervisor_session::require_persisted_sandbox(&state.store, sandbox.object_id())
                .await?;
        build_config_bootstrap(state, &sandbox).await
    }
}

/// The result a supervisor reports after applying `update` in full.
#[cfg(test)]
pub fn applied_result(update: &ConfigUpdate) -> ConfigUpdateResult {
    let sandbox = update
        .sandbox_config
        .as_ref()
        .expect("sandbox configuration");
    let policy_load = (sandbox.policy_source == i32::from(PolicySource::Sandbox)
        && sandbox.version > 0)
        .then(|| PolicyLoadResult {
            version: sandbox.version,
            loaded: true,
            error: String::new(),
        });
    ConfigUpdateResult {
        update_id: update.update_id.clone(),
        outcome: ConfigApplyOutcome::Applied.into(),
        failure: None,
        admission: Some(expected_configuration_admission(sandbox)),
        policy_load,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_delivery::SessionOutbound;
    use crate::grpc::test_support::StreamFeatures;
    use crate::supervisor_session::SessionMode;
    use openshell_core::proto::{
        ProviderEnvironmentSnapshot, ProviderEnvironmentValue, SandboxSpec, SessionAccepted,
        StartupConfigPrepared,
    };
    use tokio::sync::oneshot;

    include!("session_regression_tests.rs");

    fn make_shutdown() -> oneshot::Sender<()> {
        oneshot::channel::<()>().0
    }

    fn sandbox_record(id: &str, name: &str) -> Sandbox {
        Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: id.to_string(),
                name: name.to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    async fn state_with_sandbox(sandbox_id: &str) -> Arc<ServerState> {
        let state = crate::grpc::test_support::test_server_state().await;
        state
            .store
            .put_message(&sandbox_record(sandbox_id, sandbox_id))
            .await
            .unwrap();
        state
    }

    async fn first_gateway_message(
        harness: &mut crate::grpc::test_support::SupervisorStreamHarness,
    ) -> GatewayMessage {
        tokio::time::timeout(Duration::from_secs(5), harness.inbound.message())
            .await
            .expect("gateway response before timeout")
            .expect("stream open")
            .expect("gateway message")
    }

    fn accepted_session(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        tx: mpsc::Sender<GatewayMessage>,
    ) -> AcceptedSession {
        AcceptedSession {
            state: Arc::clone(state),
            sandbox_id: sandbox_id.into(),
            session_id: "session-1".into(),
            instance_id: "instance-1".into(),
            control: tx.clone(),
            tx,
            supports_session_redirect: false,
            pushes_config: true,
        }
    }

    #[test]
    fn configuration_stream_messages_round_trip() {
        let update = || ConfigUpdate {
            update_id: "update-1".into(),
            sandbox_config: Some(SandboxConfigSnapshot::default()),
            provider_environment: Some(ProviderEnvironmentSnapshot::default()),
        };
        let messages = [
            GatewayMessage {
                payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
                    session_id: "session-1".into(),
                    heartbeat_interval: openshell_core::time::duration_from_std(
                        Duration::from_secs(15),
                    )
                    .ok(),
                    bootstrap: Some(update()),
                    config_push_enabled: true,
                })),
            },
            GatewayMessage {
                payload: Some(gateway_message::Payload::ConfigUpdate(update())),
            },
        ];
        for original in messages {
            let decoded = GatewayMessage::decode(original.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded, original);
        }

        let result = SupervisorMessage {
            payload: Some(supervisor_message::Payload::ConfigUpdateResult(
                ConfigUpdateResult {
                    update_id: "update-1".into(),
                    outcome: ConfigApplyOutcome::Applied.into(),
                    failure: None,
                    admission: Some(SandboxConfigurationAdmission::default()),
                    policy_load: Some(PolicyLoadResult {
                        version: 3,
                        loaded: true,
                        error: String::new(),
                    }),
                },
            )),
        };
        let decoded = SupervisorMessage::decode(result.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, result);
    }

    fn register_apply_session_with_outbound(
        registry: &SupervisorSessionRegistry,
        sandbox_id: &str,
        session_id: &str,
    ) -> (mpsc::Sender<GatewayMessage>, SessionOutbound) {
        let (tx, rx) = mpsc::channel(4);
        let slots = Arc::new(ConfigSlots::default());
        registry.register_with_mode(
            sandbox_id.into(),
            session_id.into(),
            tx.clone(),
            make_shutdown(),
            SessionMode::Push(Arc::clone(&slots)),
        );
        (tx, SessionOutbound::new(rx, slots))
    }

    fn sent_update(message: GatewayMessage) -> ConfigUpdate {
        match message.payload {
            Some(gateway_message::Payload::ConfigUpdate(update)) => update,
            other => panic!("expected config update, got {other:?}"),
        }
    }

    fn config(config_revision: u64) -> SupervisorConfig {
        SupervisorConfig {
            sandbox_config: SandboxConfigSnapshot {
                config_revision,
                ..Default::default()
            },
            provider_environment: ProviderEnvironmentSnapshot::default(),
        }
    }

    fn config_revision(update: &ConfigUpdate) -> u64 {
        update.sandbox_config.as_ref().unwrap().config_revision
    }

    /// A supervisor result for `update` with `outcome`.
    fn update_result(update: &ConfigUpdate, outcome: ConfigApplyOutcome) -> ConfigUpdateResult {
        ConfigUpdateResult {
            update_id: update.update_id.clone(),
            outcome: outcome.into(),
            ..Default::default()
        }
    }

    #[test]
    fn config_delivery_reports_missing_session() {
        assert_eq!(
            SupervisorSessionRegistry::new().deliver_config("missing", "session", config(1)),
            DeliveryDisposition::NoActiveSession
        );
    }

    #[tokio::test]
    async fn config_delivery_holds_newer_configuration_until_acknowledged() {
        use tokio_stream::StreamExt as _;

        let registry = SupervisorSessionRegistry::new();
        let (_tx, mut outbound) =
            register_apply_session_with_outbound(&registry, "sb-1", "session-1");

        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(1)),
            DeliveryDisposition::Queued
        );
        for config_revision in [2, 3] {
            assert_eq!(
                registry.deliver_config("sb-1", "session-1", config(config_revision)),
                DeliveryDisposition::Coalesced
            );
        }
        let first = sent_update(outbound.next().await.unwrap().unwrap());
        assert_eq!(config_revision(&first), 1);
        assert!(first.provider_environment.is_some());

        let completed = registry
            .complete_config_update(
                "sb-1",
                "session-1",
                &update_result(&first, ConfigApplyOutcome::Applied),
            )
            .unwrap();
        registry.finalize_config_update("sb-1", "session-1", &completed, true);

        // The acknowledgement releases only the newest held configuration.
        let next = sent_update(outbound.next().await.unwrap().unwrap());
        assert_eq!(config_revision(&next), 3);
        assert_ne!(next.update_id, first.update_id);
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(3)),
            DeliveryDisposition::Coalesced,
            "the release is in flight"
        );
    }

    #[tokio::test]
    async fn config_delivery_never_crosses_into_a_replacement_session() {
        use tokio_stream::StreamExt as _;

        let registry = SupervisorSessionRegistry::new();
        let (_old_tx, _old_outbound) =
            register_apply_session_with_outbound(&registry, "sb-1", "old-session");
        let (_new_tx, mut new_outbound) =
            register_apply_session_with_outbound(&registry, "sb-1", "new-session");

        assert_eq!(
            registry.deliver_config("sb-1", "old-session", config(1)),
            DeliveryDisposition::NoActiveSession
        );
        assert_eq!(
            registry.deliver_config("sb-1", "new-session", config(2)),
            DeliveryDisposition::Queued
        );
        let update = sent_update(new_outbound.next().await.unwrap().unwrap());
        assert_eq!(config_revision(&update), 2);
    }

    #[test]
    fn config_delivery_skips_polling_sessions() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);
        registry.register("sb-1".into(), "session-1".into(), tx, make_shutdown());
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(1)),
            DeliveryDisposition::UnsupportedSession
        );
    }

    #[tokio::test]
    async fn config_delivery_rejects_oversized_messages() {
        use tokio_stream::StreamExt as _;

        let registry = SupervisorSessionRegistry::new();
        let (tx, mut outbound) =
            register_apply_session_with_outbound(&registry, "sb-1", "session-1");

        let mut oversized = config(1);
        oversized.provider_environment.values = vec![ProviderEnvironmentValue {
            name: "TOKEN".into(),
            value: "x".repeat(MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES),
            ..Default::default()
        }];
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", oversized),
            DeliveryDisposition::PayloadTooLarge
        );
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(2)),
            DeliveryDisposition::Queued,
            "an oversized configuration is not left in flight"
        );
        drop(tx);
        registry.remove_if_current("sb-1", "session-1");
        let _ = outbound.next().await;
        assert!(outbound.next().await.is_none());
    }

    /// Register a streamed-apply session and return its configuration slots.
    fn register_apply_session(
        registry: &SupervisorSessionRegistry,
        sandbox_id: &str,
        session_id: &str,
    ) -> Arc<ConfigSlots> {
        let (tx, _rx) = mpsc::channel(1);
        let slots = Arc::new(ConfigSlots::default());
        registry.register_with_mode(
            sandbox_id.into(),
            session_id.into(),
            tx,
            make_shutdown(),
            SessionMode::Push(Arc::clone(&slots)),
        );
        slots
    }

    async fn push_state() -> Arc<ServerState> {
        let mut state = crate::grpc::test_support::test_server_state().await;
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .config_delivery_mode = openshell_core::config::ConfigDeliveryMode::Push;
        state
    }

    async fn push_state_with_sandbox(sandbox_id: &str) -> Arc<ServerState> {
        let state = push_state().await;
        state
            .store
            .put_message(&sandbox_record(sandbox_id, sandbox_id))
            .await
            .unwrap();
        state
    }

    /// Answer the bootstrap in flight on `session_id` with `outcome`.
    fn answer_bootstrap(
        registry: &SupervisorSessionRegistry,
        sandbox_id: &str,
        session_id: &str,
        bootstrap: &ConfigUpdate,
        outcome: ConfigApplyOutcome,
    ) {
        let completed = registry
            .complete_config_update(sandbox_id, session_id, &update_result(bootstrap, outcome))
            .unwrap();
        registry.finalize_config_update(sandbox_id, session_id, &completed, true);
    }

    /// Register a push session accepted with `bootstrap` in flight.
    fn register_bootstrapped_session(
        registry: &SupervisorSessionRegistry,
        sandbox_id: &str,
        session_id: &str,
        bootstrap: SupervisorConfig,
    ) -> (Arc<ConfigSlots>, ConfigUpdate) {
        let slots = register_apply_session(registry, sandbox_id, session_id);
        let (update, in_flight) = bootstrap_update(bootstrap);
        registry.begin_config_bootstrap(sandbox_id, session_id, in_flight);
        (slots, update)
    }

    #[test]
    fn rebuild_racing_the_bootstrap_waits_and_is_dropped_when_unchanged() {
        let registry = SupervisorSessionRegistry::new();
        let (slots, bootstrap) =
            register_bootstrapped_session(&registry, "sb-1", "session-1", config(7));

        // The configuration the bootstrap carried is held, then dropped.
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(7)),
            DeliveryDisposition::Coalesced
        );
        answer_bootstrap(
            &registry,
            "sb-1",
            "session-1",
            &bootstrap,
            ConfigApplyOutcome::Applied,
        );
        assert!(slots.take_for_test().is_none());
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(7)),
            DeliveryDisposition::SuppressedUnchanged
        );

        // Newer configuration held behind the bootstrap is sent once it lands.
        let (slots, bootstrap) =
            register_bootstrapped_session(&registry, "sb-1", "session-2", config(7));
        assert_eq!(
            registry.deliver_config("sb-1", "session-2", config(8)),
            DeliveryDisposition::Coalesced
        );
        answer_bootstrap(
            &registry,
            "sb-1",
            "session-2",
            &bootstrap,
            ConfigApplyOutcome::Applied,
        );
        let released = sent_update(slots.take_for_test().expect("newer configuration is sent"));
        assert_eq!(config_revision(&released), 8);
    }

    #[test]
    fn bootstrap_held_past_the_acknowledgement_timeout_keeps_newer_configuration() {
        let registry = SupervisorSessionRegistry::new();
        let (_slots, _bootstrap) =
            register_bootstrapped_session(&registry, "sb-1", "session-1", config(7));
        registry.with_config_session("sb-1", "session-1", |session| {
            let in_flight = session.unwrap().in_flight.as_mut().unwrap();
            in_flight.sent_at -= CONFIG_ACK_TIMEOUT * 2;
        });
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(8)),
            DeliveryDisposition::Coalesced,
            "only the bootstrap result can release the session"
        );
    }

    #[test]
    fn bootstrap_result_acknowledges_only_an_applied_configuration() {
        let registry = SupervisorSessionRegistry::new();
        let (slots, bootstrap) =
            register_bootstrapped_session(&registry, "sb-1", "session-1", config(7));
        answer_bootstrap(
            &registry,
            "sb-1",
            "session-1",
            &bootstrap,
            ConfigApplyOutcome::FailedClosed,
        );
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(7)),
            DeliveryDisposition::Queued,
            "a failed bootstrap leaves its configuration eligible for repair"
        );
        assert!(slots.take_for_test().is_some());

        let (slots, bootstrap) =
            register_bootstrapped_session(&registry, "sb-1", "session-2", config(7));
        answer_bootstrap(
            &registry,
            "sb-1",
            "session-2",
            &bootstrap,
            ConfigApplyOutcome::Applied,
        );
        assert_eq!(
            registry.deliver_config("sb-1", "session-2", config(7)),
            DeliveryDisposition::SuppressedUnchanged
        );
        assert!(slots.take_for_test().is_none());
    }

    #[test]
    fn rejected_configuration_stays_eligible_for_reconciliation_until_applied() {
        let registry = SupervisorSessionRegistry::new();
        let slots = register_apply_session(&registry, "sb-1", "session-1");
        let report = |outcome| {
            assert_eq!(
                registry.deliver_config("sb-1", "session-1", config(7)),
                DeliveryDisposition::Queued
            );
            let update = sent_update(slots.take_for_test().expect("update"));
            let completed = registry
                .complete_config_update("sb-1", "session-1", &update_result(&update, outcome))
                .unwrap();
            registry.finalize_config_update("sb-1", "session-1", &completed, true);
        };

        report(ConfigApplyOutcome::FailedRetainedLastKnownGood);
        report(ConfigApplyOutcome::Applied);
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(7)),
            DeliveryDisposition::SuppressedUnchanged
        );
    }

    #[test]
    fn unmatched_result_leaves_the_update_in_flight() {
        let registry = SupervisorSessionRegistry::new();
        let slots = register_apply_session(&registry, "sb-1", "session-1");
        registry.deliver_config("sb-1", "session-1", config(7));
        let update = sent_update(slots.take_for_test().expect("update"));
        let mut stale = update_result(&update, ConfigApplyOutcome::Applied);
        stale.update_id = "other".into();
        assert!(
            registry
                .complete_config_update("sb-1", "session-1", &stale)
                .is_err()
        );
        let mut unspecified = update_result(&update, ConfigApplyOutcome::Applied);
        unspecified.outcome = ConfigApplyOutcome::Unspecified.into();
        assert!(
            registry
                .complete_config_update("sb-1", "session-1", &unspecified)
                .is_err()
        );
        assert_eq!(
            registry.deliver_config("sb-1", "session-1", config(8)),
            DeliveryDisposition::Coalesced
        );
    }

    /// A sandbox configuration that settles sandbox policy version 3.
    fn sandbox_policy_snapshot() -> SandboxConfigSnapshot {
        SandboxConfigSnapshot {
            configuration_instance_id: "configuration-1".into(),
            configuration_admitted: true,
            config_revision: 7,
            version: 3,
            policy_hash: "policy-hash".into(),
            provider_env_revision: 5,
            policy_source: PolicySource::Sandbox.into(),
            ..Default::default()
        }
    }

    async fn put_sandbox_policy_revision(state: &Arc<ServerState>, sandbox_id: &str) {
        use crate::policy_store::PolicyStoreExt as _;

        state
            .store
            .put_policy_revision(
                "policy-3",
                sandbox_id,
                "default",
                3,
                &SandboxPolicy::default().encode_to_vec(),
                "policy-hash",
            )
            .await
            .unwrap();
    }

    /// Register `session-1` as the push session of a running workload.
    fn register_running_push_session(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        tx: &mpsc::Sender<GatewayMessage>,
    ) -> Arc<ConfigSlots> {
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        let slots = Arc::new(ConfigSlots::default());
        state.supervisor_sessions.register_with_mode(
            sandbox_id.into(),
            "session-1".into(),
            tx.clone(),
            shutdown_tx,
            SessionMode::Push(Arc::clone(&slots)),
        );
        assert!(
            state
                .supervisor_sessions
                .mark_runtime_ready_for_test(sandbox_id, "session-1")
        );
        slots
    }

    /// What a supervisor reports for `update`: the admission its outcome
    /// implies, and a policy load result for a sandbox policy revision.
    fn reported_result(update: &ConfigUpdate, outcome: ConfigApplyOutcome) -> ConfigUpdateResult {
        use openshell_core::proto::{ConfigApplyFailure, ConfigurationAdmissionState};

        let snapshot = update.sandbox_config.as_ref().unwrap();
        let applied = outcome_acknowledges_revision(outcome);
        let mut admission = expected_configuration_admission(snapshot);
        if !applied {
            admission.state = ConfigurationAdmissionState::Rejected.into();
        }
        ConfigUpdateResult {
            update_id: update.update_id.clone(),
            outcome: outcome.into(),
            failure: (!applied).then(|| ConfigApplyFailure {
                code: "policy_rejected".into(),
                message: "policy rejected".into(),
                retryable: true,
            }),
            admission: Some(admission),
            policy_load: (snapshot.policy_source == i32::from(PolicySource::Sandbox)
                && snapshot.version > 0)
                .then(|| PolicyLoadResult {
                    version: snapshot.version,
                    loaded: applied,
                    error: if applied {
                        String::new()
                    } else {
                        "policy rejected".into()
                    },
                }),
        }
    }

    /// Deliver `snapshot` to `session-1` and return the supervisor's result
    /// for the update it receives.
    fn deliver_and_report(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        slots: &ConfigSlots,
        snapshot: &SandboxConfigSnapshot,
        outcome: ConfigApplyOutcome,
    ) -> ConfigUpdateResult {
        let config = SupervisorConfig {
            sandbox_config: snapshot.clone(),
            provider_environment: ProviderEnvironmentSnapshot::default(),
        };
        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config(sandbox_id, "session-1", config),
            DeliveryDisposition::Queued
        );
        reported_result(
            &sent_update(slots.take_for_test().expect("update")),
            outcome,
        )
    }

    /// Push a sandbox policy update to a running workload and return the
    /// supervisor's result for it.
    async fn running_push_session_result(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        tx: &mpsc::Sender<GatewayMessage>,
    ) -> (ConfigUpdateResult, SandboxConfigurationAdmission) {
        put_sandbox_policy_revision(state, sandbox_id).await;
        let slots = register_running_push_session(state, sandbox_id, tx);
        let snapshot = sandbox_policy_snapshot();
        let result = deliver_and_report(
            state,
            sandbox_id,
            &slots,
            &snapshot,
            ConfigApplyOutcome::Applied,
        );
        (result, expected_configuration_admission(&snapshot))
    }

    async fn wait_for_result_writer(state: &Arc<ServerState>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !state.config_delivery.results.is_idle() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("result writer drains");
    }

    #[tokio::test]
    async fn running_workload_results_are_acknowledged_without_the_sandbox_lock() {
        use crate::policy_store::PolicyStoreExt as _;

        let sandbox_id = "sb-running-result";
        let state = push_state_with_sandbox(sandbox_id).await;
        let (tx, mut rx) = mpsc::channel(4);
        let (result, admission) = running_push_session_result(&state, sandbox_id, &tx).await;

        // A user mutation holding the sandbox lock must not hold up the
        // supervisor's acknowledgement.
        let guard = crate::persistence::lock_order::branch(
            state.compute.sandbox_mutation_guard_by_id(sandbox_id),
        )
        .await
        .unwrap()
        .expect("sandbox");
        tokio::time::timeout(
            Duration::from_secs(2),
            handle_config_update_result(&accepted_session(&state, sandbox_id, tx.clone()), &result),
        )
        .await
        .expect("result is acknowledged while the sandbox lock is held");
        let Some(gateway_message::Payload::ConfigurationAdmission(sent)) =
            rx.recv().await.expect("admission").payload
        else {
            panic!("expected configuration admission");
        };
        assert_eq!(sent, admission);
        drop(guard);

        wait_for_result_writer(&state).await;
        let sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox");
        assert_eq!(
            sandbox
                .status
                .as_ref()
                .and_then(|status| status.configuration_admission.as_ref()),
            Some(&admission)
        );
        let policy = state
            .store
            .get_policy_by_version(sandbox_id, 3)
            .await
            .unwrap()
            .expect("policy revision");
        assert_eq!(policy.status, "loaded");
    }

    #[tokio::test]
    async fn result_writer_skips_admissions_from_replaced_sessions() {
        let sandbox_id = "sb-replaced-result";
        let state = push_state_with_sandbox(sandbox_id).await;
        let (tx, _rx) = mpsc::channel(4);
        let (_, admission) = running_push_session_result(&state, sandbox_id, &tx).await;

        result_writer::queue_admission(&state, sandbox_id, "session-0", "instance-0", &admission);
        wait_for_result_writer(&state).await;

        let sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox");
        assert!(
            sandbox
                .status
                .as_ref()
                .and_then(|status| status.configuration_admission.as_ref())
                .is_none(),
            "an admission from a replaced session must not be persisted"
        );
    }

    /// Fail every update of the named record type, as a database outage
    /// would.
    const FAIL_POLICY_RECORD_WRITES: &str = r#"
CREATE TRIGGER fail_result_writes BEFORE UPDATE ON "objects"
WHEN OLD."object_type" = 'sandbox_policy'
BEGIN SELECT RAISE(ABORT, 'database unavailable'); END;
"#;
    const FAIL_SANDBOX_RECORD_WRITES: &str = r#"
CREATE TRIGGER fail_result_writes BEFORE UPDATE ON "objects"
WHEN OLD."object_type" = 'sandbox'
BEGIN SELECT RAISE(ABORT, 'database unavailable'); END;
"#;
    const RESTORE_RESULT_WRITES: &str = "DROP TRIGGER fail_result_writes;";

    /// A running workload applies `snapshot` while `failing_writes` makes
    /// every attempt to persist its result fail. Once writes recover,
    /// reconciliation must redeliver the unchanged configuration so the
    /// supervisor reports the result again.
    async fn reconcile_after_result_writes_fail(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        snapshot: &SandboxConfigSnapshot,
        failing_writes: &'static str,
    ) {
        let (tx, _rx) = mpsc::channel(4);
        let slots = register_running_push_session(state, sandbox_id, &tx);
        let session = accepted_session(state, sandbox_id, tx);

        state.store.execute_for_test(failing_writes).await;
        let applied = deliver_and_report(
            state,
            sandbox_id,
            &slots,
            snapshot,
            ConfigApplyOutcome::Applied,
        );
        handle_config_update_result(&session, &applied).await;
        wait_for_result_writer(state).await;
        state.store.execute_for_test(RESTORE_RESULT_WRITES).await;

        // The supervisor already applied the configuration and reports a
        // duplicate.
        let duplicate = deliver_and_report(
            state,
            sandbox_id,
            &slots,
            snapshot,
            ConfigApplyOutcome::IgnoredDuplicate,
        );
        handle_config_update_result(&session, &duplicate).await;
        wait_for_result_writer(state).await;
    }

    #[tokio::test]
    async fn reconciliation_recovers_a_dropped_policy_result() {
        use crate::policy_store::PolicyStoreExt as _;

        let sandbox_id = "sb-dropped-policy-result";
        let state = push_state_with_sandbox(sandbox_id).await;
        put_sandbox_policy_revision(&state, sandbox_id).await;

        reconcile_after_result_writes_fail(
            &state,
            sandbox_id,
            &sandbox_policy_snapshot(),
            FAIL_POLICY_RECORD_WRITES,
        )
        .await;

        let policy = state
            .store
            .get_policy_by_version(sandbox_id, 3)
            .await
            .unwrap()
            .expect("policy revision");
        assert_eq!(policy.status, "loaded");
        let sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox");
        assert_eq!(sandbox.current_policy_version(), 3);
    }

    #[tokio::test]
    async fn reconciliation_recovers_a_dropped_admission() {
        let sandbox_id = "sb-dropped-admission";
        let state = push_state_with_sandbox(sandbox_id).await;
        // No sandbox policy, so the admission is the only result to persist.
        let snapshot = SandboxConfigSnapshot {
            policy_source: PolicySource::Unspecified.into(),
            ..sandbox_policy_snapshot()
        };

        reconcile_after_result_writes_fail(
            &state,
            sandbox_id,
            &snapshot,
            FAIL_SANDBOX_RECORD_WRITES,
        )
        .await;

        let sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox");
        assert_eq!(
            sandbox
                .status
                .as_ref()
                .and_then(|status| status.configuration_admission.as_ref()),
            Some(&expected_configuration_admission(&snapshot))
        );
    }

    #[tokio::test]
    async fn reported_policy_load_failure_is_recorded() {
        use crate::policy_store::PolicyStoreExt as _;

        let state = push_state_with_sandbox("sb-policy-result").await;
        state
            .store
            .put_policy_revision(
                "policy-3",
                "sb-policy-result",
                "default",
                3,
                &SandboxPolicy::default().encode_to_vec(),
                "hash-3",
            )
            .await
            .unwrap();
        record_or_queue_policy_result(
            &state,
            "sb-policy-result",
            "session-1",
            Some(&PolicyLoadResult {
                version: 3,
                loaded: false,
                error: "x".repeat(2_000),
            }),
        )
        .await
        .unwrap();

        let policy = state
            .store
            .get_policy_by_version("sb-policy-result", 3)
            .await
            .unwrap()
            .expect("policy revision");
        assert_eq!(policy.status, "failed");
        assert_eq!(policy.load_error.map(|error| error.len()), Some(1_024));
    }

    #[test]
    fn configuration_admission_preserves_gateway_rejection_and_accepts_repair() {
        use openshell_core::proto::ConfigurationAdmissionState;

        let mut expected = SandboxConfigurationAdmission {
            instance_id: "configuration-1".into(),
            state: ConfigurationAdmissionState::Rejected.into(),
            policy_version: 3,
            policy_hash: "policy-hash".into(),
            config_revision: 7,
            provider_env_revision: 5,
            error: "invalid image policy".into(),
        };
        let rejected = validate_configuration_admission(
            Some(&expected),
            &expected,
            ConfigApplyOutcome::Applied,
        )
        .unwrap();
        assert_eq!(rejected, expected);

        expected.state = ConfigurationAdmissionState::Accepted.into();
        expected.error.clear();
        let accepted = validate_configuration_admission(
            Some(&expected),
            &expected,
            ConfigApplyOutcome::Applied,
        )
        .unwrap();
        assert_eq!(accepted, expected);
    }

    #[tokio::test]
    async fn failed_admission_persistence_does_not_suppress_unchanged_repair() {
        let sandbox_id = "sb-admission-persistence-retry";
        let state = push_state_with_sandbox(sandbox_id).await;
        let (tx, _rx) = mpsc::channel(4);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        let slots = Arc::new(ConfigSlots::default());
        state.supervisor_sessions.register_with_mode(
            sandbox_id.into(),
            "session-1".into(),
            tx.clone(),
            shutdown_tx,
            SessionMode::Push(Arc::clone(&slots)),
        );
        let snapshot = SandboxConfigSnapshot {
            policy_source: PolicySource::Unspecified.into(),
            ..sandbox_policy_snapshot()
        };
        let result = deliver_and_report(
            &state,
            sandbox_id,
            &slots,
            &snapshot,
            ConfigApplyOutcome::Applied,
        );
        *FAIL_NEXT_ADMISSION_PERSISTENCE_FOR_SANDBOX.lock().unwrap() = Some(sandbox_id.into());

        handle_config_update_result(&accepted_session(&state, sandbox_id, tx.clone()), &result)
            .await;

        assert_eq!(
            state.supervisor_sessions.deliver_config(
                sandbox_id,
                "session-1",
                SupervisorConfig {
                    sandbox_config: snapshot,
                    provider_environment: ProviderEnvironmentSnapshot::default(),
                }
            ),
            DeliveryDisposition::Queued,
            "a non-durable admission must leave the revision eligible for repair"
        );
        assert!(matches!(
            slots.take_for_test().expect("repair update").payload,
            Some(gateway_message::Payload::ConfigUpdate(_))
        ));
    }

    #[tokio::test]
    async fn invalid_image_policy_waits_for_gateway_repair_on_same_stream() {
        use openshell_core::proto::image_policy_discovery::Result as DiscoveryResult;

        let sandbox_id = "sb-invalid-image-repair";
        let state = state_with_startup_policy(sandbox_id, None).await;
        let connecting_state = Arc::clone(&state);
        let connection = tokio::spawn(async move {
            crate::grpc::test_support::connect_supervisor_stream_with_image_policy_discovery(
                &connecting_state,
                sandbox_id,
                StreamFeatures::Apply,
                openshell_core::proto::ImagePolicyDiscovery {
                    result: Some(DiscoveryResult::Invalid(())),
                },
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !connection.is_finished(),
            "invalid image policy must keep the startup stream pending"
        );

        let repaired_policy = openshell_policy::restrictive_default_policy();
        let mut sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox exists");
        sandbox.spec.get_or_insert_default().policy = Some(repaired_policy.clone());
        state.store.put_message(&sandbox).await.unwrap();
        state.sandbox_watch_bus.notify(sandbox_id);

        let mut harness = tokio::time::timeout(Duration::from_secs(5), connection)
            .await
            .expect("repair resumes the pending stream")
            .expect("connection task")
            .expect("supervisor connects after repair");
        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate after repair");
        };
        assert_eq!(candidate.policy.as_ref(), Some(&repaired_policy));
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::Unchanged(())),
                    },
                )),
            })
            .await
            .unwrap();
        assert!(matches!(
            first_gateway_message(&mut harness).await.payload,
            Some(gateway_message::Payload::SessionAccepted(_))
        ));
    }

    #[tokio::test]
    async fn invalid_prepared_policy_rejects_session_without_acceptance() {
        let image_policy = openshell_policy::restrictive_default_policy();
        let mut invalid_policy = image_policy.clone();
        invalid_policy
            .filesystem
            .get_or_insert_default()
            .read_only
            .push("relative/path".into());
        let state = state_with_startup_policy("sb-startup-invalid", None).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream_with_image_policy(
            &state,
            "sb-startup-invalid",
            StreamFeatures::Apply,
            Some(image_policy),
        )
        .await
        .expect("supervisor must connect");

        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate");
        };
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::PreparedPolicy(
                            invalid_policy,
                        )),
                    },
                )),
            })
            .await
            .unwrap();

        let Some(gateway_message::Payload::SessionRejected(rejected)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("invalid preparation must reject without accepting the session");
        };
        assert!(rejected.reason.contains("policy"));
    }

    /// Register a streamed-apply session whose control channel stays open
    /// for as long as the returned receiver lives.
    fn register_apply_session_in_state(
        state: &ServerState,
        sandbox_id: &str,
    ) -> (
        mpsc::Sender<GatewayMessage>,
        mpsc::Receiver<GatewayMessage>,
        Arc<ConfigSlots>,
    ) {
        let (tx, rx) = mpsc::channel(1);
        let slots = Arc::new(ConfigSlots::default());
        state.supervisor_sessions.register_with_mode(
            sandbox_id.into(),
            "session-1".into(),
            tx.clone(),
            make_shutdown(),
            SessionMode::Push(Arc::clone(&slots)),
        );
        (tx, rx, slots)
    }

    fn admitted_config() -> SupervisorConfig {
        SupervisorConfig {
            sandbox_config: SandboxConfigSnapshot {
                configuration_instance_id: "configuration-1".into(),
                configuration_admitted: true,
                config_revision: 7,
                provider_env_revision: 11,
                ..Default::default()
            },
            provider_environment: ProviderEnvironmentSnapshot {
                provider_env_revision: 11,
                ..Default::default()
            },
        }
    }

    async fn current_config(state: &Arc<ServerState>, sandbox_id: &str) -> SupervisorConfig {
        let sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox exists");
        build_config_bootstrap(state, &sandbox).await.unwrap()
    }

    /// Put `config` in flight on `session-1` as its bootstrap.
    fn begin_bootstrap(
        state: &ServerState,
        sandbox_id: &str,
        config: SupervisorConfig,
    ) -> ConfigUpdate {
        let (update, in_flight) = bootstrap_update(config);
        state
            .supervisor_sessions
            .begin_config_bootstrap(sandbox_id, "session-1", in_flight);
        update
    }

    #[tokio::test]
    async fn persisted_bootstrap_result_suppresses_unchanged_reconciliation() {
        let state = state_with_startup_policy("sb-bootstrap-ack", None).await;
        let (tx, mut rx, slots) = register_apply_session_in_state(&state, "sb-bootstrap-ack");
        let config = current_config(&state, "sb-bootstrap-ack").await;
        let bootstrap = begin_bootstrap(&state, "sb-bootstrap-ack", config.clone());

        assert!(
            handle_config_update_result(
                &accepted_session(&state, "sb-bootstrap-ack", tx),
                &applied_result(&bootstrap),
            )
            .await
        );
        assert!(matches!(
            rx.recv().await.expect("admission").payload,
            Some(gateway_message::Payload::ConfigurationAdmission(_))
        ));
        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config("sb-bootstrap-ack", "session-1", config),
            DeliveryDisposition::SuppressedUnchanged
        );
        assert!(slots.take_for_test().is_none());
    }

    #[tokio::test]
    async fn startup_admission_waits_for_configuration_committed_after_the_bootstrap() {
        use crate::policy_store::PolicyStoreExt as _;
        use openshell_core::proto::ConfigurationAdmissionState;

        let sandbox_id = "sb-bootstrap-superseded";
        let state = state_with_startup_policy(sandbox_id, None).await;
        let put_policy = |version: u32, policy: SandboxPolicy| {
            let state = Arc::clone(&state);
            async move {
                state
                    .store
                    .put_policy_revision(
                        &format!("policy-{version}"),
                        sandbox_id,
                        "default",
                        i64::from(version),
                        &policy.encode_to_vec(),
                        &format!("hash-{version}"),
                    )
                    .await
                    .unwrap();
            }
        };
        let policy = openshell_policy::restrictive_default_policy();
        put_policy(1, policy.clone()).await;
        let (tx, mut rx, slots) = register_apply_session_in_state(&state, sandbox_id);
        let session = accepted_session(&state, sandbox_id, tx);
        let bootstrap =
            begin_bootstrap(&state, sandbox_id, current_config(&state, sandbox_id).await);

        // A newer policy commits while the supervisor applies the bootstrap,
        // and its build is held behind the bootstrap.
        let mut newer_policy = policy;
        newer_policy
            .filesystem
            .get_or_insert_default()
            .read_only
            .push("/opt".into());
        put_policy(2, newer_policy).await;
        let newer = current_config(&state, sandbox_id).await;
        assert_ne!(
            newer.sandbox_config.config_revision,
            bootstrap.sandbox_config.as_ref().unwrap().config_revision
        );
        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config(sandbox_id, "session-1", newer.clone()),
            DeliveryDisposition::Coalesced
        );

        assert!(
            handle_config_update_result(&session, &applied_result(&bootstrap)).await,
            "a superseded bootstrap keeps the session open"
        );
        assert!(
            rx.try_recv().is_err(),
            "a superseded bootstrap must not unlock startup"
        );
        let stored = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            stored
                .status
                .and_then(|status| status.configuration_activated),
            Some(true)
        );

        // The held configuration is released, and its admission unlocks
        // startup.
        let update = sent_update(slots.take_for_test().expect("released newer configuration"));
        assert!(handle_config_update_result(&session, &applied_result(&update)).await);
        let Some(gateway_message::Payload::ConfigurationAdmission(admitted)) = rx
            .try_recv()
            .expect("the newer configuration's admission is sent")
            .payload
        else {
            panic!("expected configuration admission");
        };
        assert_eq!(
            admitted.config_revision,
            newer.sandbox_config.config_revision
        );
        assert_eq!(
            admitted.state,
            i32::from(ConfigurationAdmissionState::Accepted)
        );
    }

    #[tokio::test]
    async fn invalid_bootstrap_admission_closes_the_session_without_acknowledging() {
        let state = push_state_with_sandbox("sb-bootstrap-invalid").await;
        let (tx, _rx, slots) = register_apply_session_in_state(&state, "sb-bootstrap-invalid");
        let config = admitted_config();
        let bootstrap = begin_bootstrap(&state, "sb-bootstrap-invalid", config.clone());
        let mut result = applied_result(&bootstrap);
        result.admission.as_mut().unwrap().config_revision = 8;

        assert!(
            !handle_config_update_result(
                &accepted_session(&state, "sb-bootstrap-invalid", tx),
                &result,
            )
            .await,
            "a mismatched admission closes the session"
        );
        // The bootstrap was not acknowledged, so it remains eligible.
        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config("sb-bootstrap-invalid", "session-1", config),
            DeliveryDisposition::Queued
        );
        assert!(slots.take_for_test().is_some());
    }

    #[tokio::test]
    async fn prepared_policy_is_validated_and_returned_in_fresh_bootstrap() {
        let image_policy = openshell_policy::restrictive_default_policy();
        let mut prepared_policy = image_policy.clone();
        prepared_policy
            .filesystem
            .get_or_insert_default()
            .read_only
            .push("/prepared-path".into());
        let state = state_with_startup_policy("sb-startup-prepared", None).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream_with_image_policy(
            &state,
            "sb-startup-prepared",
            StreamFeatures::Apply,
            Some(image_policy),
        )
        .await
        .expect("supervisor must connect");

        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate");
        };
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::PreparedPolicy(
                            prepared_policy.clone(),
                        )),
                    },
                )),
            })
            .await
            .unwrap();

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        assert_eq!(
            accepted
                .bootstrap
                .and_then(|bootstrap| bootstrap.sandbox_config)
                .and_then(|snapshot| snapshot.policy),
            Some(prepared_policy)
        );
    }

    #[test]
    fn fingerprint_covers_the_provider_environment_the_configuration_names() {
        let registry = SupervisorSessionRegistry::new();
        let snapshot = SandboxConfigSnapshot {
            configuration_admitted: true,
            config_revision: 7,
            provider_env_revision: 11,
            provider_attachment_epoch: "epoch-1".into(),
            policy_hash: "policy-1".into(),
            ..Default::default()
        };
        let with = |snapshot: SandboxConfigSnapshot| SupervisorConfig {
            sandbox_config: snapshot,
            provider_environment: ProviderEnvironmentSnapshot::default(),
        };
        let changes = [
            SandboxConfigSnapshot {
                provider_env_revision: 12,
                ..snapshot.clone()
            },
            SandboxConfigSnapshot {
                provider_attachment_epoch: "epoch-2".into(),
                ..snapshot.clone()
            },
            SandboxConfigSnapshot {
                policy_hash: "policy-2".into(),
                ..snapshot.clone()
            },
        ];
        for (index, changed) in changes.into_iter().enumerate() {
            let session_id = format!("session-{index}");
            let (slots, bootstrap) = register_bootstrapped_session(
                &registry,
                "sb-1",
                &session_id,
                with(snapshot.clone()),
            );
            answer_bootstrap(
                &registry,
                "sb-1",
                &session_id,
                &bootstrap,
                ConfigApplyOutcome::Applied,
            );
            assert_eq!(
                registry.deliver_config("sb-1", &session_id, with(snapshot.clone())),
                DeliveryDisposition::SuppressedUnchanged
            );
            assert_eq!(
                registry.deliver_config("sb-1", &session_id, with(changed)),
                DeliveryDisposition::Queued
            );
            assert!(slots.take_for_test().is_some());
        }
    }

    async fn report_bootstrap_and_runtime_ready(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        harness: &mut crate::grpc::test_support::SupervisorStreamHarness,
        bootstrap: &ConfigUpdate,
    ) {
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::ConfigUpdateResult(
                    applied_result(bootstrap),
                )),
            })
            .await
            .unwrap();
        assert!(matches!(
            first_gateway_message(harness).await.payload,
            Some(gateway_message::Payload::ConfigurationAdmission(_))
        ));
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::RuntimeReady(
                    openshell_core::proto::SupervisorRuntimeReady {},
                )),
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !state.supervisor_sessions.is_runtime_ready(sandbox_id) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("runtime readiness before timeout");
    }

    /// Prepare a first session's startup policy unchanged and return the
    /// bootstrap it is accepted with.
    async fn accept_unchanged_startup_policy(
        harness: &mut crate::grpc::test_support::SupervisorStreamHarness,
    ) -> ConfigUpdate {
        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(harness).await.payload
        else {
            panic!("initial session must prepare the startup policy");
        };
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::Unchanged(())),
                    },
                )),
            })
            .await
            .unwrap();
        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(harness).await.payload
        else {
            panic!("expected initial SessionAccepted");
        };
        accepted.bootstrap.expect("initial authoritative bootstrap")
    }

    #[tokio::test]
    async fn failed_runtime_readiness_save_closes_the_session_for_a_reconnect() {
        use openshell_core::proto::SandboxPhase;

        let sandbox_id = "sb-readiness-save-failure";
        let policy = openshell_policy::restrictive_default_policy();
        let state = state_with_startup_policy(sandbox_id, Some(policy)).await;
        // A new sandbox provisions under an armed deadline.
        let mut sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox");
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        sandbox
            .status
            .get_or_insert_with(Default::default)
            .provisioning = Some(crate::compute::provisioning_deadline::new_record(
            openshell_core::time::now_ms(),
        ));
        state.store.put_message(&sandbox).await.unwrap();

        let mut initial = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            sandbox_id,
            StreamFeatures::Apply,
        )
        .await
        .expect("initial supervisor connection");
        let bootstrap = accept_unchanged_startup_policy(&mut initial).await;
        initial
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::ConfigUpdateResult(
                    applied_result(&bootstrap),
                )),
            })
            .await
            .unwrap();
        assert!(matches!(
            first_gateway_message(&mut initial).await.payload,
            Some(gateway_message::Payload::ConfigurationAdmission(_))
        ));

        // The supervisor reports readiness again only after another admission,
        // so a lost save must close the session instead of leaving the running
        // workload to the provisioning deadline.
        state
            .store
            .execute_for_test(FAIL_SANDBOX_RECORD_WRITES)
            .await;
        initial
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::RuntimeReady(
                    openshell_core::proto::SupervisorRuntimeReady {},
                )),
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Ok(Some(_)) = initial.inbound.message().await {}
        })
        .await
        .expect("gateway closes the session after a failed readiness save");
        state.store.execute_for_test(RESTORE_RESULT_WRITES).await;

        let mut reconnect = crate::grpc::test_support::reconnect_supervisor_stream(
            &state,
            sandbox_id,
            StreamFeatures::Apply,
        )
        .await
        .expect("supervisor reconnects");
        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut reconnect).await.payload
        else {
            panic!("expected SessionAccepted on reconnect");
        };
        let bootstrap = accepted
            .bootstrap
            .expect("reconnect authoritative bootstrap");
        report_bootstrap_and_runtime_ready(&state, sandbox_id, &mut reconnect, &bootstrap).await;

        let sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox");
        assert_eq!(sandbox.phase(), SandboxPhase::Ready as i32);
        let provisioning = sandbox
            .status
            .as_ref()
            .and_then(|status| status.provisioning.as_ref())
            .expect("provisioning record");
        assert!(
            provisioning.deadline.is_none() && provisioning.timeout_time.is_none(),
            "readiness ends provisioning before the deadline can reclaim the workload"
        );
    }

    #[tokio::test]
    async fn apply_reconnect_skips_startup_preparation_and_restores_readiness() {
        let sandbox_id = "sb-reconnect-no-preparation";
        let policy = openshell_policy::restrictive_default_policy();
        let state = state_with_startup_policy(sandbox_id, Some(policy)).await;
        let mut initial = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            sandbox_id,
            StreamFeatures::Apply,
        )
        .await
        .expect("initial supervisor connection");
        let bootstrap = accept_unchanged_startup_policy(&mut initial).await;
        report_bootstrap_and_runtime_ready(&state, sandbox_id, &mut initial, &bootstrap).await;
        drop(initial);

        let mut reconnect = crate::grpc::test_support::reconnect_supervisor_stream(
            &state,
            sandbox_id,
            StreamFeatures::Apply,
        )
        .await
        .expect("stock supervisor reconnect");
        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut reconnect).await.payload
        else {
            panic!("reconnect must proceed directly to SessionAccepted");
        };
        let bootstrap = accepted
            .bootstrap
            .expect("reconnect authoritative bootstrap");
        report_bootstrap_and_runtime_ready(&state, sandbox_id, &mut reconnect, &bootstrap).await;
    }

    #[tokio::test]
    async fn poll_mode_gateway_does_not_enable_apply() {
        let state = state_with_sandbox("sb-poll-apply").await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            "sb-poll-apply",
            StreamFeatures::Apply,
        )
        .await
        .expect("apply-capable supervisor connects in poll mode");

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted without a startup candidate");
        };
        assert!(!accepted.config_push_enabled);
        assert!(accepted.bootstrap.is_none());

        // This supervisor connects before its workload starts, so acceptance
        // alone must not report it ready.
        assert!(!state.supervisor_sessions.is_runtime_ready("sb-poll-apply"));
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::RuntimeReady(
                    openshell_core::proto::SupervisorRuntimeReady {},
                )),
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !state.supervisor_sessions.is_runtime_ready("sb-poll-apply") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("runtime readiness marks the polling session ready");
    }

    #[tokio::test]
    async fn repeated_runtime_readiness_is_not_persisted_again() {
        let sandbox_id = "sb-ready-repeat";
        let state = state_with_sandbox(sandbox_id).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            sandbox_id,
            StreamFeatures::Apply,
        )
        .await
        .expect("supervisor connects");
        first_gateway_message(&mut harness).await;
        let runtime_ready = || SupervisorMessage {
            payload: Some(supervisor_message::Payload::RuntimeReady(
                openshell_core::proto::SupervisorRuntimeReady {},
            )),
        };
        harness.outbound.send(runtime_ready()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !state.supervisor_sessions.is_runtime_ready(sandbox_id) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("first readiness report is persisted");
        let resource_version = || async {
            state
                .store
                .get_message::<Sandbox>(sandbox_id)
                .await
                .unwrap()
                .and_then(|sandbox| sandbox.metadata.map(|metadata| metadata.resource_version))
        };
        let before = resource_version().await;

        // Supervisors report readiness again after every accepted admission.
        for _ in 0..3 {
            harness.outbound.send(runtime_ready()).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(resource_version().await, before);
    }

    #[tokio::test]
    async fn polling_reconnect_after_workload_start_is_ready_on_accept() {
        let state = state_with_sandbox("sb-poll-running").await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            "sb-poll-running",
            StreamFeatures::ApplyAfterStart,
        )
        .await
        .expect("apply-capable supervisor reconnects in poll mode");

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        assert!(!accepted.config_push_enabled);
        // Its workload already runs, so it is ready like a supervisor that
        // predates streamed apply.
        assert!(
            state
                .supervisor_sessions
                .is_runtime_ready("sb-poll-running")
        );
    }

    #[tokio::test]
    async fn startup_candidate_prefers_gateway_policy_and_accepts_unchanged_result() {
        let gateway_policy = openshell_policy::restrictive_default_policy();
        let mut image_policy = gateway_policy.clone();
        image_policy
            .filesystem
            .get_or_insert_default()
            .read_only
            .push("/image-only".into());
        let state =
            state_with_startup_policy("sb-startup-gateway", Some(gateway_policy.clone())).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream_with_image_policy(
            &state,
            "sb-startup-gateway",
            StreamFeatures::Apply,
            Some(image_policy),
        )
        .await
        .expect("supervisor must connect");

        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate");
        };
        assert_eq!(candidate.policy.as_ref(), Some(&gateway_policy));
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::Unchanged(())),
                    },
                )),
            })
            .await
            .unwrap();

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        assert_eq!(
            accepted
                .bootstrap
                .and_then(|bootstrap| bootstrap.sandbox_config)
                .and_then(|snapshot| snapshot.policy),
            Some(gateway_policy)
        );
    }

    async fn state_with_startup_policy(
        sandbox_id: &str,
        policy: Option<SandboxPolicy>,
    ) -> Arc<ServerState> {
        let state = push_state().await;
        let mut sandbox = sandbox_record(sandbox_id, sandbox_id);
        sandbox.spec = Some(SandboxSpec {
            policy,
            ..SandboxSpec::default()
        });
        state.store.put_message(&sandbox).await.unwrap();
        state
    }

    #[tokio::test]
    async fn unchanged_image_policy_is_persisted_before_session_acceptance() {
        let image_policy = openshell_policy::restrictive_default_policy();
        let state = state_with_startup_policy("sb-startup-image", None).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream_with_image_policy(
            &state,
            "sb-startup-image",
            StreamFeatures::Apply,
            Some(image_policy.clone()),
        )
        .await
        .expect("supervisor must connect");

        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate");
        };
        assert_eq!(candidate.policy.as_ref(), Some(&image_policy));
        assert_eq!(candidate.policy_version, 0);
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::Unchanged(())),
                    },
                )),
            })
            .await
            .unwrap();

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        let snapshot = accepted
            .bootstrap
            .and_then(|bootstrap| bootstrap.sandbox_config)
            .expect("authoritative sandbox snapshot");
        assert_eq!(snapshot.policy, Some(image_policy));
        assert_eq!(snapshot.version, 1);
    }
}
