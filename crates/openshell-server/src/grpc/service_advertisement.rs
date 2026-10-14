// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Expiring app route installation evidence, fenced by supervisor session ownership.
//! Like the supervisor-owner index, these private JSON records are ephemeral and
//! fail closed after restart, ownership replacement, declaration changes, or expiry.

use crate::ServerState;
use crate::compute::MutationScope;
use crate::persistence::{ObjectCursor, ObjectRecord, PersistenceError, WriteCondition};
use crate::supervisor_owner::{OWNER_TTL, OwnerGuard, SupervisorOwnerIndex};
use openshell_core::config::ServiceRoutingConfig;
use openshell_core::proto::{Sandbox, SandboxPhase, SupervisorServiceAdvertisement};
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tonic::Status;

pub(super) const OBJECT_TYPE: &str = "supervisor_service_advertisement";
const MAX_ROUTES: usize = 1024;
const LEASE_MS: i64 = 30_000;
const SANDBOX_PLACEHOLDER: &str = "{sandbox}";
const CLEANUP_PAGE_SIZE: u32 = 128;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RouteStamp {
    pub endpoint_id: String,
    pub resource_version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Advertisement {
    pub sandbox_id: String,
    pub session_id: String,
    pub supervisor_instance_id: String,
    pub connection_epoch: u64,
    pub service_domain: String,
    pub address: String,
    pub expires_at_ms: i64,
    pub report_sequence: u64,
    pub digest: String,
    pub routes: Vec<RouteStamp>,
}

/// Retain sequence fences until the publishing session is permanently fenced.
/// Expiry, withdrawal, or a missing/expired owner alone is not sufficient.
async fn cleanup_record(state: &Arc<ServerState>, record: &ObjectRecord) -> Result<bool, Status> {
    let advertisement: Advertisement = serde_json::from_slice(&record.payload)
        .map_err(|_| Status::internal("invalid stored service advertisement"))?;
    let _guard = state
        .compute
        .mutation_guard(MutationScope::sandbox(
            &record.workspace,
            &advertisement.sandbox_id,
        ))
        .await
        .map_err(|_| Status::internal("service advertisement cleanup lock failed"))?;
    let current = state
        .store
        .get(OBJECT_TYPE, &record.id)
        .await
        .map_err(|_| Status::unavailable("service advertisement unavailable during cleanup"))?;
    // Versions restart when a deleted object is recreated. Check the payload
    // under the publisher's lock too, not only the version captured by paging.
    if current.is_none_or(|current| {
        current.resource_version != record.resource_version || current.payload != record.payload
    }) {
        return Ok(false);
    }
    let sandbox = state
        .store
        .get_message::<Sandbox>(&advertisement.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("sandbox unavailable during advertisement cleanup"))?;
    let permanently_fenced = if sandbox.is_none() {
        true
    } else {
        let owner = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
            .read(&advertisement.sandbox_id)
            .await
            .map_err(|_| Status::unavailable("supervisor ownership unavailable during cleanup"))?;
        owner.is_some_and(|owner| {
            owner.session_id != advertisement.session_id
                || owner.supervisor_instance_id != advertisement.supervisor_instance_id
                || owner.connection_epoch != advertisement.connection_epoch
        })
    };
    if !permanently_fenced {
        return Ok(false);
    }
    match state
        .store
        .delete_if(OBJECT_TYPE, &record.id, record.resource_version)
        .await
    {
        Ok(deleted) => Ok(deleted),
        // A replacement or renewal won the race; a later page may inspect it.
        Err(PersistenceError::Conflict { .. }) => Ok(false),
        Err(_) => Err(Status::unavailable("service advertisement cleanup failed")),
    }
}

async fn cleanup_page(
    state: &Arc<ServerState>,
    after: Option<&ObjectCursor>,
) -> Result<Option<ObjectCursor>, Status> {
    let records = state
        .store
        .list_by_type_after(OBJECT_TYPE, after, CLEANUP_PAGE_SIZE)
        .await
        .map_err(|_| Status::unavailable("service advertisements unavailable during cleanup"))?;
    // Capture the cursor before deletion so removals cannot shift the next page.
    let next = (records.len() == CLEANUP_PAGE_SIZE as usize)
        .then(|| records.last().map(ObjectCursor::from))
        .flatten();
    for record in records {
        if cleanup_record(state, &record).await.is_err() {
            tracing::warn!("Service advertisement cleanup skipped an unavailable record");
        }
    }
    Ok(next)
}

/// Bound each sweep's work, release the mutation guard between records, and
/// stop promptly with the gateway. Multiple replicas may safely sweep together.
pub fn spawn_cleanup_worker(
    state: Arc<ServerState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut after = None;
        let mut timer = tokio::time::interval(CLEANUP_INTERVAL);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                    continue;
                },
                _ = timer.tick() => {},
            }
            let sweep = tokio::time::timeout(CLEANUP_TIMEOUT, cleanup_page(&state, after.as_ref()));
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                },
                result = sweep => {
                    if let Ok(Ok(next)) = result {
                        after = next;
                    } else {
                        tracing::warn!("Service advertisement cleanup deferred an incomplete page");
                    }
                },
            }
        }
    })
}

pub fn validate_config(config: &ServiceRoutingConfig) -> Result<(), String> {
    crate::service_routing::validate_ingress_config(config)?;
    match (
        &config.supervisor_app_address_template,
        &config.supervisor_app_service_domain,
    ) {
        (None, None) => Ok(()),
        (Some(template), Some(domain)) => {
            if !valid_domain(domain) {
                return Err("supervisor app service domain must be lowercase DNS".into());
            }
            validate_address(
                &template
                    .replace("{sandbox_id}", "id")
                    .replace(SANDBOX_PLACEHOLDER, "sandbox")
                    .replace("{workspace}", "default"),
            )
        }
        _ => Err(
            "supervisor app address template and service domain must be configured together".into(),
        ),
    }
}

fn valid_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn validate_address(address: &str) -> Result<(), String> {
    let authority: http::uri::Authority = address
        .parse()
        .map_err(|_| "invalid supervisor app address")?;
    if authority.host().is_empty()
        || authority.port_u16().is_none_or(|port| port == 0)
        || address.contains(['@', '{', '}', '/', '?', '#'])
    {
        return Err("supervisor app address must be host:port without URL or credentials".into());
    }
    Ok(())
}

pub async fn accept(
    state: &Arc<ServerState>,
    owner: &OwnerGuard,
    report: SupervisorServiceAdvertisement,
) -> Result<(), Status> {
    let Some(_guard) = state
        .compute
        .sandbox_mutation_guard_by_id(&owner.sandbox_id)
        .await
        .map_err(|_| Status::internal("service advertisement mutation lock failed"))?
    else {
        return Err(Status::not_found("sandbox not found"));
    };
    if !state
        .supervisor_sessions
        .is_endpoint_status_authority(&owner.sandbox_id, &owner.session_id)
    {
        return Err(Status::permission_denied(
            "service advertisement requires the current supervisor session",
        ));
    }
    let current_owner = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
        .read(&owner.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("supervisor ownership unavailable"))?;
    if !current_owner.is_some_and(|current| {
        current.is_fresh(OWNER_TTL)
            && current.session_id == owner.session_id
            && current.supervisor_instance_id == owner.supervisor_instance_id
            && current.connection_epoch == owner.connection_epoch
    }) {
        return Err(Status::permission_denied(
            "service advertisement ownership changed",
        ));
    }
    let id = format!("service-advertisement:{}", owner.sandbox_id);
    let previous = state
        .store
        .get(OBJECT_TYPE, &id)
        .await
        .map_err(|_| Status::internal("load service advertisement failed"))?;
    let digest = format!("{:x}", Sha256::digest(report.encode_to_vec()));
    if report.report_sequence == 0 {
        return Err(Status::invalid_argument("report_sequence is required"));
    }
    if let Some(previous) = &previous {
        let stored: Advertisement = serde_json::from_slice(&previous.payload)
            .map_err(|_| Status::internal("invalid stored service advertisement"))?;
        if stored.session_id == owner.session_id {
            if report.report_sequence < stored.report_sequence {
                return Err(Status::failed_precondition("older service advertisement"));
            }
            if report.report_sequence == stored.report_sequence {
                return if stored.digest == digest {
                    Ok(())
                } else {
                    Err(Status::invalid_argument(
                        "sequence must reuse identical advertisement",
                    ))
                };
            }
        }
    }
    let sandbox = state
        .store
        .get_message::<Sandbox>(&owner.sandbox_id)
        .await
        .map_err(|_| Status::internal("load sandbox failed"))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let mut advertisement = Advertisement {
        sandbox_id: owner.sandbox_id.clone(),
        session_id: owner.session_id.clone(),
        supervisor_instance_id: owner.supervisor_instance_id.clone(),
        connection_epoch: owner.connection_epoch,
        service_domain: String::new(),
        address: String::new(),
        expires_at_ms: 0,
        report_sequence: report.report_sequence,
        digest,
        routes: Vec::new(),
    };
    // Keep a withdrawal tombstone so delayed lower sequences cannot revive it.
    if !report.routes.is_empty() {
        if report.routes.len() > MAX_ROUTES {
            return Err(Status::resource_exhausted(
                "too many advertised service routes",
            ));
        }
        if SandboxPhase::try_from(sandbox.phase()).ok() != Some(SandboxPhase::Ready)
            || sandbox.status.as_ref().is_none_or(|status| {
                status.main_process_instance_id != owner.supervisor_instance_id
            })
        {
            return Err(Status::failed_precondition(
                "sandbox runtime is not ready for service advertisements",
            ));
        }
        let config = &state.config.service_routing;
        validate_config(config).map_err(Status::failed_precondition)?;
        let template = config
            .supervisor_app_address_template
            .as_ref()
            .ok_or_else(|| {
                Status::failed_precondition("supervisor app publication is not configured")
            })?;
        if config.supervisor_app_service_domain.as_deref() != Some(report.service_domain.as_str()) {
            return Err(Status::failed_precondition(
                "app listener service domain does not match operator configuration",
            ));
        }
        let address = template
            .replace("{sandbox_id}", sandbox.object_id())
            .replace(SANDBOX_PLACEHOLDER, sandbox.object_name())
            .replace("{workspace}", sandbox.object_workspace());
        validate_address(&address).map_err(Status::failed_precondition)?;
        let expires = report
            .expires_at
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("advertisement expiry is required"))?;
        let expires = openshell_core::time::timestamp_to_millis(expires)
            .map_err(|_| Status::invalid_argument("invalid advertisement expiry"))?;
        let now = openshell_core::time::now_ms();
        if expires <= now {
            return Err(Status::failed_precondition("service advertisement expired"));
        }
        let accepted = super::policy::load_sandbox_config(state, &sandbox).await?;
        if !accepted.configuration_admitted {
            return Err(Status::failed_precondition(
                "sandbox configuration is not admitted",
            ));
        }
        let mut seen = BTreeSet::new();
        for route in report.routes {
            if !seen.insert(route.endpoint_id.clone()) || !accepted.service_routes.contains(&route)
            {
                return Err(Status::failed_precondition(
                    "advertisement does not match current service declarations",
                ));
            }
            advertisement.routes.push(RouteStamp {
                endpoint_id: route.endpoint_id,
                resource_version: route.resource_version,
            });
        }
        advertisement
            .routes
            .sort_by(|a, b| a.endpoint_id.cmp(&b.endpoint_id));
        advertisement.address = address;
        advertisement.service_domain = report.service_domain;
        advertisement.expires_at_ms = expires.min(now.saturating_add(LEASE_MS));
    }
    let payload = serde_json::to_vec(&advertisement)
        .map_err(|_| Status::internal("encode service advertisement failed"))?;
    let condition = previous
        .as_ref()
        .map_or(WriteCondition::MustCreate, |record| {
            WriteCondition::MatchResourceVersion(record.resource_version)
        });
    state
        .store
        .put_if(
            OBJECT_TYPE,
            &id,
            &owner.sandbox_id,
            sandbox.object_workspace(),
            &payload,
            None,
            condition,
        )
        .await
        .map_err(|_| Status::aborted("service advertisement changed while publishing"))?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::test_support::{authed_request, test_server_state};
    use super::*;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{
        ExposeServiceRequest, FilesystemPolicy, SandboxPolicy, SandboxSpec, SandboxStatus,
    };

    pub async fn fixture() -> (Arc<ServerState>, OwnerGuard, SupervisorServiceAdvertisement) {
        let mut state = test_server_state().await;
        Arc::get_mut(&mut state).unwrap().admin_role = "openshell-admin".into();
        let config = &mut Arc::get_mut(&mut state).unwrap().config.service_routing;
        config.supervisor_app_address_template =
            Some("app-{sandbox_id}.{workspace}.svc:443".into());
        config.supervisor_app_service_domain = Some("svc.openshell.internal".into());
        let sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sandbox-a-id".into(),
                name: "sandbox-a".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        include_workdir: true,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: Some(SandboxStatus {
                phase: SandboxPhase::Ready as i32,
                main_process_instance_id: "runtime-a".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        state.store.put_message(&sandbox).await.unwrap();
        let owner = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
            .publish(
                "sandbox-a-id",
                "session-a",
                "runtime-a",
                1,
                &state.replica_id,
                "local://test",
            )
            .await
            .unwrap();
        register(&state, "session-a");
        super::super::service::handle_expose_service(
            &state,
            authed_request(ExposeServiceRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                sandbox: "sandbox-a".into(),
                name: "web".into(),
                target_port: 8080,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let config = super::super::policy::load_sandbox_config(&state, &sandbox)
            .await
            .unwrap();
        assert!(config.configuration_admitted);
        let advertisement = SupervisorServiceAdvertisement {
            service_domain: "svc.openshell.internal".into(),
            routes: config.service_routes,
            expires_at: openshell_core::time::timestamp_from_millis(
                openshell_core::time::now_ms() + 20_000,
            )
            .ok(),
            report_sequence: 1,
        };
        (state, owner, advertisement)
    }
    fn register(state: &ServerState, session: &str) {
        state.supervisor_sessions.register(
            "sandbox-a-id".into(),
            session.into(),
            tokio::sync::mpsc::channel(1).0,
            tokio::sync::oneshot::channel().0,
        );
        assert!(
            state
                .supervisor_sessions
                .initialize_endpoint_status_authority("sandbox-a-id", session)
        );
    }
    async fn stored(state: &ServerState) -> Advertisement {
        serde_json::from_slice(
            &state
                .store
                .get(OBJECT_TYPE, "service-advertisement:sandbox-a-id")
                .await
                .unwrap()
                .unwrap()
                .payload,
        )
        .unwrap()
    }
    #[tokio::test]
    async fn advertisement_is_operator_addressed_and_idempotent() {
        let (state, owner, report) = fixture().await;
        accept(&state, &owner, report.clone()).await.unwrap();
        let initial = stored(&state).await;
        assert_eq!(initial.address, "app-sandbox-a-id.default.svc:443");
        assert_eq!(initial.routes.len(), 1);
        accept(&state, &owner, report.clone()).await.unwrap();
        assert_eq!(stored(&state).await.expires_at_ms, initial.expires_at_ms);
        let mut changed = report;
        changed.routes[0].target_port = 9090;
        assert_eq!(
            accept(&state, &owner, changed).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
    #[tokio::test]
    async fn advertisement_rejects_broadened_stale_and_expired_routes() {
        let (state, owner, report) = fixture().await;
        for field in 0..4 {
            let mut forged = report.clone();
            match field {
                0 => forged.routes[0].target_port = 9090,
                1 => forged.routes[0].endpoint_id = "other-sandbox-service".into(),
                2 => forged.routes[0].resource_version += 1,
                _ => forged.expires_at = openshell_core::time::timestamp_from_millis(1).ok(),
            }
            assert_eq!(
                accept(&state, &owner, forged).await.unwrap_err().code(),
                tonic::Code::FailedPrecondition
            );
        }
        assert!(
            state
                .store
                .get(OBJECT_TYPE, "service-advertisement:sandbox-a-id")
                .await
                .unwrap()
                .is_none()
        );
    }
    #[tokio::test]
    async fn advertisement_withdrawal_and_session_replacement_are_fenced() {
        let (state, owner, report) = fixture().await;
        accept(&state, &owner, report.clone()).await.unwrap();
        let mut withdrawal = report.clone();
        withdrawal.routes.clear();
        withdrawal.report_sequence = 2;
        accept(&state, &owner, withdrawal).await.unwrap();
        assert!(stored(&state).await.routes.is_empty());
        assert_eq!(
            accept(&state, &owner, report.clone())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
        let replacement = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
            .publish(
                "sandbox-a-id",
                "session-b",
                "runtime-a",
                2,
                &state.replica_id,
                "local://test",
            )
            .await
            .unwrap();
        register(&state, "session-b");
        assert_eq!(
            accept(&state, &owner, report.clone())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        accept(&state, &replacement, report).await.unwrap();
        assert_eq!(stored(&state).await.session_id, "session-b");
    }

    async fn record(state: &ServerState) -> ObjectRecord {
        state
            .store
            .get(OBJECT_TYPE, "service-advertisement:sandbox-a-id")
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn cleanup_preserves_expired_and_withdrawn_sequence_fences() {
        let (state, owner, report) = fixture().await;
        accept(&state, &owner, report.clone()).await.unwrap();
        let previous = record(&state).await;
        let mut expired = stored(&state).await;
        expired.expires_at_ms = 0;
        state
            .store
            .put_if(
                OBJECT_TYPE,
                &previous.id,
                &previous.name,
                &previous.workspace,
                &serde_json::to_vec(&expired).unwrap(),
                None,
                WriteCondition::MatchResourceVersion(previous.resource_version),
            )
            .await
            .unwrap();
        assert!(!cleanup_record(&state, &record(&state).await).await.unwrap());

        // A higher sequence can renew the same session after advertisement expiry.
        let mut renewed = report.clone();
        renewed.report_sequence = 2;
        accept(&state, &owner, renewed.clone()).await.unwrap();
        let withdrawal = SupervisorServiceAdvertisement {
            report_sequence: 3,
            routes: Vec::new(),
            ..renewed.clone()
        };
        accept(&state, &owner, withdrawal).await.unwrap();
        assert!(!cleanup_record(&state, &record(&state).await).await.unwrap());
        assert_eq!(
            accept(&state, &owner, renewed.clone())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );

        // Missing owner evidence alone is also insufficient to discard a fence.
        SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
            .release_if_current(&owner)
            .await
            .unwrap();
        assert!(!cleanup_record(&state, &record(&state).await).await.unwrap());
        assert_eq!(stored(&state).await.report_sequence, 3);
    }

    #[tokio::test]
    async fn cleanup_cannot_delete_a_concurrent_renewal_or_recreated_record() {
        let (state, owner, mut report) = fixture().await;
        accept(&state, &owner, report.clone()).await.unwrap();
        let scanned = record(&state).await;
        report.report_sequence = 2;
        accept(&state, &owner, report.clone()).await.unwrap();
        assert!(!cleanup_record(&state, &scanned).await.unwrap());
        assert_eq!(stored(&state).await.report_sequence, 2);

        let owners = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
        let replacement = owners
            .publish(
                "sandbox-a-id",
                "session-b",
                "runtime-a",
                2,
                &state.replica_id,
                "local://test",
            )
            .await
            .unwrap();
        register(&state, "session-b");
        assert!(cleanup_record(&state, &record(&state).await).await.unwrap());
        assert!(
            state
                .store
                .get(OBJECT_TYPE, &scanned.id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            accept(&state, &owner, report.clone())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );

        // Deletion resets the resource version, so an old page can see version 1
        // again. Its old payload must never authorize deletion of session B.
        report.report_sequence = 1;
        accept(&state, &replacement, report).await.unwrap();
        assert_eq!(
            record(&state).await.resource_version,
            scanned.resource_version
        );
        assert!(!cleanup_record(&state, &scanned).await.unwrap());
        assert_eq!(stored(&state).await.session_id, "session-b");
    }

    #[tokio::test]
    async fn cleanup_pages_remove_deleted_sandboxes_without_offset_skips() {
        let (state, owner, report) = fixture().await;
        accept(&state, &owner, report).await.unwrap();
        let template = stored(&state).await;
        let historical_count = CLEANUP_PAGE_SIZE * 2 + 3;
        for index in 0..historical_count {
            let sandbox_id = format!("deleted-{index:04}");
            let historical = Advertisement {
                sandbox_id: sandbox_id.clone(),
                ..template.clone()
            };
            state
                .store
                .put_if(
                    OBJECT_TYPE,
                    &format!("service-advertisement:{sandbox_id}"),
                    &sandbox_id,
                    "default",
                    &serde_json::to_vec(&historical).unwrap(),
                    None,
                    WriteCondition::MustCreate,
                )
                .await
                .unwrap();
        }
        let mut after = cleanup_page(&state, None).await.unwrap();
        assert!(after.is_some());
        assert_eq!(
            state
                .store
                .list(OBJECT_TYPE, "default", 1000, 0)
                .await
                .unwrap()
                .len(),
            historical_count as usize + 1 - CLEANUP_PAGE_SIZE as usize + 1
        );
        while let Some(cursor) = after {
            after = cleanup_page(&state, Some(&cursor)).await.unwrap();
        }
        assert_eq!(
            state
                .store
                .list(OBJECT_TYPE, "default", 1000, 0)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(stored(&state).await.session_id, owner.session_id);
    }

    #[tokio::test]
    async fn cleanup_worker_stops_with_gateway_shutdown() {
        let (state, _, _) = fixture().await;
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let worker = spawn_cleanup_worker(state, receiver);
        tokio::task::yield_now().await;
        shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("cleanup must not wait for its next interval on shutdown")
            .unwrap();
    }
    #[test]
    fn advertisement_config_requires_trusted_complete_address() {
        let mut config = ServiceRoutingConfig {
            supervisor_app_address_template: Some("https://user@host:443/path".into()),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
        config.supervisor_app_service_domain = Some("svc.openshell.internal".into());
        assert!(validate_config(&config).is_err());
        config.supervisor_app_address_template =
            Some("app-{sandbox_id}.{workspace}.svc:443".into());
        validate_config(&config).unwrap();
    }
}
