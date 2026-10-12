// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Expiring app route installation evidence, fenced by supervisor session ownership.
//! Like the supervisor-owner index, these private JSON records are ephemeral and
//! fail closed after restart, ownership replacement, declaration changes, or expiry.

use crate::ServerState;
use crate::persistence::WriteCondition;
use crate::supervisor_owner::{OWNER_TTL, OwnerGuard, SupervisorOwnerIndex};
use openshell_core::config::ServiceRoutingConfig;
use openshell_core::proto::{Sandbox, SandboxPhase, SupervisorServiceAdvertisement};
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;
use tonic::Status;

pub(super) const OBJECT_TYPE: &str = "supervisor_service_advertisement";
const MAX_ROUTES: usize = 1024;
const LEASE_MS: i64 = 30_000;
const SANDBOX_PLACEHOLDER: &str = "{sandbox}";

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

pub fn validate_config(config: &ServiceRoutingConfig) -> Result<(), String> {
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
    let _guard = state
        .compute
        .sandbox_sync_guard()
        .await
        .map_err(|_| Status::internal("service advertisement mutation lock failed"))?;
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
