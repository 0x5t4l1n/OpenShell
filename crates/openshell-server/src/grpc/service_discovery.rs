// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workspace-scoped, read-only views of unexpired supervisor app advertisements.

use super::service_advertisement::{Advertisement, OBJECT_TYPE};
use crate::ServerState;
use crate::auth::principal::Principal;
use crate::auth::workspace_authz::{
    MinWorkspaceRole, authorize_workspace, selected_workspace_name,
};
use crate::persistence::ObjectCursor;
use crate::supervisor_owner::{OWNER_TTL, SupervisorOwnerIndex};
use openshell_core::proto::{
    DiscoveredServiceRoute, GetServiceRouteSnapshotRequest, GetServiceRouteSnapshotResponse,
    Sandbox, SandboxPhase, ServiceEndpoint, ServiceRouteSnapshot, WatchServiceRoutesRequest,
    WatchServiceRoutesResponse,
};
use openshell_core::{GetResourceVersion, ObjectId, ObjectName, ObjectWorkspace};
use prost::Message as _;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

const MAX_ADVERTISEMENTS: usize = 1000;
const PAGE_SIZE: u32 = 128;
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DISCOVERED_ROUTES: usize = 4096;
const SANDBOX_KEY: &str = "{sandbox}";
const WORKSPACE_KEY: &str = "{workspace}";
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const WATCH_LIFETIME: Duration = Duration::from_mins(1);
pub(super) type RouteWatchStream = ReceiverStream<Result<WatchServiceRoutesResponse, Status>>;

async fn authorize(
    state: &ServerState,
    principal: &Principal,
    workspace: &str,
) -> Result<(), Status> {
    if !matches!(principal, Principal::User(_) | Principal::Operator(_)) {
        return Err(Status::permission_denied(
            "service discovery requires a user/API principal",
        ));
    }
    authorize_workspace(
        &state.store,
        &state.admin_role,
        principal,
        workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    super::workspace::resolve_workspace(state.store.as_ref(), workspace)
        .await?
        .ensure_active()?;
    Ok(())
}

pub(super) async fn get_snapshot(
    state: &Arc<ServerState>,
    request: Request<GetServiceRouteSnapshotRequest>,
) -> Result<Response<GetServiceRouteSnapshotResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let workspace = selected_workspace_name(request.get_ref().workspace_scope.as_ref())?;
    authorize(state, &principal, workspace).await?;
    Ok(Response::new(GetServiceRouteSnapshotResponse {
        snapshot: Some(snapshot(state, workspace).await?),
    }))
}

pub(super) async fn watch_routes(
    state: &Arc<ServerState>,
    request: Request<WatchServiceRoutesRequest>,
) -> Result<Response<RouteWatchStream>, Status> {
    let principal = super::extract_principal(&request)?;
    let workspace =
        selected_workspace_name(request.get_ref().workspace_scope.as_ref())?.to_string();
    authorize(state, &principal, &workspace).await?;
    let initial = snapshot(state, &workspace).await?;
    let mut revision = initial.revision.clone();
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(Ok(WatchServiceRoutesResponse {
        snapshot: Some(initial),
    }))
    .await
    .map_err(|_| Status::cancelled("discovery client closed"))?;
    let state = state.clone();
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + WATCH_LIFETIME;
        let mut interval = tokio::time::interval(POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            tokio::select! {
                () = tx.closed() => return,
                () = tokio::time::sleep_until(deadline) => return,
                _ = interval.tick() => {},
            }
            // Recheck membership on every refresh; reconnect also reauthenticates bearer credentials.
            let refresh = async {
                authorize(&state, &principal, &workspace).await?;
                snapshot(&state, &workspace).await
            };
            let result = tokio::select! {
                () = tx.closed() => return,
                () = tokio::time::sleep_until(deadline) => return,
                result = refresh => result,
            };
            let next = match result {
                Ok(next) => next,
                Err(error) => {
                    tokio::select! {
                        () = tx.closed() => {},
                        () = tokio::time::sleep_until(deadline) => {},
                        _ = tx.send(Err(error)) => {},
                    }
                    return;
                }
            };
            if revision != next.revision {
                revision.clone_from(&next.revision);
                tokio::select! {
                    () = tx.closed() => return,
                    () = tokio::time::sleep_until(deadline) => return,
                    _ = tx.send(Ok(WatchServiceRoutesResponse { snapshot: Some(next) })) => {},
                }
            }
        }
    });
    Ok(Response::new(ReceiverStream::new(rx)))
}

pub(super) async fn snapshot(
    state: &Arc<ServerState>,
    workspace: &str,
) -> Result<ServiceRouteSnapshot, Status> {
    tokio::time::timeout(
        SNAPSHOT_TIMEOUT,
        collect_snapshot(state, workspace, MAX_ADVERTISEMENTS, MAX_DISCOVERED_ROUTES),
    )
    .await
    .map_err(|_| Status::unavailable("service discovery snapshot timed out"))?
}

async fn collect_snapshot(
    state: &Arc<ServerState>,
    workspace: &str,
    max_advertisements: usize,
    max_routes: usize,
) -> Result<ServiceRouteSnapshot, Status> {
    let config = &state.config.service_routing;
    let mut routes = Vec::new();
    if let (Some(template), Some(domain)) = (
        &config.supervisor_app_address_template,
        &config.supervisor_app_service_domain,
    ) {
        let owners = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
        let mut after = None;
        let mut eligible_advertisements = 0;
        loop {
            let records = state
                .store
                .list_after(OBJECT_TYPE, workspace, after.as_ref(), PAGE_SIZE)
                .await
                .map_err(|_| Status::unavailable("service advertisements unavailable"))?;
            let final_page = records.len() < PAGE_SIZE as usize;
            after = records.last().map(ObjectCursor::from);
            for record in records {
                let advertisement: Advertisement = serde_json::from_slice(&record.payload)
                    .map_err(|_| Status::internal("invalid stored service advertisement"))?;
                let now = openshell_core::time::now_ms();
                if advertisement.routes.is_empty()
                    || advertisement.expires_at_ms <= now
                    || advertisement.service_domain != *domain
                {
                    continue;
                }
                let Some(owner) = owners
                    .read(&advertisement.sandbox_id)
                    .await
                    .map_err(|_| Status::unavailable("supervisor ownership unavailable"))?
                else {
                    continue;
                };
                if !owner.is_fresh(OWNER_TTL)
                    || owner.session_id != advertisement.session_id
                    || owner.supervisor_instance_id != advertisement.supervisor_instance_id
                    || owner.connection_epoch != advertisement.connection_epoch
                {
                    continue;
                }
                let Some(sandbox) = state
                    .store
                    .get_message::<Sandbox>(&advertisement.sandbox_id)
                    .await
                    .map_err(|_| Status::unavailable("sandbox unavailable"))?
                else {
                    continue;
                };
                if sandbox.object_workspace() != workspace
                    || SandboxPhase::try_from(sandbox.phase()).ok() != Some(SandboxPhase::Ready)
                    || sandbox.status.as_ref().is_none_or(|status| {
                        status.main_process_instance_id != advertisement.supervisor_instance_id
                    })
                {
                    continue;
                }
                let address = template
                    .replace("{sandbox_id}", sandbox.object_id())
                    .replace(SANDBOX_KEY, sandbox.object_name())
                    .replace(WORKSPACE_KEY, workspace);
                if address != advertisement.address {
                    continue;
                }
                let accepted = super::policy::load_sandbox_config(state, &sandbox).await?;
                if !accepted.configuration_admitted {
                    continue;
                }
                let expires = advertisement
                    .expires_at_ms
                    .min(owner.updated_at_ms.saturating_add(45_000));
                let first_route = routes.len();
                for stamp in &advertisement.routes {
                    let Some(endpoint) = state
                        .store
                        .get_message::<ServiceEndpoint>(&stamp.endpoint_id)
                        .await
                        .map_err(|_| Status::unavailable("service declaration unavailable"))?
                    else {
                        continue;
                    };
                    if endpoint.object_workspace() != workspace
                        || endpoint.sandbox_id != advertisement.sandbox_id
                        || endpoint.get_resource_version() != stamp.resource_version
                        || !endpoint.domain
                        || expires <= openshell_core::time::now_ms()
                    {
                        continue;
                    }
                    let service_label = if endpoint.name.is_empty() {
                        String::new()
                    } else {
                        format!("--{}", endpoint.name)
                    };
                    if routes.len() == first_route {
                        eligible_advertisements += 1;
                        if eligible_advertisements > max_advertisements {
                            return Err(Status::resource_exhausted(
                                "too many eligible service advertisements for one snapshot",
                            ));
                        }
                    }
                    routes.push(DiscoveredServiceRoute {
                        workspace: workspace.into(),
                        sandbox: sandbox.object_name().into(),
                        name: endpoint.name.clone(),
                        sandbox_id: advertisement.sandbox_id.clone(),
                        service_id: endpoint.object_id().into(),
                        hostname: format!(
                            "{workspace}--{}{service_label}.{domain}",
                            sandbox.object_name()
                        ),
                        supervisor_instance_id: advertisement.supervisor_instance_id.clone(),
                        supervisor_app_address: address.clone(),
                        service_revision: stamp.resource_version,
                        runtime_generation: advertisement.supervisor_instance_id.clone(),
                        expires_at: openshell_core::time::timestamp_from_millis(expires).ok(),
                        advertisement_revision: record.resource_version,
                    });
                    if routes.len() > max_routes {
                        return Err(Status::resource_exhausted(
                            "too many routes for one snapshot",
                        ));
                    }
                }
            }
            if final_page {
                break;
            }
            // Keep large historical scans cooperative; the outer timeout bounds total work.
            tokio::task::yield_now().await;
        }
    }
    let now = openshell_core::time::now_ms();
    routes.retain(|route| {
        route
            .expires_at
            .as_ref()
            .and_then(|expires| openshell_core::time::timestamp_to_millis(expires).ok())
            .is_some_and(|expiry| expiry > now)
    });
    routes.sort_by(|a, b| a.service_id.cmp(&b.service_id));
    let mut snapshot = ServiceRouteSnapshot {
        routes,
        ..Default::default()
    };
    let mut digest = Sha256::new();
    digest.update(workspace.as_bytes());
    digest.update(snapshot.encode_to_vec());
    snapshot.revision = format!("{:x}", digest.finalize());
    snapshot.observed_at = openshell_core::time::timestamp_from_millis(now).ok();
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::super::service_advertisement::{accept, tests::fixture};
    use super::super::test_support::authed_request;
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};
    use crate::auth::principal::UserPrincipal;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{
        DeleteServiceRequest, ExposeServiceRequest, SupervisorServiceAdvertisement,
        WorkspaceMember, WorkspaceRole,
    };
    use tokio_stream::StreamExt as _;

    fn scope() -> openshell_core::proto::WorkspaceSelector {
        openshell_core::proto::workspace_selector("default")
    }
    async fn expire(state: &ServerState) {
        let record = state
            .store
            .get(OBJECT_TYPE, "service-advertisement:sandbox-a-id")
            .await
            .unwrap()
            .unwrap();
        let mut advertisement: Advertisement = serde_json::from_slice(&record.payload).unwrap();
        advertisement.expires_at_ms = 0;
        state
            .store
            .put_if(
                OBJECT_TYPE,
                &record.id,
                &record.name,
                "default",
                &serde_json::to_vec(&advertisement).unwrap(),
                None,
                crate::persistence::WriteCondition::MatchResourceVersion(record.resource_version),
            )
            .await
            .unwrap();
    }

    async fn stored_advertisement(state: &ServerState) -> Advertisement {
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

    async fn seed_eligible_route(state: &Arc<ServerState>, suffix: &str) {
        let mut advertisement = stored_advertisement(state).await;
        let mut sandbox = state
            .store
            .get_message::<Sandbox>("sandbox-a-id")
            .await
            .unwrap()
            .unwrap();
        let id = format!("sandbox-{suffix}-id");
        let name = format!("sandbox-{suffix}");
        let metadata = sandbox.metadata.as_mut().unwrap();
        metadata.id.clone_from(&id);
        metadata.name.clone_from(&name);
        metadata.resource_version = 0;
        sandbox.status.as_mut().unwrap().main_process_instance_id = format!("runtime-{suffix}");
        state.store.put_message(&sandbox).await.unwrap();

        let mut endpoint = state
            .store
            .get_message::<ServiceEndpoint>(&advertisement.routes[0].endpoint_id)
            .await
            .unwrap()
            .unwrap();
        endpoint.sandbox_id.clone_from(&id);
        endpoint.sandbox.clone_from(&name);
        let metadata = endpoint.metadata.as_mut().unwrap();
        metadata.id = format!("endpoint-{suffix}");
        metadata.name = format!("{name}--web");
        metadata.resource_version = 0;
        state.store.put_message(&endpoint).await.unwrap();

        let owner = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
            .publish(
                &id,
                &format!("session-{suffix}"),
                &format!("runtime-{suffix}"),
                1,
                &state.replica_id,
                "local://test",
            )
            .await
            .unwrap();
        advertisement.sandbox_id.clone_from(&id);
        advertisement.session_id = owner.session_id;
        advertisement.supervisor_instance_id = owner.supervisor_instance_id;
        advertisement.connection_epoch = owner.connection_epoch;
        advertisement.address = format!("app-{id}.default.svc:443");
        advertisement.expires_at_ms = openshell_core::time::now_ms() + 20_000;
        advertisement.routes[0].endpoint_id = format!("endpoint-{suffix}");
        advertisement.routes[0].resource_version = 1;
        state
            .store
            .put_if(
                OBJECT_TYPE,
                &format!("service-advertisement:{id}"),
                &id,
                "default",
                &serde_json::to_vec(&advertisement).unwrap(),
                None,
                crate::persistence::WriteCondition::MustCreate,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn discovery_pages_past_historical_records_to_find_live_services() {
        let (state, owner, report) = fixture().await;
        accept(&state, &owner, report).await.unwrap();
        let template = stored_advertisement(&state).await;
        for index in 0..MAX_ADVERTISEMENTS + 5 {
            let id = format!("historical-{index:04}");
            let mut advertisement = Advertisement {
                sandbox_id: id.clone(),
                ..template.clone()
            };
            match index % 3 {
                0 => advertisement.expires_at_ms = 0,
                1 => advertisement.routes.clear(),
                // Unexpired evidence without an eligible owner also does not count.
                _ => {}
            }
            state
                .store
                .put_if(
                    OBJECT_TYPE,
                    &format!("service-advertisement:{id}"),
                    &id,
                    "default",
                    &serde_json::to_vec(&advertisement).unwrap(),
                    None,
                    crate::persistence::WriteCondition::MustCreate,
                )
                .await
                .unwrap();
        }
        // This live record sorts after the historical pages.
        seed_eligible_route(&state, "later").await;
        let discovered = snapshot(&state, "default").await.unwrap();
        assert_eq!(discovered.routes.len(), 2);
        assert!(
            discovered
                .routes
                .iter()
                .any(|route| route.sandbox == "sandbox-later")
        );
        assert!(
            discovered
                .routes
                .iter()
                .any(|route| route.sandbox == "sandbox-a")
        );
        // Discovery remains read-only; historical cleanup runs separately.
        assert_eq!(
            state
                .store
                .list(OBJECT_TYPE, "default", 2000, 0)
                .await
                .unwrap()
                .len(),
            MAX_ADVERTISEMENTS + 7
        );
    }

    #[tokio::test]
    async fn discovery_still_enforces_eligible_advertisement_and_route_limits() {
        let (state, owner, report) = fixture().await;
        accept(&state, &owner, report).await.unwrap();
        seed_eligible_route(&state, "b").await;
        // Exercise the same collector with small limits to keep the fixture compact.
        assert_eq!(
            collect_snapshot(&state, "default", 1, 2)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(
            collect_snapshot(&state, "default", 2, 1)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(
            collect_snapshot(&state, "default", 2, 2)
                .await
                .unwrap()
                .routes
                .len(),
            2
        );
    }
    #[tokio::test]
    async fn discovery_snapshot_contains_only_current_advertised_declarations() {
        let (state, owner, report) = fixture().await;
        assert!(snapshot(&state, "default").await.unwrap().routes.is_empty());
        accept(&state, &owner, report).await.unwrap();
        let result = get_snapshot(
            &state,
            authed_request(GetServiceRouteSnapshotRequest {
                workspace_scope: Some(scope()),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .snapshot
        .unwrap();
        assert_eq!(result.routes.len(), 1);
        let route = &result.routes[0];
        assert_eq!(
            route.hostname,
            "default--sandbox-a--web.svc.openshell.internal"
        );
        assert_eq!(
            route.supervisor_app_address,
            "app-sandbox-a-id.default.svc:443"
        );
        assert_eq!(route.runtime_generation, "runtime-a");
        assert_eq!(route.workspace, "default");
        assert_eq!(
            snapshot(&state, "default").await.unwrap().revision,
            result.revision
        );
        assert!(
            snapshot(&state, "other-workspace")
                .await
                .unwrap()
                .routes
                .is_empty()
        );
        super::super::service::handle_expose_service(
            &state,
            authed_request(ExposeServiceRequest {
                workspace_scope: Some(scope()),
                sandbox: "sandbox-a".into(),
                name: "web".into(),
                target_port: 9090,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert!(
            snapshot(&state, "default").await.unwrap().routes.is_empty(),
            "old declaration revision cannot be discovered"
        );
    }
    #[tokio::test]
    async fn discovery_withdraws_on_expiry_and_ownership_change() {
        let (state, owner, report) = fixture().await;
        accept(&state, &owner, report.clone()).await.unwrap();
        expire(&state).await;
        assert!(snapshot(&state, "default").await.unwrap().routes.is_empty());
        let mut renewed = report.clone();
        renewed.report_sequence = 2;
        accept(&state, &owner, renewed).await.unwrap();
        assert_eq!(snapshot(&state, "default").await.unwrap().routes.len(), 1);
        let owners = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
        owners.release_if_current(&owner).await.unwrap();
        assert!(snapshot(&state, "default").await.unwrap().routes.is_empty());
        let new = owners
            .publish(
                "sandbox-a-id",
                "different-session",
                "runtime-a",
                2,
                &state.replica_id,
                "local://test",
            )
            .await
            .unwrap();
        assert!(
            snapshot(&state, "default").await.unwrap().routes.is_empty(),
            "fresh replacement cannot inherit advertisements"
        );
        owners.release_if_current(&new).await.unwrap();
        let restored = owners
            .publish(
                "sandbox-a-id",
                "session-a",
                "runtime-a",
                3,
                &state.replica_id,
                "local://test",
            )
            .await
            .unwrap();
        assert!(
            snapshot(&state, "default").await.unwrap().routes.is_empty(),
            "connection epoch fences equal-valued sessions"
        );
        let _ = restored;
    }
    #[tokio::test]
    async fn discovery_requires_explicit_workspace_and_membership() {
        let (state, _, _) = fixture().await;
        assert_eq!(
            get_snapshot(
                &state,
                authed_request(GetServiceRouteSnapshotRequest::default())
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::InvalidArgument
        );
        let mut request = Request::new(GetServiceRouteSnapshotRequest {
            workspace_scope: Some(scope()),
        });
        request.extensions_mut().insert(Principal::Anonymous);
        assert_eq!(
            get_snapshot(&state, request).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        let mut request = Request::new(GetServiceRouteSnapshotRequest {
            workspace_scope: Some(scope()),
        });
        request.extensions_mut().insert(router());
        assert_eq!(
            get_snapshot(&state, request).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
    }
    fn router() -> Principal {
        Principal::User(UserPrincipal {
            identity: Identity {
                subject: "router".into(),
                display_name: None,
                roles: Vec::new(),
                scopes: vec!["sandbox:read".into()],
                provider: IdentityProvider::Oidc,
            },
        })
    }
    #[tokio::test]
    async fn discovery_watch_sends_initial_snapshot_and_declaration_withdrawal() {
        let (state, owner, report) = fixture().await;
        accept(&state, &owner, report).await.unwrap();
        let mut stream = watch_routes(
            &state,
            authed_request(WatchServiceRoutesRequest {
                workspace_scope: Some(scope()),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let initial = stream.next().await.unwrap().unwrap().snapshot.unwrap();
        assert_eq!(initial.routes.len(), 1);
        super::super::service::handle_delete_service(
            &state,
            authed_request(DeleteServiceRequest {
                workspace_scope: Some(scope()),
                sandbox: "sandbox-a".into(),
                name: "web".into(),
                allow_missing: false,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let next = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .snapshot
            .unwrap();
        assert!(next.routes.is_empty());
        assert_ne!(next.revision, initial.revision);
        let restarted = watch_routes(
            &state,
            authed_request(WatchServiceRoutesRequest {
                workspace_scope: Some(scope()),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .next()
        .await
        .unwrap()
        .unwrap()
        .snapshot
        .unwrap();
        assert_eq!(restarted.revision, next.revision);
    }
    #[tokio::test]
    async fn discovery_watch_revokes_workspace_membership() {
        let (state, owner, report) = fixture().await;
        accept(&state, &owner, report).await.unwrap();
        let member = WorkspaceMember {
            metadata: Some(ObjectMeta {
                id: "router-member".into(),
                name: "router".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            principal_subject: "router".into(),
            role: WorkspaceRole::User as i32,
        };
        state.store.put_message(&member).await.unwrap();
        let mut request = Request::new(WatchServiceRoutesRequest {
            workspace_scope: Some(scope()),
        });
        request.extensions_mut().insert(router());
        let mut stream = watch_routes(&state, request).await.unwrap().into_inner();
        assert_eq!(
            stream
                .next()
                .await
                .unwrap()
                .unwrap()
                .snapshot
                .unwrap()
                .routes
                .len(),
            1
        );
        state
            .store
            .delete("workspace_member", "router-member")
            .await
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }
    #[tokio::test]
    async fn discovery_does_not_require_a_local_supervisor_session() {
        let (state, owner, report) = fixture().await;
        accept(&state, &owner, report).await.unwrap();
        // A reader on another gateway has only the shared owner record, not a local session.
        state.supervisor_sessions.disconnect("sandbox-a-id");
        assert_eq!(snapshot(&state, "default").await.unwrap().routes.len(), 1);
    }
    #[tokio::test]
    async fn discovery_watch_has_bounded_lifetime() {
        let (state, _, _) = fixture().await;
        let mut stream = watch_routes(
            &state,
            authed_request(WatchServiceRoutesRequest {
                workspace_scope: Some(scope()),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        stream.next().await.unwrap().unwrap();
        // Initialize SQLite and deliver the initial snapshot with real time;
        // auto-advancing a paused clock can exhaust the database pool deadline.
        tokio::time::pause();
        tokio::task::yield_now().await;
        tokio::time::advance(WATCH_LIFETIME + Duration::from_millis(1)).await;
        assert!(stream.next().await.is_none());
    }
    #[test]
    fn discovery_rpc_metadata_requires_authenticated_read_scope() {
        for method in ["GetServiceRouteSnapshot", "WatchServiceRoutes"] {
            let path = format!("/openshell.v1.OpenShell/{method}");
            let entry = crate::auth::method_authz::lookup(&path).unwrap();
            assert_eq!(entry.auth_mode, crate::auth::method_authz::AuthMode::Bearer);
            assert_eq!(entry.scope.as_deref(), Some("sandbox:read"));
            assert_eq!(entry.workspace_role.as_deref(), Some("user"));
        }
    }
    #[tokio::test]
    async fn discovery_snapshot_and_watch_work_over_grpc() {
        use openshell_core::proto::open_shell_client::OpenShellClient;
        use openshell_core::proto::open_shell_server::OpenShellServer;
        let (state, owner, report) = fixture().await;
        accept(&state, &owner, report).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let principal = super::super::extract_principal(&authed_request(())).unwrap();
        let service = OpenShellServer::with_interceptor(
            super::super::OpenShellService::new(state.clone()),
            move |mut request: Request<()>| {
                request.extensions_mut().insert(principal.clone());
                Ok(request)
            },
        );
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = stopped.await;
                    },
                ),
        );
        let mut client = OpenShellClient::connect(format!("http://{address}"))
            .await
            .unwrap();
        let initial = client
            .get_service_route_snapshot(GetServiceRouteSnapshotRequest {
                workspace_scope: Some(scope()),
            })
            .await
            .unwrap()
            .into_inner()
            .snapshot
            .unwrap();
        assert_eq!(initial.routes.len(), 1);
        let mut stream = client
            .watch_service_routes(WatchServiceRoutesRequest {
                workspace_scope: Some(scope()),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            stream
                .message()
                .await
                .unwrap()
                .unwrap()
                .snapshot
                .unwrap()
                .revision,
            initial.revision
        );
        accept(
            &state,
            &owner,
            SupervisorServiceAdvertisement {
                report_sequence: 2,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let withdrawn = tokio::time::timeout(Duration::from_secs(3), stream.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .snapshot
            .unwrap();
        assert!(withdrawn.routes.is_empty());
        drop(stream);
        drop(client);
        shutdown.send(()).unwrap();
        task.await.unwrap().unwrap();
    }
}
