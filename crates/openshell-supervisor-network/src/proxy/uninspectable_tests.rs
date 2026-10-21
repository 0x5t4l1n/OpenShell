// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::middleware::{HttpRequestView, InProcessMiddleware};
use openshell_core::proto::{
    EvaluateUninspectableNetworkRequest, EvaluateUninspectableNetworkResponse, HttpRequestResult,
    MiddlewareBinding, MiddlewareManifest, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, UninspectableNetworkDecision, UninspectableNetworkReason,
};
use openshell_supervisor_middleware::ChainRunner;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::Notify;

const POLICY: &str = include_str!("../../data/sandbox-policy.rego");
const DATA: &str = r"
network_middlewares:
  guard:
    middleware: test/connection-guard
    on_error: fail_open
    endpoints:
      include: [example.test]
network_policies:
  sql:
    name: sql
    endpoints:
      - host: example.test
        port: 5432
        protocol: sql
        enforcement: audit
        rules:
          - allow: {command: SELECT}
    binaries:
      - {path: /usr/bin/psql}
";

struct ConnectionGuard {
    calls: Mutex<Vec<EvaluateUninspectableNetworkRequest>>,
    entered: Notify,
    release: Notify,
    wait: bool,
    decision: UninspectableNetworkDecision,
}

#[tonic::async_trait]
impl InProcessMiddleware for ConnectionGuard {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: "test/connection-guard".into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::UninspectableNetwork as i32,
                phase: SupervisorMiddlewarePhase::PreForward as i32,
                ..Default::default()
            }],
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                "test/connection-guard",
                "test",
                [],
            )),
            ..Default::default()
        }
    }
    async fn validate_config(&self, _name: &str, _config: &prost_types::Struct) -> Result<()> {
        Ok(())
    }
    async fn evaluate_http_request(
        &self,
        _request: HttpRequestView<'_>,
    ) -> Result<HttpRequestResult> {
        panic!("unexpected HTTP hook")
    }
    async fn evaluate_uninspectable_network(
        &self,
        request: EvaluateUninspectableNetworkRequest,
    ) -> std::result::Result<EvaluateUninspectableNetworkResponse, tonic::Status> {
        self.calls.lock().unwrap().push(request);
        self.entered.notify_one();
        if self.wait {
            self.release.notified().await;
        }
        Ok(EvaluateUninspectableNetworkResponse {
            decision: self.decision as i32,
            diagnostics: None,
        })
    }
}

fn fixture(
    wait: bool,
) -> (
    Arc<OpaEngine>,
    Arc<ConnectionGuard>,
    crate::l7::relay::L7EvalContext,
) {
    let engine = Arc::new(OpaEngine::from_strings(POLICY, DATA).unwrap());
    let service = Arc::new(ConnectionGuard {
        calls: Mutex::default(),
        entered: Notify::new(),
        release: Notify::new(),
        wait,
        decision: UninspectableNetworkDecision::AllowWithoutInspection,
    });
    engine.set_middleware_runner_for_tests(ChainRunner::new(service.clone()));
    let ctx = crate::l7::relay::L7EvalContext {
        host: "example.test".into(),
        port: 5432,
        request_default_port: Some(5432),
        policy_name: "sql".into(),
        binary_path: "/usr/bin/psql".into(),
        ..Default::default()
    };
    (engine, service, ctx)
}

#[tokio::test]
async fn connection_routes_supply_reason_and_process_context() {
    let (engine, service, ctx) = fixture(false);
    for reason in [
        UninspectableNetworkReason::TlsSkip,
        UninspectableNetworkReason::RawTcp,
        UninspectableNetworkReason::H2c,
        UninspectableNetworkReason::UnsupportedTunnel,
    ] {
        let result = middleware_uninspectable_gate(&engine, &ctx, reason)
            .await
            .unwrap();
        assert_eq!(
            result,
            crate::l7::middleware::UninspectableTrafficGate::Allowed
        );
        let calls = service.calls.lock().unwrap();
        let call = calls.last().unwrap();
        assert_eq!(call.reason, reason as i32);
        let identity = call.context.as_ref().unwrap();
        assert!(!identity.request_id.is_empty());
        assert_eq!(
            identity.originating_process.as_ref().unwrap().binary,
            "/usr/bin/psql"
        );
        assert_eq!(identity.originating_process.as_ref().unwrap().pid, 0);
    }
}

#[tokio::test]
async fn sql_passthrough_waits_for_approval() {
    let (engine, service, ctx) = fixture(true);
    let input = crate::l7::middleware::middleware_network_input(&ctx);
    let (endpoint, generation) = engine
        .query_endpoint_config_with_generation(&input)
        .unwrap();
    let config = crate::l7::parse_l7_config(&endpoint.unwrap()).unwrap();
    let tunnel = engine.clone_engine_for_tunnel(generation).unwrap();
    let (mut app, mut client) = tokio::io::duplex(1024);
    let (mut upstream, mut peer) = tokio::io::duplex(1024);
    let relay = tokio::spawn(async move {
        crate::l7::relay::relay_with_inspection(&config, tunnel, &mut client, &mut upstream, &ctx)
            .await
    });
    app.write_all(b"SQL application bytes").await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), service.entered.notified())
        .await
        .unwrap();
    let mut bytes = [0; 21];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), peer.read(&mut bytes))
            .await
            .is_err()
    );
    {
        let calls = service.calls.lock().unwrap();
        assert_eq!(
            calls[0].reason,
            UninspectableNetworkReason::SqlPassthrough as i32
        );
    }
    service.release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), peer.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"SQL application bytes");
    drop(app);
    drop(peer);
    relay.await.unwrap().unwrap();
}

pub(super) fn denying_runner() -> ChainRunner {
    ChainRunner::new(denying_service())
}

pub(super) fn denying_service() -> Arc<dyn InProcessMiddleware> {
    Arc::new(ConnectionGuard {
        calls: Mutex::default(),
        entered: Notify::new(),
        release: Notify::new(),
        wait: false,
        decision: UninspectableNetworkDecision::Deny,
    })
}

#[tokio::test]
async fn inspected_http_does_not_invoke_connection_only_hook() {
    let (engine, service, ctx) = fixture(false);
    let data = DATA
        .replace("protocol: sql", "protocol: rest")
        .replace("{command: SELECT}", "{method: GET, path: '/**'}");
    engine.reload(POLICY, &data).unwrap();
    let input = crate::l7::middleware::middleware_network_input(&ctx);
    let (endpoint, generation) = engine
        .query_endpoint_config_with_generation(&input)
        .unwrap();
    let config = crate::l7::parse_l7_config(&endpoint.unwrap()).unwrap();
    let tunnel = engine.clone_engine_for_tunnel(generation).unwrap();
    let (mut app, mut client) = tokio::io::duplex(1024);
    let (mut upstream, mut peer) = tokio::io::duplex(1024);
    let relay = tokio::spawn(async move {
        crate::l7::relay::relay_with_inspection(&config, tunnel, &mut client, &mut upstream, &ctx)
            .await
    });
    let request = b"GET /ok HTTP/1.1\r\nHost: example.test:5432\r\nConnection: close\r\n\r\n";
    app.write_all(request).await.unwrap();
    let mut forwarded = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !forwarded.ends_with(b"\r\n\r\n") {
            forwarded.push(peer.read_u8().await.unwrap());
            assert!(forwarded.len() < 4096);
        }
    })
    .await
    .unwrap();
    assert!(forwarded.starts_with(b"GET /ok HTTP/1.1\r\n"));
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    peer.write_all(response).await.unwrap();
    peer.shutdown().await.unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), app.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert!(received.ends_with(b"ok"));
    relay.await.unwrap().unwrap();
    assert!(service.calls.lock().unwrap().is_empty());
}
