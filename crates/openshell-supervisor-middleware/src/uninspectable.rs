// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decisions about connections `OpenShell` forwards without inspecting their
//! payload (`tls: skip`, h2c, unsupported tunnels, raw TCP, SQL passthrough).
//!
//! Each selected entry whose service binds `UNINSPECTABLE_NETWORK/PRE_FORWARD`
//! is asked through `UninspectableNetworkMiddleware.Evaluate`, in chain order,
//! and must allow the connection. Any failure denies. Other entries follow
//! their `on_error`: `fail_closed` denies, and `fail_open` lets the connection
//! through with a finding. That `fail_open` exception is deprecated and removed
//! in 0.2.0.

use openshell_core::proto::{
    EvaluateUninspectableNetworkRequest, MiddlewareDiagnostics, RequestContext,
    SupervisorMiddlewareOperation as Operation, SupervisorMiddlewarePhase as Phase,
    UninspectableNetworkDecision, UninspectableTrafficReason,
};
use prost::Message;

use crate::diagnostics::{normalize_diagnostics, validate_diagnostics};
use crate::{
    ChainEntry, ChainRunner, DescribedChainEntry, MAX_MIDDLEWARE_CHAIN_TIMEOUT,
    MAX_MIDDLEWARE_CONFIG_BYTES, MAX_MIDDLEWARE_CONTEXT_BYTES, MAX_MIDDLEWARE_TARGET_BYTES,
    MiddlewareDenial, NamespacedFinding, OnError, middleware_denial_reason,
};

/// A connection `OpenShell` forwards without inspecting its payload.
#[derive(Debug, Clone)]
pub struct UninspectableTrafficInput {
    /// Sandbox and originating process identity. `request_id` identifies the
    /// connection.
    pub context: RequestContext,
    pub host: String,
    pub port: u16,
    pub reason: UninspectableTrafficReason,
}

/// What one entry decided about an uninspectable connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninspectableInvocationOutcome {
    AllowWithoutInspection,
    /// An entry without the binding that sets `on_error: fail_open`.
    /// Deprecated; removed in 0.2.0.
    LegacyBypass,
    Deny,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninspectableInvocation {
    pub config_name: String,
    pub implementation: String,
    pub outcome: UninspectableInvocationOutcome,
    pub reason_code: Option<String>,
    /// Platform-owned failure reason.
    pub failure_reason: Option<String>,
}

/// Decision about one uninspectable connection.
#[derive(Debug, Clone, Default)]
pub struct UninspectableOutcome {
    pub allowed: bool,
    /// Platform-owned reason for a denial: `middleware_denied:<config>[:<code>]`
    /// for a denial, `middleware_failed: <reason>` otherwise.
    pub reason: String,
    /// Present only when a service denied the connection.
    pub denial: Option<MiddlewareDenial>,
    /// One record per evaluated entry.
    pub invocations: Vec<UninspectableInvocation>,
    pub findings: Vec<NamespacedFinding>,
}

impl UninspectableOutcome {
    fn record(
        &mut self,
        entry: &ChainEntry,
        outcome: UninspectableInvocationOutcome,
        reason_code: Option<String>,
        failure_reason: Option<&str>,
    ) {
        self.invocations.push(UninspectableInvocation {
            config_name: entry.name.clone(),
            implementation: entry.implementation.clone(),
            outcome,
            reason_code,
            failure_reason: failure_reason.map(str::to_string),
        });
    }

    fn fail(mut self, entry: Option<&ChainEntry>, reason: &str) -> Self {
        if let Some(entry) = entry {
            self.record(
                entry,
                UninspectableInvocationOutcome::Failed,
                None,
                Some(reason),
            );
        }
        self.allowed = false;
        self.reason = format!("middleware_failed: {reason}");
        self
    }
}

impl ChainRunner {
    /// Decide whether an uninspectable connection that selects `entries` may
    /// proceed. Entries without the binding are checked first, so a
    /// `fail_closed` one denies before any service is called.
    pub async fn evaluate_uninspectable(
        &self,
        entries: &[ChainEntry],
        input: UninspectableTrafficInput,
    ) -> UninspectableOutcome {
        let mut outcome = UninspectableOutcome {
            allowed: true,
            ..Default::default()
        };
        if entries.is_empty() {
            return outcome;
        }
        let Ok(chain) = self
            .describe_chain_for(entries, Operation::UninspectableNetwork, Phase::PreForward)
            .await
        else {
            return outcome.fail(None, "describe_failed");
        };
        let (bound, undescribed): (Vec<_>, Vec<_>) = chain
            .entries
            .into_iter()
            .partition(|stage| stage.service.is_some());
        for entry in chain
            .unbound
            .iter()
            .chain(undescribed.iter().map(|stage| &stage.entry))
        {
            // Deprecated: the fail_open exception is removed in 0.2.0.
            if entry.on_error == OnError::FailOpen {
                outcome.record(
                    entry,
                    UninspectableInvocationOutcome::LegacyBypass,
                    None,
                    None,
                );
                continue;
            }
            return outcome.fail(Some(entry), "uninspectable_binding_missing");
        }
        let Some(first) = bound.first() else {
            return outcome;
        };
        if input.context.encoded_len() > MAX_MIDDLEWARE_CONTEXT_BYTES
            || input.host.len() > MAX_MIDDLEWARE_TARGET_BYTES
        {
            return outcome.fail(Some(&first.entry), "connection_input_over_capacity");
        }
        let chain_deadline = tokio::time::Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        let Ok(Ok(_admission)) =
            tokio::time::timeout_at(chain_deadline, self.reserve_middleware_work_admission()).await
        else {
            return outcome.fail(Some(&first.entry), "work_capacity_exhausted");
        };
        for stage in &bound {
            let (decision, diagnostics) = match evaluate_stage(stage, &input, chain_deadline).await
            {
                Ok(result) => result,
                Err(reason) => return outcome.fail(Some(&stage.entry), reason),
            };
            let reason_code =
                (!diagnostics.reason_code.is_empty()).then(|| diagnostics.reason_code.clone());
            outcome
                .findings
                .extend(
                    diagnostics
                        .findings
                        .into_iter()
                        .map(|finding| NamespacedFinding {
                            middleware: stage.entry.name.clone(),
                            finding,
                        }),
                );
            if decision == UninspectableNetworkDecision::Deny {
                outcome.record(
                    &stage.entry,
                    UninspectableInvocationOutcome::Deny,
                    reason_code.clone(),
                    None,
                );
                outcome.allowed = false;
                outcome.reason =
                    middleware_denial_reason(&stage.entry.name, reason_code.as_deref());
                outcome.denial = Some(MiddlewareDenial {
                    config_name: stage.entry.name.clone(),
                    reason_code,
                });
                return outcome;
            }
            outcome.record(
                &stage.entry,
                UninspectableInvocationOutcome::AllowWithoutInspection,
                reason_code,
                None,
            );
        }
        outcome
    }
}

/// Call one bound entry. Returns its decision and normalized diagnostics, or a
/// platform failure reason.
async fn evaluate_stage(
    stage: &DescribedChainEntry,
    input: &UninspectableTrafficInput,
    chain_deadline: tokio::time::Instant,
) -> Result<(UninspectableNetworkDecision, MiddlewareDiagnostics), &'static str> {
    let Some(service) = stage.service.as_ref() else {
        return Err("service_not_registered");
    };
    if stage.entry.config.encoded_len() > MAX_MIDDLEWARE_CONFIG_BYTES {
        return Err("config_over_capacity");
    }
    let request = EvaluateUninspectableNetworkRequest {
        middleware_name: stage.entry.implementation.clone(),
        context: Some(input.context.clone()),
        config: Some(stage.entry.config.clone()),
        host: input.host.clone(),
        port: u32::from(input.port),
        reason: input.reason as i32,
    };
    let deadline = chain_deadline.min(tokio::time::Instant::now() + stage.timeout);
    let response = match tokio::time::timeout_at(
        deadline,
        service.service.evaluate_uninspectable_network(request),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => return Err("evaluation_failed"),
        Err(_) => return Err("evaluation_timeout"),
    };
    let mut diagnostics = validate_diagnostics(response.diagnostics.as_ref())?;
    let Ok(
        decision @ (UninspectableNetworkDecision::AllowWithoutInspection
        | UninspectableNetworkDecision::Deny),
    ) = UninspectableNetworkDecision::try_from(response.decision)
    else {
        return Err("invalid_decision");
    };
    normalize_diagnostics(
        &stage.entry.implementation,
        service.diagnostic_policy,
        &mut diagnostics,
    );
    Ok((decision, diagnostics))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HttpRequestView, InProcessMiddleware, MiddlewareRegistry, OnError};
    use openshell_core::extension_protocol::{ExtensionFamily, extension_metadata};
    use openshell_core::proto::{
        EvaluateUninspectableNetworkResponse, HttpRequestResult, MiddlewareBinding,
        MiddlewareManifest,
    };
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    pub(super) struct Service {
        pub(super) name: &'static str,
        operations: Vec<Operation>,
        pub(super) calls: Arc<Mutex<Vec<EvaluateUninspectableNetworkRequest>>>,
        pub(super) result: Result<EvaluateUninspectableNetworkResponse, tonic::Code>,
        delay: Duration,
        callback_timeout: Duration,
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for Service {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: self.name.into(),
                bindings: self
                    .operations
                    .iter()
                    .map(|operation| MiddlewareBinding {
                        operation: *operation as i32,
                        phase: match operation {
                            Operation::HttpResponse => Phase::PreReturn,
                            Operation::UninspectableNetwork => Phase::PreForward,
                            _ => Phase::PreCredentials,
                        } as i32,
                        max_payload_bytes: if *operation == Operation::UninspectableNetwork {
                            0
                        } else {
                            1024
                        },
                        request_timeout: Some(if *operation == Operation::UninspectableNetwork {
                            self.callback_timeout.try_into().unwrap()
                        } else {
                            prost_types::Duration {
                                seconds: 0,
                                nanos: 10_000_000,
                            }
                        }),
                    })
                    .collect(),
                extension: Some(extension_metadata(
                    ExtensionFamily::SupervisorMiddleware,
                    self.name,
                    "test",
                    [],
                )),
                ..Default::default()
            }
        }
        async fn validate_config(
            &self,
            _name: &str,
            _config: &prost_types::Struct,
        ) -> miette::Result<()> {
            Ok(())
        }
        async fn evaluate_http_request(
            &self,
            _request: HttpRequestView<'_>,
        ) -> miette::Result<HttpRequestResult> {
            panic!("connection callback must not use HTTP evaluation")
        }
        async fn evaluate_uninspectable_network(
            &self,
            request: EvaluateUninspectableNetworkRequest,
        ) -> Result<EvaluateUninspectableNetworkResponse, tonic::Status> {
            self.calls.lock().unwrap().push(request.clone());
            tokio::time::sleep(self.delay).await;
            if request
                .config
                .as_ref()
                .is_some_and(|config| config.fields.contains_key("deny"))
            {
                return Ok(response(UninspectableNetworkDecision::Deny));
            }
            self.result
                .clone()
                .map_err(|code| tonic::Status::new(code, "DO_NOT_LOG_SERVICE_SECRET"))
        }
    }

    pub(super) fn response(
        decision: UninspectableNetworkDecision,
    ) -> EvaluateUninspectableNetworkResponse {
        EvaluateUninspectableNetworkResponse {
            decision: decision as i32,
            diagnostics: None,
        }
    }

    /// A service that binds `operations` and the uninspectable hook.
    pub(super) fn test_service(name: &'static str, operations: Vec<Operation>) -> Arc<Service> {
        Arc::new(Service {
            name,
            operations: operations
                .into_iter()
                .chain([Operation::UninspectableNetwork])
                .collect(),
            calls: Arc::default(),
            result: Ok(response(
                UninspectableNetworkDecision::AllowWithoutInspection,
            )),
            delay: Duration::ZERO,
            callback_timeout: Duration::from_millis(500),
        })
    }

    /// A service that binds `operations` but not the uninspectable hook.
    fn legacy_service(name: &'static str, operations: Vec<Operation>) -> Arc<Service> {
        let mut service = test_service(name, operations);
        Arc::get_mut(&mut service)
            .unwrap()
            .operations
            .retain(|op| *op != Operation::UninspectableNetwork);
        service
    }

    pub(super) fn entry(name: &str, implementation: &str, order: i32) -> ChainEntry {
        ChainEntry {
            name: name.into(),
            implementation: implementation.into(),
            order,
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        }
    }

    pub(super) fn input() -> UninspectableTrafficInput {
        UninspectableTrafficInput {
            context: RequestContext {
                request_id: "connection-1".into(),
                sandbox_id: "sandbox-1".into(),
                ..Default::default()
            },
            host: "example.test".into(),
            port: 443,
            reason: UninspectableTrafficReason::TlsSkip,
        }
    }

    async fn test_runner(services: Vec<Arc<dyn InProcessMiddleware>>) -> ChainRunner {
        ChainRunner::from_registry(
            MiddlewareRegistry::connect_services(services, vec![])
                .await
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn bound_services_are_called_whatever_their_other_bindings() {
        for operations in [
            vec![],
            vec![Operation::HttpRequest],
            vec![Operation::HttpResponse, Operation::WebsocketMessage],
        ] {
            let service = test_service("test/guard", operations);
            let runner = test_runner(vec![service.clone()]).await;
            let outcome = runner
                .evaluate_uninspectable(&[entry("guard", service.name, 0)], input())
                .await;
            assert!(outcome.allowed, "{}", outcome.reason);
            let calls = service.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].middleware_name, "test/guard");
            assert_eq!(calls[0].reason, UninspectableTrafficReason::TlsSkip as i32);
            assert_eq!(
                calls[0].context.as_ref().unwrap().request_id,
                "connection-1"
            );
        }
    }

    #[tokio::test]
    async fn every_entry_must_allow_in_order_with_its_own_configuration() {
        let service = test_service("test/guard", vec![]);
        let runner = test_runner(vec![service.clone()]).await;
        let mut deny = entry("second", service.name, 1);
        deny.config
            .fields
            .insert("deny".into(), prost_types::Value::default());
        let outcome = runner
            .evaluate_uninspectable(
                &[
                    entry("third", service.name, 2),
                    deny,
                    entry("first", service.name, 0),
                ],
                input(),
            )
            .await;
        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "middleware_denied:second");
        assert_eq!(outcome.denial.unwrap().config_name, "second");
        assert_eq!(
            outcome
                .invocations
                .iter()
                .map(|i| i.outcome)
                .collect::<Vec<_>>(),
            [
                UninspectableInvocationOutcome::AllowWithoutInspection,
                UninspectableInvocationOutcome::Deny
            ]
        );
        let calls = service.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].config.as_ref().unwrap().fields.is_empty());
        assert!(
            calls[1]
                .config
                .as_ref()
                .unwrap()
                .fields
                .contains_key("deny")
        );
    }

    #[tokio::test]
    async fn failures_and_invalid_decisions_deny_even_when_fail_open() {
        let mut cases = vec![
            Ok(EvaluateUninspectableNetworkResponse::default()),
            Ok(EvaluateUninspectableNetworkResponse {
                decision: 999,
                ..Default::default()
            }),
            Ok(EvaluateUninspectableNetworkResponse {
                diagnostics: Some(MiddlewareDiagnostics {
                    reason_code: "INVALID SECRET".into(),
                    ..Default::default()
                }),
                ..response(UninspectableNetworkDecision::AllowWithoutInspection)
            }),
        ];
        for code in [
            tonic::Code::Unimplemented,
            tonic::Code::Unavailable,
            tonic::Code::DeadlineExceeded,
        ] {
            cases.push(Err(code));
        }
        for result in cases {
            let mut service = test_service("test/guard", vec![]);
            Arc::get_mut(&mut service).unwrap().result = result;
            let runner = test_runner(vec![service.clone()]).await;
            let outcome = runner
                .evaluate_uninspectable(&[entry("guard", service.name, 0)], input())
                .await;
            assert!(!outcome.allowed);
            assert_eq!(
                outcome.invocations[0].outcome,
                UninspectableInvocationOutcome::Failed
            );
            assert!(outcome.denial.is_none());
            assert!(!format!("{outcome:?}").contains("SECRET"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn callback_uses_its_own_binding_timeout() {
        let mut service = test_service("test/guard", vec![Operation::HttpResponse]);
        let state = Arc::get_mut(&mut service).unwrap();
        state.delay = Duration::from_millis(20);
        state.callback_timeout = Duration::from_millis(10);
        let runner = test_runner(vec![service.clone()]).await;
        let outcome = runner
            .evaluate_uninspectable(&[entry("guard", service.name, 0)], input())
            .await;
        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "middleware_failed: evaluation_timeout");
    }

    #[tokio::test]
    async fn entries_without_the_binding_follow_on_error_without_a_call() {
        let service = legacy_service("test/legacy", vec![Operation::HttpResponse]);
        let runner = test_runner(vec![service.clone()]).await;
        for on_error in [OnError::FailOpen, OnError::FailClosed] {
            let mut selected = entry("legacy", service.name, 0);
            selected.on_error = on_error;
            let outcome = runner.evaluate_uninspectable(&[selected], input()).await;
            assert_eq!(outcome.allowed, on_error == OnError::FailOpen);
            assert_eq!(
                outcome.invocations[0].outcome,
                if on_error == OnError::FailOpen {
                    UninspectableInvocationOutcome::LegacyBypass
                } else {
                    UninspectableInvocationOutcome::Failed
                }
            );
        }
        assert!(service.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_allow_cannot_override_another_entry() {
        let callback = test_service("test/callback", vec![]);
        let legacy = legacy_service("test/legacy", vec![Operation::HttpRequest]);
        let runner = test_runner(vec![callback.clone(), legacy.clone()]).await;

        // A fail_closed entry without the binding denies before any call.
        let mut closed = entry("legacy", legacy.name, 0);
        closed.on_error = OnError::FailClosed;
        let outcome = runner
            .evaluate_uninspectable(&[closed, entry("callback", callback.name, 1)], input())
            .await;
        assert!(!outcome.allowed);
        assert!(callback.calls.lock().unwrap().is_empty());

        // A fail_open entry without the binding does not override a denial.
        let mut deny = entry("callback", callback.name, 1);
        deny.config
            .fields
            .insert("deny".into(), prost_types::Value::default());
        let outcome = runner
            .evaluate_uninspectable(&[entry("legacy", legacy.name, 0), deny], input())
            .await;
        assert!(!outcome.allowed);
        assert_eq!(outcome.denial.unwrap().config_name, "callback");
        assert!(legacy.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn hook_only_service_does_not_join_inspected_payload_chains() {
        let service = test_service("test/connection-only", vec![]);
        let runner = test_runner(vec![service.clone()]).await;
        let entries = [entry("guard", service.name, 0)];
        assert!(runner.describe_chain(&entries).await.unwrap().is_empty());
        assert!(
            runner
                .describe_http_response_chain(&entries)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            runner
                .describe_websocket_chain(&entries)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(service.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn capacity_exhaustion_refuses_without_calling_service() {
        let service = test_service("test/guard", vec![]);
        let runner = test_runner(vec![service.clone()]).await;
        let _work = runner
            .registry
            .work_admission
            .clone()
            .acquire_many_owned(u32::try_from(crate::MAX_CONCURRENT_MIDDLEWARE_WORK).unwrap())
            .await
            .unwrap();
        let _waiters = runner
            .registry
            .work_admission_waiters
            .clone()
            .acquire_many_owned(u32::try_from(crate::MAX_QUEUED_MIDDLEWARE_WORK).unwrap())
            .await
            .unwrap();
        let outcome = runner
            .evaluate_uninspectable(&[entry("guard", service.name, 0)], input())
            .await;
        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "middleware_failed: work_capacity_exhausted");
        assert!(service.calls.lock().unwrap().is_empty());
    }
}

#[cfg(test)]
mod transport_tests {
    use super::tests::{Service, entry, input, test_service};
    use super::*;
    use crate::{InProcessMiddleware, MiddlewareRegistry, WebSocketResponseStream};
    use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
        SupervisorMiddleware, SupervisorMiddlewareServer,
    };
    use openshell_core::proto::middleware::v1::uninspectable_network_middleware_server::{
        UninspectableNetworkMiddleware, UninspectableNetworkMiddlewareServer,
    };
    use openshell_core::proto::{
        EvaluateUninspectableNetworkResponse, Finding, HttpRequestEvaluation, HttpRequestResult,
        MiddlewareDescribeRequest, MiddlewareManifest, SupervisorMiddlewareService,
        ValidateConfigRequest, ValidateConfigResponse, WebSocketSessionEvent,
    };
    use std::sync::Arc;
    use tonic::{Request, Response, Status};

    #[derive(Clone)]
    struct Remote(Arc<Service>);

    #[tonic::async_trait]
    impl SupervisorMiddleware for Remote {
        type EvaluateWebSocketSessionStream = WebSocketResponseStream;
        async fn describe(
            &self,
            _request: Request<MiddlewareDescribeRequest>,
        ) -> Result<Response<MiddlewareManifest>, Status> {
            Ok(Response::new(
                InProcessMiddleware::describe(self.0.as_ref()).await,
            ))
        }
        async fn validate_config(
            &self,
            _request: Request<ValidateConfigRequest>,
        ) -> Result<Response<ValidateConfigResponse>, Status> {
            Ok(Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }
        async fn evaluate_http_request(
            &self,
            _request: Request<HttpRequestEvaluation>,
        ) -> Result<Response<HttpRequestResult>, Status> {
            panic!("unexpected HTTP hook")
        }
        async fn evaluate_web_socket_session(
            &self,
            _request: Request<tonic::Streaming<WebSocketSessionEvent>>,
        ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
            Err(Status::unimplemented("not used"))
        }
    }

    #[tonic::async_trait]
    impl UninspectableNetworkMiddleware for Remote {
        async fn evaluate(
            &self,
            request: Request<EvaluateUninspectableNetworkRequest>,
        ) -> Result<Response<EvaluateUninspectableNetworkResponse>, Status> {
            InProcessMiddleware::evaluate_uninspectable_network(
                self.0.as_ref(),
                request.into_inner(),
            )
            .await
            .map(Response::new)
        }
    }

    /// The remote client calls `UninspectableNetworkMiddleware` on the
    /// registration's endpoint, and a service that does not serve it denies.
    #[tokio::test]
    async fn remote_registration_uses_the_dedicated_service() {
        for serve_hook in [true, false] {
            let mut service = test_service("test/guard", vec![]);
            Arc::get_mut(&mut service).unwrap().result = Ok(EvaluateUninspectableNetworkResponse {
                decision: UninspectableNetworkDecision::AllowWithoutInspection as i32,
                diagnostics: Some(MiddlewareDiagnostics {
                    reason: "DO_NOT_LOG_SERVICE_SECRET".into(),
                    findings: vec![Finding {
                        r#type: "DO_NOT_LOG_SERVICE_SECRET".into(),
                        label: "DO_NOT_LOG_SERVICE_SECRET".into(),
                        count: 1,
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            });
            let remote = Remote(service.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let mut router = tonic::transport::Server::builder()
                .add_service(SupervisorMiddlewareServer::new(remote.clone()));
            if serve_hook {
                router = router.add_service(UninspectableNetworkMiddlewareServer::new(remote));
            }
            let server = tokio::spawn(
                router
                    .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
            );
            let registry = MiddlewareRegistry::connect_services(
                vec![],
                vec![SupervisorMiddlewareService {
                    name: "operator-registration".into(),
                    grpc_endpoint: endpoint,
                    allow_insecure_transport: true,
                    ..Default::default()
                }],
            )
            .await
            .unwrap();
            let outcome = ChainRunner::from_registry(registry)
                .evaluate_uninspectable(&[entry("guard", "operator-registration", 0)], input())
                .await;
            assert_eq!(outcome.allowed, serve_hook, "{}", outcome.reason);
            assert!(!format!("{outcome:?}").contains("DO_NOT_LOG_SERVICE_SECRET"));
            if serve_hook {
                assert_eq!(
                    outcome.findings[0].finding.r#type,
                    "operator-registration.finding"
                );
                let calls = service.calls.lock().unwrap();
                assert_eq!(calls[0].middleware_name, "operator-registration");
            }
            server.abort();
        }
    }
}
