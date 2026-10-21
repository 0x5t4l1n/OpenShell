// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::proto::SandboxPolicy;
use openshell_supervisor_middleware::MiddlewareRegistry;
use tonic::Status;

/// Validate implementation-owned middleware config, and the HTTP hook version
/// rules, before accepting a policy.
pub async fn validate_policy(
    registry: &MiddlewareRegistry,
    policy: &SandboxPolicy,
) -> Result<(), Status> {
    async {
        registry.validate_policy_configs(policy).await?;
        registry.validate_http_hook_rules(policy).await
    }
    .await
    .map_err(|error| {
        Status::invalid_argument(format!("policy middleware validation failed: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::extension_protocol::{
        ExtensionFamily, extension_metadata, http_session_middleware_metadata,
    };
    use openshell_core::proto::{
        HttpRequestResult, MiddlewareBinding, MiddlewareEndpointSelector, MiddlewareManifest,
        NetworkMiddlewareConfig, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
    };
    use openshell_supervisor_middleware::{HttpRequestView, InProcessMiddleware};
    use std::sync::Arc;

    struct TestMiddleware {
        name: &'static str,
        operations: &'static [SupervisorMiddlewareOperation],
        websocket: bool,
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for TestMiddleware {
        async fn describe(&self) -> MiddlewareManifest {
            let mut bindings: Vec<_> = self
                .operations
                .iter()
                .map(|operation| MiddlewareBinding {
                    operation: *operation as i32,
                    phase: match operation {
                        SupervisorMiddlewareOperation::HttpResponse => {
                            SupervisorMiddlewarePhase::PreReturn
                        }
                        SupervisorMiddlewareOperation::UninspectableNetwork => {
                            SupervisorMiddlewarePhase::PreForward
                        }
                        _ => SupervisorMiddlewarePhase::PreCredentials,
                    } as i32,
                    max_payload_bytes: if *operation
                        == SupervisorMiddlewareOperation::UninspectableNetwork
                    {
                        0
                    } else {
                        1024
                    },
                    ..Default::default()
                })
                .collect();
            if self.websocket {
                bindings.push(MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::WebsocketMessage as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: 1024,
                    ..Default::default()
                });
            }
            MiddlewareManifest {
                name: self.name.into(),
                bindings,
                extension: Some(
                    if self.operations == [SupervisorMiddlewareOperation::UninspectableNetwork] {
                        extension_metadata(
                            ExtensionFamily::SupervisorMiddleware,
                            self.name,
                            "test",
                            [],
                        )
                    } else {
                        http_session_middleware_metadata(self.name, "test")
                    },
                ),
                ..Default::default()
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> miette::Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            _request: HttpRequestView<'_>,
        ) -> miette::Result<HttpRequestResult> {
            Err(miette::miette!("HTTP session hook test middleware"))
        }
    }

    async fn registry() -> MiddlewareRegistry {
        let mut services = openshell_supervisor_middleware_builtins::services();
        services.push(Arc::new(TestMiddleware {
            name: "example/guard",
            operations: &[
                SupervisorMiddlewareOperation::HttpRequest,
                SupervisorMiddlewareOperation::HttpResponse,
            ],
            websocket: false,
        }));
        services.push(Arc::new(TestMiddleware {
            name: "example/guard-with-websocket",
            operations: &[SupervisorMiddlewareOperation::HttpRequest],
            websocket: true,
        }));
        services.push(Arc::new(TestMiddleware {
            name: "example/response-guard",
            operations: &[SupervisorMiddlewareOperation::HttpResponse],
            websocket: false,
        }));
        services.push(Arc::new(TestMiddleware {
            name: "example/connection-guard",
            operations: &[SupervisorMiddlewareOperation::UninspectableNetwork],
            websocket: false,
        }));
        MiddlewareRegistry::connect_services(services, Vec::new())
            .await
            .expect("registry")
    }

    fn entry(
        middleware: &str,
        order: i32,
        include: &str,
        on_error: &str,
    ) -> NetworkMiddlewareConfig {
        NetworkMiddlewareConfig {
            middleware: middleware.into(),
            order,
            on_error: on_error.into(),
            endpoints: Some(MiddlewareEndpointSelector {
                include: vec![include.into()],
                exclude: Vec::new(),
            }),
            ..Default::default()
        }
    }

    fn policy(entries: Vec<(&str, NetworkMiddlewareConfig)>) -> SandboxPolicy {
        SandboxPolicy {
            network_middlewares: entries
                .into_iter()
                .map(|(name, entry)| (name.to_string(), entry))
                .collect(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn fail_open_is_rejected_on_http_session_hook_middleware() {
        let registry = registry().await;
        for middleware in ["example/guard", "example/guard-with-websocket"] {
            let error = validate_policy(
                &registry,
                &policy(vec![(
                    "guard",
                    entry(middleware, 0, "api.example.com", "fail_open"),
                )]),
            )
            .await
            .expect_err("HTTP session hook middleware is always fail-closed");
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
            assert!(
                error.message().contains("cannot use on_error: fail_open"),
                "{}",
                error.message()
            );
        }
        validate_policy(
            &registry,
            &policy(vec![(
                "redactor",
                entry(
                    openshell_supervisor_middleware_builtins::BUILTIN_REGEX,
                    0,
                    "api.example.com",
                    "fail_open",
                ),
            )]),
        )
        .await
        .expect("v1 HTTP hook middleware keeps fail_open");
    }

    #[tokio::test]
    async fn overlapping_selectors_must_use_one_http_protocol_per_operation() {
        let registry = registry().await;
        let regex = openshell_supervisor_middleware_builtins::BUILTIN_REGEX;
        let error = validate_policy(
            &registry,
            &policy(vec![
                ("redactor", entry(regex, 0, "*.example.com", "")),
                ("guard", entry("example/guard", 1, "api.example.com", "")),
            ]),
        )
        .await
        .expect_err("one HTTP request cannot run both hook versions");
        assert!(
            error
                .message()
                .contains("separate their endpoint selectors"),
            "{}",
            error.message()
        );

        // Disjoint selectors never select the same message.
        validate_policy(
            &registry,
            &policy(vec![
                ("redactor", entry(regex, 0, "legacy.example.com", "")),
                ("guard", entry("example/guard", 1, "api.example.com", "")),
            ]),
        )
        .await
        .expect("disjoint selectors may use different hook versions");

        // The regex middleware has no response binding, so a response-only
        // HTTP session hook service may share its selector.
        validate_policy(
            &registry,
            &policy(vec![
                ("redactor", entry(regex, 0, "api.example.com", "")),
                (
                    "guard",
                    entry("example/response-guard", 1, "api.example.com", ""),
                ),
            ]),
        )
        .await
        .expect("no HTTP operation is served by both hook versions");
    }

    #[tokio::test]
    async fn unregistered_external_middleware_is_rejected_before_admission() {
        let policy = SandboxPolicy {
            network_middlewares: std::collections::HashMap::from([(
                "guard".into(),
                NetworkMiddlewareConfig {
                    middleware: "example/content-guard".into(),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let error = validate_policy(&MiddlewareRegistry::default(), &policy)
            .await
            .expect_err("unregistered middleware must fail");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("not registered"));
    }

    #[tokio::test]
    async fn tls_skip_rule_exempts_middleware_that_binds_uninspectable_network() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule, NetworkTlsMode};
        let registry = registry().await;
        let legacy = openshell_supervisor_middleware_builtins::BUILTIN_REGEX;
        for (implementation, on_error, accepted) in [
            (legacy, "fail_open", true),
            (legacy, "fail_closed", false),
            (legacy, "", false),
            ("example/connection-guard", "fail_closed", true),
            ("example/guard", "", false),
            ("example/response-guard", "", false),
        ] {
            let mut policy = policy(vec![(
                "guard",
                entry(implementation, 0, "*.example.com", on_error),
            )]);
            policy.network_policies.insert(
                "tls".into(),
                NetworkPolicyRule {
                    name: "tls".into(),
                    endpoints: vec![NetworkEndpoint {
                        host: "api.example.com".into(),
                        port: 443,
                        tls: NetworkTlsMode::Skip as i32,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            );
            let conflicts =
                openshell_policy::middleware_tls_skip_conflicts(&policy, |middleware| {
                    registry.decides_uninspectable_traffic(middleware)
                });
            assert_eq!(
                conflicts.is_empty(),
                accepted,
                "{implementation}/{on_error}: {conflicts:?}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_builtin_config_is_rejected_by_implementation() {
        let registry = MiddlewareRegistry::connect_services(
            openshell_supervisor_middleware_builtins::services(),
            Vec::new(),
        )
        .await
        .expect("built-in registry");
        let policy = SandboxPolicy {
            network_middlewares: std::collections::HashMap::from([(
                "redactor".into(),
                NetworkMiddlewareConfig {
                    middleware: openshell_supervisor_middleware_builtins::BUILTIN_REGEX.into(),
                    config: Some(prost_types::Struct {
                        fields: std::iter::once((
                            "mode".into(),
                            prost_types::Value {
                                kind: Some(prost_types::value::Kind::StringValue("allow".into())),
                            },
                        ))
                        .collect(),
                    }),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let error = validate_policy(&registry, &policy)
            .await
            .expect_err("invalid built-in config must fail admission");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("supports only mode: redact"));
    }
}
