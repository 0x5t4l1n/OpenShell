// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Delegated sandbox identities from a real SPIRE agent.
//!
//! `mise run test:spire-delegation` starts a pinned SPIRE server and agent,
//! registers this test process as an authorized delegate and the sandbox
//! entries named below, and runs this test. Gateway session JWTs are signed
//! with real Ed25519 keys. The gateway confirmation RPC and the token
//! service are local fakes: the gateway accepts only the generation it was
//! told is current, and the token service records each client assertion and
//! answers with a token that names its subject.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::StreamBody;
use hyper::body::Frame;
use openshell_core::grpc_client::{GatewayCredentials, GatewayEndpoint};
use openshell_core::jwt::{
    CredentialEpoch, SandboxId, SandboxRuntimeIdentity, SecretJwt, SessionJwtIssuer,
    SessionJwtVerifier, SessionRotation, SessionTokenProfile, SessionVerificationKey,
    SupervisorAuthBundle, SystemJwtClock,
};
use openshell_core::proto::ProviderCredentialTokenGrantType;
use openshell_core::sandbox_generation::SandboxGenerationId;
use openshell_core::spiffe::SandboxSpiffeIdPrefix;
use openshell_core::token_grant_failure::{TokenGrantFailureKind, TokenGrantStage};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::DelegatedIdentityConfig;
use crate::token_grant::{ObtainProviderTokenRequest, ProviderIdentitySource, SessionTokenGrants};

const AUDIENCE: &str = "https://sts.openshell.test";
const KEY_ID: &str = "gateway-key";
const PROVIDER_KEY: &str = "api.example.test\t443\t/v1/**\trev:1\tprovider:access_token";

/// Environment the harness script provides.
struct Spire {
    admin_socket: std::path::PathBuf,
    prefix: SandboxSpiffeIdPrefix,
    gateway_id: String,
    sandbox: HashMap<&'static str, String>,
}

fn spire() -> Spire {
    let var = |name: &str| {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} is set by test:spire-delegation"))
    };
    Spire {
        admin_socket: var("OPENSHELL_TEST_SPIRE_ADMIN_SOCKET").into(),
        prefix: SandboxSpiffeIdPrefix::parse(&var("OPENSHELL_TEST_SPIRE_ID_PREFIX")).unwrap(),
        gateway_id: var("OPENSHELL_TEST_SPIRE_GATEWAY_ID"),
        sandbox: [
            "ALPHA",
            "BETA",
            "UNREGISTERED",
            "MISREGISTERED",
            "AMBIGUOUS",
        ]
        .into_iter()
        .map(|name| (name, var(&format!("OPENSHELL_TEST_SPIRE_SANDBOX_{name}"))))
        .collect(),
    }
}

/// Gateway signing keys and the matching verification material.
struct Keys {
    issuer: SessionJwtIssuer,
    verification: Vec<SessionVerificationKey>,
}

fn gateway_keys(gateway_id: &str) -> Keys {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    Keys {
        issuer: SessionJwtIssuer::from_ed25519_pem(
            key.serialize_pem().as_bytes(),
            KEY_ID,
            gateway_id,
            Some(Duration::from_hours(1)),
            Arc::new(SystemJwtClock),
        )
        .unwrap(),
        verification: vec![SessionVerificationKey {
            key_id: KEY_ID.to_string(),
            public_key_pem: key.public_key_pem().into_bytes(),
        }],
    }
}

fn identity(sandbox_id: &str, generation: &str) -> SandboxRuntimeIdentity {
    SandboxRuntimeIdentity {
        sandbox_id: SandboxId::parse(sandbox_id).unwrap(),
        runtime_generation: SandboxGenerationId::parse(generation).unwrap(),
        auth_epoch: CredentialEpoch::new(1).unwrap(),
    }
}

type GrpcBody =
    StreamBody<futures::stream::Iter<std::vec::IntoIter<Result<Frame<Bytes>, Infallible>>>>;

/// Gateway confirmation RPC that accepts only the current generation.
#[derive(Clone)]
struct Gateway {
    url: String,
    current: Arc<Mutex<HashMap<String, String>>>,
    confirmations: Arc<AtomicUsize>,
}

impl Gateway {
    async fn start(verification: Vec<SessionVerificationKey>, gateway_id: &str) -> Self {
        let verifier = Arc::new(
            SessionJwtVerifier::new(
                gateway_id,
                SessionTokenProfile::Gateway,
                verification,
                Arc::new(SystemJwtClock),
            )
            .unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway = Self {
            url: format!("http://{}", listener.local_addr().unwrap()),
            current: Arc::default(),
            confirmations: Arc::default(),
        };
        let state = gateway.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (state, verifier) = (state.clone(), verifier.clone());
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |request| {
                        let (state, verifier) = (state.clone(), verifier.clone());
                        async move { Ok::<_, Infallible>(state.answer(&verifier, &request)) }
                    });
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
                });
            }
        });
        gateway
    }

    fn set_current(&self, sandbox_id: &str, generation: &str) {
        self.current
            .lock()
            .unwrap()
            .insert(sandbox_id.to_string(), generation.to_string());
    }

    fn confirmations(&self) -> usize {
        self.confirmations.load(Ordering::SeqCst)
    }

    fn answer(
        &self,
        verifier: &SessionJwtVerifier,
        request: &http::Request<hyper::body::Incoming>,
    ) -> http::Response<GrpcBody> {
        let accepted = request.uri().path() == "/openshell.v1.OpenShell/GetSandboxConfig"
            && request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .and_then(|token| verifier.verify(token).ok())
                .is_some_and(|session| {
                    self.current
                        .lock()
                        .unwrap()
                        .get(session.sandbox_id.as_str())
                        .is_some_and(|current| current == session.runtime_generation.as_str())
                });
        self.confirmations.fetch_add(1, Ordering::SeqCst);
        let mut trailers = http::HeaderMap::new();
        let frames = if accepted {
            trailers.insert("grpc-status", "0".parse().unwrap());
            // One empty GetSandboxConfigResponse.
            vec![
                Ok(Frame::data(Bytes::from_static(&[0, 0, 0, 0, 0]))),
                Ok(Frame::trailers(trailers)),
            ]
        } else {
            trailers.insert("grpc-status", "16".parse().unwrap());
            vec![Ok(Frame::trailers(trailers))]
        };
        http::Response::builder()
            .header("content-type", "application/grpc")
            .body(StreamBody::new(futures::stream::iter(frames)))
            .unwrap()
    }
}

/// RFC 7523 token service that answers `tok-<sandbox-id>-<n>` for an
/// assertion whose subject ends in that sandbox ID.
#[derive(Clone, Default)]
struct TokenService {
    url: String,
    assertions: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl TokenService {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let service = Self {
            url: format!("http://{}/token", listener.local_addr().unwrap()),
            assertions: Arc::default(),
        };
        let assertions = service.assertions.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let assertions = assertions.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0_u8; 4096];
                    let body = loop {
                        let read = stream.read(&mut chunk).await.unwrap();
                        assert!(read > 0, "token request ended early");
                        request.extend_from_slice(&chunk[..read]);
                        let text = String::from_utf8_lossy(&request);
                        if let Some((head, body)) = text.split_once("\r\n\r\n") {
                            let length = head
                                .lines()
                                .find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().ok())?
                                })
                                .unwrap_or(0);
                            if body.len() >= length {
                                break body.to_string();
                            }
                        }
                    };
                    let assertion = body
                        .split('&')
                        .find_map(|pair| pair.strip_prefix("client_assertion="))
                        .expect("client assertion");
                    // Observation only: the supervisor already verified it.
                    let claims: serde_json::Value = serde_json::from_slice(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(assertion.split('.').nth(1).unwrap())
                            .unwrap(),
                    )
                    .unwrap();
                    let sandbox = claims["sub"]
                        .as_str()
                        .and_then(|sub| sub.rsplit('/').next())
                        .unwrap()
                        .to_string();
                    let ordinal = {
                        let mut assertions = assertions.lock().unwrap();
                        assertions.push(claims);
                        assertions.len()
                    };
                    let body = format!(
                        r#"{{"access_token":"tok-{sandbox}-{ordinal}","token_type":"Bearer","expires_in":300}}"#
                    );
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        service
    }

    fn subjects(&self) -> Vec<String> {
        self.assertions
            .lock()
            .unwrap()
            .iter()
            .map(|claims| {
                assert_eq!(claims["aud"], serde_json::json!([AUDIENCE]));
                claims["sub"].as_str().unwrap().to_string()
            })
            .collect()
    }
}

struct Session {
    grants: SessionTokenGrants,
    credentials: GatewayCredentials,
}

struct Fixture {
    spire: Spire,
    keys: Keys,
    gateway: Gateway,
    tokens: TokenService,
}

impl Fixture {
    /// A session registered for `registered`, presenting `gateway_token`.
    fn session_with_token(
        &self,
        registered: &SandboxRuntimeIdentity,
        gateway_token: &str,
    ) -> Session {
        let sandbox_token = self.keys.issuer.mint_pair(registered).unwrap().sandbox;
        let bundle = SupervisorAuthBundle {
            session_id: uuid::Uuid::new_v4().to_string().parse().unwrap(),
            runtime_generation: registered.runtime_generation.clone(),
            session_rotation: SessionRotation::new(1).unwrap(),
            auth_epoch: registered.auth_epoch,
            gateway_token: SecretJwt::parse(gateway_token).unwrap(),
            gateway_expires_at: 0,
            sandbox_token: sandbox_token.token,
            sandbox_expires_at: sandbox_token.expires_at,
            ssh_host_private_key: None,
            ocsf_otlp_headers: None,
        };
        let credentials = GatewayCredentials::from_auth_bundle(&bundle).unwrap();
        let config = DelegatedIdentityConfig {
            admin_socket: self.spire.admin_socket.clone(),
            spiffe_id_prefix: self.spire.prefix.clone(),
            gateway_id: self.spire.gateway_id.clone(),
            gateway_verifier: SessionJwtVerifier::new(
                &self.spire.gateway_id,
                SessionTokenProfile::Gateway,
                self.keys.verification.clone(),
                Arc::new(SystemJwtClock),
            )
            .unwrap(),
            sandbox_id: registered.sandbox_id.clone(),
            runtime_generation: registered.runtime_generation.clone(),
            auth_epoch: registered.auth_epoch,
        };
        Session {
            grants: SessionTokenGrants::new(
                Some(GatewayEndpoint::new(
                    self.gateway.url.as_str(),
                    credentials.clone(),
                )),
                Some(registered.sandbox_id.to_string()),
                Some(format!("name-{}", registered.sandbox_id)),
                ProviderIdentitySource::Delegated(config),
            ),
            credentials,
        }
    }

    /// A session whose gateway JWT matches its registration.
    fn session(&self, registered: &SandboxRuntimeIdentity) -> Session {
        let token = self
            .keys
            .issuer
            .mint_pair(registered)
            .unwrap()
            .gateway
            .token;
        self.session_with_token(registered, token.expose_secret())
    }

    fn expected_id(&self, sandbox_id: &str) -> String {
        self.spire
            .prefix
            .sandbox_spiffe_id(&self.spire.gateway_id, sandbox_id)
            .unwrap()
    }
}

async fn obtain(
    session: &Session,
    token_endpoint: &str,
    cached: bool,
) -> Result<String, openshell_core::token_grant_failure::TokenGrantFailure> {
    session
        .grants
        .obtain_provider_token(ObtainProviderTokenRequest {
            provider_name: PROVIDER_KEY,
            token_endpoint,
            jwt_svid_audience: AUDIENCE,
            client_assertion_type: "",
            audience: "api://resource",
            scopes: &[],
            cache_ttl_override: (!cached).then_some(Duration::ZERO),
            grant_type: ProviderCredentialTokenGrantType::ClientCredentials as i32,
            requested_token_type: "",
            request_id: "4f1c2b3a-9d8e-4c7b-a6f5-e4d3c2b1a098",
        })
        .await
}

fn rejected_locally(
    result: Result<String, openshell_core::token_grant_failure::TokenGrantFailure>,
) -> bool {
    result.is_err_and(|failure| {
        failure.kind() == TokenGrantFailureKind::WorkloadIdentityRejected
            && failure.stage() == TokenGrantStage::WorkloadIdentity
    })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a SPIRE server and agent; run `mise run test:spire-delegation`"]
async fn spire_delegates_each_sandbox_only_its_own_stable_identity() {
    let spire = spire();
    let keys = gateway_keys(&spire.gateway_id);
    let gateway = Gateway::start(keys.verification.clone(), &spire.gateway_id).await;
    let tokens = TokenService::start().await;
    let fixture = Fixture {
        spire,
        keys,
        gateway,
        tokens,
    };
    let sandbox = |name: &str| fixture.spire.sandbox[name].clone();
    let endpoint = fixture.tokens.url.clone();

    // Two sandboxes on one supervisor obtain their own identities and tokens.
    let alpha_1 = identity(&sandbox("ALPHA"), "generation-1");
    let beta = identity(&sandbox("BETA"), "generation-1");
    for registered in [&alpha_1, &beta] {
        fixture
            .gateway
            .set_current(registered.sandbox_id.as_str(), "generation-1");
    }
    let alpha = fixture.session(&alpha_1);
    let beta = fixture.session(&beta);
    // The agent picks up new registration entries on its next sync.
    let alpha_token = tokio::time::timeout(Duration::from_mins(1), async {
        loop {
            if let Ok(token) = obtain(&alpha, &endpoint, true).await {
                return token;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("SPIRE delegates the registered sandbox identity");
    let beta_token = obtain(&beta, &endpoint, true).await.unwrap();
    assert_eq!(alpha_token, format!("tok-{}-1", sandbox("ALPHA")));
    assert_eq!(beta_token, format!("tok-{}-2", sandbox("BETA")));
    assert_eq!(
        fixture.tokens.subjects(),
        [
            fixture.expected_id(&sandbox("ALPHA")),
            fixture.expected_id(&sandbox("BETA"))
        ]
    );
    // Each session's cache serves only its own token.
    assert_eq!(obtain(&alpha, &endpoint, true).await.unwrap(), alpha_token);
    assert_eq!(obtain(&beta, &endpoint, true).await.unwrap(), beta_token);
    assert_eq!(fixture.tokens.subjects().len(), 2);

    // A restarted sandbox keeps its SPIFFE ID; its old generation cannot
    // acquire a new one once the gateway moves on.
    let alpha_2 = identity(&sandbox("ALPHA"), "generation-2");
    fixture
        .gateway
        .set_current(alpha_2.sandbox_id.as_str(), "generation-2");
    let restarted = fixture.session(&alpha_2);
    let restarted_token = obtain(&restarted, &endpoint, true).await.unwrap();
    assert_eq!(restarted_token, format!("tok-{}-3", sandbox("ALPHA")));
    assert_eq!(
        fixture.tokens.subjects()[2],
        fixture.expected_id(&sandbox("ALPHA"))
    );
    let stale = obtain(&alpha, &endpoint, false).await.unwrap_err();
    assert_eq!(
        stale.kind(),
        TokenGrantFailureKind::WorkloadIdentityRejected
    );
    assert_eq!(stale.stage(), TokenGrantStage::GatewayRpc);
    assert_eq!(fixture.tokens.subjects().len(), 3);

    // A removed session neither reuses its cached token nor acquires another.
    restarted.credentials.revoke();
    assert!(rejected_locally(obtain(&restarted, &endpoint, true).await));
    assert!(rejected_locally(obtain(&restarted, &endpoint, false).await));
    assert_eq!(fixture.tokens.subjects().len(), 3);

    // A JWT that is not the gateway's current, exact credential for the
    // registered sandbox cannot select any identity, and is refused before
    // the gateway or SPIRE is asked.
    let alpha_3 = identity(&sandbox("ALPHA"), "generation-3");
    fixture
        .gateway
        .set_current(alpha_3.sandbox_id.as_str(), "generation-3");
    let genuine = fixture.keys.issuer.mint_pair(&alpha_3).unwrap();
    let tampered = {
        let token = genuine.gateway.token.expose_secret();
        let (signed, signature) = token.rsplit_once('.').unwrap();
        let mut signature = signature.to_string();
        let replaced = if signature.starts_with('A') { "B" } else { "A" };
        signature.replace_range(..1, replaced);
        format!("{signed}.{signature}")
    };
    let foreign_key = gateway_keys(&fixture.spire.gateway_id)
        .issuer
        .mint_pair(&alpha_3)
        .unwrap()
        .gateway
        .token;
    let other_gateway = gateway_keys("other-gateway")
        .issuer
        .mint_pair(&alpha_3)
        .unwrap()
        .gateway
        .token;
    let other_sandbox = fixture
        .keys
        .issuer
        .mint_pair(&identity(&sandbox("BETA"), "generation-3"))
        .unwrap()
        .gateway
        .token;
    let other_generation = fixture
        .keys
        .issuer
        .mint_pair(&alpha_1)
        .unwrap()
        .gateway
        .token;
    let confirmations = fixture.gateway.confirmations();
    for presented in [
        tampered.as_str(),
        foreign_key.expose_secret(),
        other_gateway.expose_secret(),
        other_sandbox.expose_secret(),
        other_generation.expose_secret(),
        genuine.sandbox.token.expose_secret(),
    ] {
        let session = fixture.session_with_token(&alpha_3, presented);
        assert!(rejected_locally(obtain(&session, &endpoint, false).await));
    }
    assert_eq!(fixture.gateway.confirmations(), confirmations);
    assert_eq!(fixture.tokens.subjects().len(), 3);

    // Registration mistakes fail closed: no entry (a recreated sandbox has a
    // new ID), an entry that names another sandbox's SPIFFE ID, and two
    // entries for one sandbox.
    for name in ["UNREGISTERED", "MISREGISTERED", "AMBIGUOUS"] {
        let registered = identity(&sandbox(name), "generation-1");
        fixture
            .gateway
            .set_current(registered.sandbox_id.as_str(), "generation-1");
        let session = fixture.session(&registered);
        assert!(
            rejected_locally(obtain(&session, &endpoint, false).await),
            "{name} must not obtain an identity"
        );
    }
    assert_eq!(fixture.tokens.subjects().len(), 3);
}
