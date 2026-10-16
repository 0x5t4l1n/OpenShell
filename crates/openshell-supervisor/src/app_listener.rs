// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in application ingress, separate from the gateway control transport.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::body::Body;
use http::{Request, Response, StatusCode, header};
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use miette::{IntoDiagnostic, Result};
use openshell_core::grpc_client::SettingsPollResult;
use openshell_core::proto::{SandboxServiceRoute, SupervisorServiceAdvertisement};
use openshell_isolation_interface::contract::LoopbackTarget;
use openshell_ocsf::{
    ActionId, ActivityId, AppLifecycleBuilder, ConfigStateChangeBuilder, DispositionId,
    NetworkActivityBuilder, SeverityId, StatusId, ocsf_emit,
};
use openshell_sandbox_backend::BoundaryLoopbackConnector;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

const FRESHNESS: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Config {
    address: SocketAddr,
    domain: String,
    certificate: PathBuf,
    key: PathBuf,
}

impl Config {
    pub(crate) fn from_env() -> Result<Option<Self>> {
        let address = std::env::var("OPENSHELL_APP_LISTEN_ADDRESS").ok();
        let domain = std::env::var("OPENSHELL_APP_SERVICE_DOMAIN").ok();
        let certificate = std::env::var("OPENSHELL_APP_TLS_CERT").ok();
        let key = std::env::var("OPENSHELL_APP_TLS_KEY").ok();
        if address.is_none() && domain.is_none() && certificate.is_none() && key.is_none() {
            return Ok(None);
        }
        let (Some(address), Some(domain), Some(certificate), Some(key)) =
            (address, domain, certificate, key)
        else {
            return Err(miette::miette!(
                "app listener requires address, domain, certificate, and key"
            ));
        };
        let domain = domain.to_ascii_lowercase();
        if domain.len() > 253 || !domain.split('.').all(valid_label) {
            return Err(miette::miette!("invalid app service domain"));
        }
        let address: SocketAddr = address.parse().into_diagnostic()?;
        if address.port() == 0 {
            return Err(miette::miette!("app listener port must be nonzero"));
        }
        Ok(Some(Self {
            address,
            domain,
            certificate: certificate.into(),
            key: key.into(),
        }))
    }

    pub(crate) async fn bind(self) -> Result<BoundListener> {
        let certificates = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(self.certificate).into_diagnostic()?,
        ))
        .collect::<std::io::Result<Vec<_>>>()
        .into_diagnostic()?;
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(self.key).into_diagnostic()?,
        ))
        .into_diagnostic()?
        .ok_or_else(|| miette::miette!("app TLS private key missing"))?;
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .into_diagnostic()?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let listener = tokio::net::TcpListener::bind(self.address)
            .await
            .into_diagnostic()?;
        Ok(BoundListener {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            domain: self.domain,
        })
    }
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[derive(Clone, Default)]
struct Snapshot {
    routes: BTreeMap<String, SandboxServiceRoute>,
    generations: BTreeMap<String, u64>,
    next_generation: u64,
    expires: Option<Instant>,
    // Whole-sandbox suspension fence, independent of individual service edits.
    epoch: u64,
}

#[derive(Clone, Copy)]
struct RouteToken {
    epoch: u64,
    generation: u64,
}

/// Shared by policy reconciliation and ingress. Only accepted configuration
/// refreshes this lease; route changes cannot restart or replace the workload.
#[derive(Clone)]
pub struct Routes {
    sender: watch::Sender<Snapshot>,
    stopped: Arc<AtomicBool>,
}

impl Default for Routes {
    fn default() -> Self {
        Self {
            sender: watch::channel(Snapshot::default()).0,
            stopped: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Routes {
    #[cfg(test)]
    pub(crate) fn route_count(&self) -> usize {
        self.sender.borrow().routes.len()
    }
    pub(crate) fn install(&self, result: &SettingsPollResult) {
        if self.stopped.load(Ordering::Acquire) {
            return;
        }
        let mut routes = BTreeMap::new();
        if result.configuration_admitted
            && valid_label(&result.workspace)
            && !result.workspace.contains("--")
        {
            for route in &result.service_routes {
                if route.endpoint_id.is_empty()
                    || route.target_port == 0
                    || route.target_port > 65535
                    || !matches!(route.authorization_mode, 0..=2)
                    || (!route.name.is_empty()
                        && (!valid_label(&route.name) || route.name.contains("--")))
                {
                    self.suspend();
                    return;
                }
                if routes.insert(route.name.clone(), route.clone()).is_some() {
                    self.suspend();
                    return;
                }
            }
        }
        let changed = self.sender.borrow().routes != routes;
        self.sender.send_modify(|snapshot| {
            // Renewal after a lapse cannot revive a connection whose lease expired.
            if snapshot
                .expires
                .is_some_and(|expiry| expiry <= Instant::now())
            {
                snapshot.epoch = snapshot.epoch.wrapping_add(1);
            }
            let generations = routes
                .iter()
                .map(|(name, route)| {
                    let previous = (snapshot.routes.get(name) == Some(route))
                        .then(|| snapshot.generations.get(name).copied())
                        .flatten();
                    let generation = previous.unwrap_or_else(|| {
                        snapshot.next_generation = snapshot
                            .next_generation
                            .checked_add(1)
                            .expect("app route generation exhausted");
                        snapshot.next_generation
                    });
                    (name.clone(), generation)
                })
                .collect();
            snapshot.routes = routes;
            snapshot.generations = generations;
            snapshot.expires = Some(Instant::now() + FRESHNESS);
        });
        if changed {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .message("App listener service routes updated")
                    .build()
            );
        }
    }

    pub(crate) fn suspend(&self) {
        self.sender.send_modify(|snapshot| {
            snapshot.routes.clear();
            snapshot.generations.clear();
            snapshot.expires = None;
            snapshot.epoch = snapshot.epoch.wrapping_add(1);
        });
    }

    fn resolve(
        &self,
        sni: &str,
        prefix: &str,
        domain: &str,
    ) -> Option<(SandboxServiceRoute, RouteToken)> {
        let encoded = sni.strip_suffix(&format!(".{domain}"))?;
        let service = if encoded == prefix {
            ""
        } else {
            encoded.strip_prefix(&format!("{prefix}--"))?
        };
        let snapshot = self.sender.borrow();
        if snapshot.expires? <= Instant::now() {
            return None;
        }
        Some((
            snapshot.routes.get(service)?.clone(),
            RouteToken {
                epoch: snapshot.epoch,
                generation: *snapshot.generations.get(service)?,
            },
        ))
    }

    async fn revoked(&self, route: &SandboxServiceRoute, token: RouteToken) {
        let mut receiver = self.sender.subscribe();
        loop {
            let expiry = {
                let snapshot = receiver.borrow_and_update();
                if snapshot.epoch != token.epoch
                    || snapshot.generations.get(&route.name) != Some(&token.generation)
                    || snapshot.routes.get(&route.name) != Some(route)
                {
                    return;
                }
                let Some(expiry) = snapshot.expires else {
                    return;
                };
                expiry
            };
            tokio::select! {
                () = tokio::time::sleep_until(expiry) => return,
                result = receiver.changed() => if result.is_err() { return; },
            }
        }
    }
}

pub struct BoundListener {
    listener: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
    domain: String,
}

pub struct Handle {
    task: tokio::task::JoinHandle<()>,
    routes: Routes,
    advertisement_task: tokio::task::JoinHandle<()>,
    advertisements: watch::Sender<Option<SupervisorServiceAdvertisement>>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.routes.stopped.store(true, Ordering::Release);
        self.routes.suspend();
        self.advertisements
            .send_replace(Some(SupervisorServiceAdvertisement::default()));
        self.advertisement_task.abort();
        self.task.abort();
    }
}

impl BoundListener {
    pub(crate) fn start(
        self,
        routes: Routes,
        sandbox: String,
        workspace: watch::Receiver<String>,
        connector: Arc<BoundaryLoopbackConnector>,
        advertisements: watch::Sender<Option<SupervisorServiceAdvertisement>>,
    ) -> Handle {
        let retained_routes = routes.clone();
        let publication_routes = routes.clone();
        let publication_domain = self.domain.clone();
        let publication_sender = advertisements.clone();
        let advertisement_task = tokio::spawn(async move {
            publish_advertisements(publication_routes, publication_domain, publication_sender)
                .await;
        });
        let task = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(64));
            let mut connections = JoinSet::new();
            ocsf_emit!(
                AppLifecycleBuilder::new(crate::ocsf_ctx())
                    .activity(ActivityId::Open)
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .message("Supervisor app listener ready")
                    .build()
            );
            loop {
                tokio::select! {
                    Some(_) = connections.join_next(), if !connections.is_empty() => {},
                    accepted = self.listener.accept() => {
                        let Ok((stream, _peer)) = accepted else { break; };
                        let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                        openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                        let acceptor = self.acceptor.clone();
                        let domain = self.domain.clone();
                        let routes = routes.clone();
                        let connector = connector.clone();
                        let prefix = format!("{}--{sandbox}", workspace.borrow().as_str());
                        connections.spawn(async move {
                            let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await else { return; };
                            let Some(sni) = tls.get_ref().1.server_name().map(str::to_ascii_lowercase) else {
                                emit_denial("App listener missing SNI"); return;
                            };
                            let Some((route, token)) = routes.resolve(&sni, &prefix, &domain) else {
                                emit_denial("App listener unknown or expired SNI route"); return;
                            };
                            let connection_routes = routes.clone();
                            let connection_route = route.clone();
                            let permit = Arc::new(permit);
                            let service = hyper::service::service_fn(move |req| {
                                proxy(req, sni.clone(), route.clone(), routes.clone(), connector.clone(), permit.clone(), token)
                            });
                            let connection = hyper::server::conn::http1::Builder::new()
                                .timer(TokioTimer::new()).header_read_timeout(HANDSHAKE_TIMEOUT)
                                .max_buf_size(65536).max_headers(64)
                                .serve_connection(TokioIo::new(tls), service).with_upgrades();
                            tokio::select! {
                                _ = connection => {},
                                () = connection_routes.revoked(&connection_route, token) => {},
                            }
                        });
                    }
                }
            }
            routes.suspend();
        });
        Handle {
            task,
            routes: retained_routes,
            advertisement_task,
            advertisements,
        }
    }
}

async fn publish_advertisements(
    routes: Routes,
    domain: String,
    sender: watch::Sender<Option<SupervisorServiceAdvertisement>>,
) {
    let mut updates = routes.sender.subscribe();
    loop {
        let snapshot = updates.borrow_and_update().clone();
        let remaining = snapshot
            .expires
            .and_then(|expiry| expiry.checked_duration_since(Instant::now()));
        let active = remaining.is_some_and(|duration| !duration.is_zero())
            && !routes.stopped.load(Ordering::Acquire);
        sender.send_replace(Some(SupervisorServiceAdvertisement {
            service_domain: domain.clone(),
            routes: if active {
                snapshot.routes.values().cloned().collect()
            } else {
                Vec::new()
            },
            expires_at: remaining.and_then(|duration| {
                openshell_core::time::timestamp_from_system_time(
                    std::time::SystemTime::now() + duration,
                )
                .ok()
            }),
            report_sequence: 0,
        }));
        tokio::select! {
            changed = updates.changed() => { if changed.is_err() { return; } },
            () = async {
                if let Some(duration) = remaining.filter(|duration| !duration.is_zero()) {
                    tokio::time::sleep(duration).await;
                } else { std::future::pending::<()>().await; }
            } => {},
        }
    }
}

fn error(status: StatusCode) -> Response<Body> {
    emit_denial(&format!(
        "App listener request rejected [status:{}]",
        status.as_u16()
    ));
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("valid error response")
}

fn emit_denial(message: &str) {
    ocsf_emit!(
        NetworkActivityBuilder::new(crate::ocsf_ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .dst_endpoint(openshell_ocsf::Endpoint {
                domain: None,
                ip: None,
                port: None
            })
            .message(message)
            .build()
    );
}

fn authority_matches<B>(req: &Request<B>, sni: &str) -> bool {
    let mut values = req.headers().get_all(header::HOST).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(value) = value.to_str() else {
        return false;
    };
    if value.contains('@') {
        return false;
    }
    let Ok(authority) = value.parse::<http::uri::Authority>() else {
        return false;
    };
    if authority.port().is_some() && authority.port_u16().is_none() {
        return false;
    }
    authority.host().eq_ignore_ascii_case(sni)
        && req
            .uri()
            .authority()
            .is_none_or(|uri| uri.as_str().eq_ignore_ascii_case(value))
}

fn gateway_header(name: &str) -> bool {
    matches!(
        name,
        "proxy-authorization"
            | "cf-access-jwt-assertion"
            | "cf-access-authenticated-user-email"
            | "x-openshell-principal"
            | "x-openshell-user"
            | "x-openshell-roles"
            | "x-forwarded-client-cert"
            | "x-ssl-client-cert"
            | "x-client-cert"
    )
}

fn hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn sanitize_headers(headers: &mut http::HeaderMap, passthrough: bool, websocket: bool) -> bool {
    if passthrough {
        let values: Vec<_> = headers.get_all(header::AUTHORIZATION).iter().collect();
        if values.len() > 1 {
            return false;
        }
        if let Some(value) = values.first() {
            let Ok(value) = value.to_str() else {
                return false;
            };
            let Some(token) = openshell_core::auth::strip_bearer_scheme(value) else {
                return false;
            };
            if token.is_empty()
                || !token
                    .trim_end_matches('=')
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
                || token.trim_end_matches('=').is_empty()
            {
                return false;
            }
        }
    } else {
        headers.remove(header::AUTHORIZATION);
    }
    let connection_headers: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .collect();
    let remove: Vec<_> = headers
        .keys()
        .filter(|name| {
            gateway_header(name.as_str())
                || ((hop_header(name.as_str())
                    || connection_headers
                        .iter()
                        .any(|value| value == name.as_str()))
                    && !(websocket && matches!(name.as_str(), "connection" | "upgrade")))
        })
        .cloned()
        .collect();
    for name in remove {
        headers.remove(name);
    }
    let cookies: Vec<_> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter(|cookie| {
            cookie.split_once('=').is_some_and(|(name, _)| {
                !name.trim().eq_ignore_ascii_case("CF_Authorization")
                    && !name.trim().eq_ignore_ascii_case("cf-authorization")
            })
        })
        .map(str::trim)
        .collect();
    let cookie = cookies.join("; ");
    headers.remove(header::COOKIE);
    if !cookie.is_empty()
        && let Ok(cookie) = cookie.parse()
    {
        headers.insert(header::COOKIE, cookie);
    }
    true
}

async fn proxy(
    mut req: Request<Incoming>,
    sni: String,
    route: SandboxServiceRoute,
    routes: Routes,
    connector: Arc<BoundaryLoopbackConnector>,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    token: RouteToken,
) -> std::result::Result<Response<Body>, std::convert::Infallible> {
    if !authority_matches(&req, &sni) {
        return Ok(error(StatusCode::MISDIRECTED_REQUEST));
    }
    // Keep the public authority after validating it against SNI. The dial target
    // is loopback, but rewriting Host would break application same-origin checks.
    let authority = req.headers()[header::HOST].clone();
    let websocket = req
        .headers()
        .get(header::UPGRADE)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"));
    if !sanitize_headers(req.headers_mut(), route.authorization_mode == 2, websocket) {
        return Ok(error(StatusCode::BAD_REQUEST));
    }
    let downstream = websocket.then(|| hyper::upgrade::on(&mut req));
    let target = LoopbackTarget::new(
        "127.0.0.1".parse().expect("loopback"),
        u16::try_from(route.target_port).expect("validated route port"),
    )
    .expect("validated route port");
    let Ok(Ok(stream)) = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(target)).await
    else {
        return Ok(error(StatusCode::BAD_GATEWAY));
    };
    let Ok((mut sender, connection)) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
    else {
        return Ok(error(StatusCode::BAD_GATEWAY));
    };
    let upstream_task = tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let (mut parts, body) = req.into_parts();
    parts.uri = parts
        .uri
        .path_and_query()
        .map_or("/", |path| path.as_str())
        .parse()
        .expect("valid path");
    parts.headers.insert(header::HOST, authority);
    let response = sender.send_request(Request::from_parts(parts, body)).await;
    let Ok(mut response) = response else {
        upstream_task.abort();
        return Ok(error(StatusCode::BAD_GATEWAY));
    };
    if response.status() == StatusCode::SWITCHING_PROTOCOLS && websocket {
        let upstream = hyper::upgrade::on(&mut response);
        let downstream = downstream.expect("websocket upgrade");
        tokio::spawn(async move {
            let _permit = permit;
            tokio::select! {
                () = async {
                    if let (Ok(upstream), Ok(downstream)) = tokio::join!(upstream, downstream) {
                        let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(upstream), &mut TokioIo::new(downstream)).await;
                    }
                } => {},
                () = routes.revoked(&route, token) => {},
            }
            upstream_task.abort();
        });
        let (parts, _) = response.into_parts();
        return Ok(Response::from_parts(parts, Body::empty()));
    }
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(parts, Body::new(body)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt as _, StreamExt as _};
    use openshell_isolation_interface::contract::{BackendError, BoundaryDuplexStream};
    use openshell_sandbox_backend::test_support as rpc_test;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    const HOST: &str = "default--sandbox-a--web.svc.openshell.internal";

    fn installed(routes: Vec<SandboxServiceRoute>) -> SettingsPollResult {
        SettingsPollResult {
            service_routes: routes,
            configuration_instance_id: "runtime-a".into(),
            configuration_admitted: true,
            configuration_error: String::new(),
            policy: None,
            version: 1,
            policy_hash: String::new(),
            config_revision: 1,
            policy_source: openshell_core::proto::PolicySource::Unspecified,
            settings: std::collections::HashMap::default(),
            global_policy_version: 0,
            provider_env_revision: 0,
            provider_attachment_epoch: String::new(),
            supervisor_middleware_services: Vec::new(),
            workspace: "default".into(),
            policy_validation_failure_mode: openshell_core::PolicyValidationFailureMode::default(),
            extension_authentication_enabled: false,
        }
    }

    struct Connector {
        calls: AtomicUsize,
    }

    #[tonic::async_trait]
    impl rpc_test::BoundaryLoopbackConnector for Connector {
        async fn connect(
            &self,
            target: LoopbackTarget,
        ) -> std::result::Result<BoundaryDuplexStream, BackendError> {
            assert_eq!(target.port(), 8080);
            let (client, server) = tokio::io::duplex(8192);
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(|mut req: Request<Incoming>| async move {
                    if let Some(key) = req.headers().get("sec-websocket-key") {
                        let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(
                            key.as_bytes(),
                        );
                        let upgraded = hyper::upgrade::on(&mut req);
                        tokio::spawn(async move {
                            if let Ok(stream) = upgraded.await {
                                let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                                    TokioIo::new(stream),
                                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                                    None,
                                )
                                .await;
                                while let Some(Ok(message)) = ws.next().await {
                                    if ws.send(message).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        });
                        return Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(101)
                                .header("connection", "upgrade")
                                .header("upgrade", "websocket")
                                .header("sec-websocket-accept", accept)
                                .header("x-test-upstream-host", req.headers()[header::HOST].clone())
                                .header(
                                    "x-test-upstream-origin",
                                    req.headers()
                                        .get(header::ORIGIN)
                                        .cloned()
                                        .unwrap_or_else(|| "absent".parse().unwrap()),
                                )
                                .body(Body::empty())
                                .unwrap(),
                        );
                    }
                    let body = format!(
                        "{} {} {} {}",
                        req.uri(),
                        req.headers()[header::HOST].to_str().unwrap(),
                        req.headers()
                            .get(header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("stripped"),
                        req.headers()
                            .get(header::ORIGIN)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("absent")
                    );
                    Ok::<_, std::convert::Infallible>(Response::new(Body::from(body)))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(server), service)
                    .with_upgrades()
                    .await;
            });
            Ok(Box::new(client))
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        _handle: Handle,
        address: SocketAddr,
        tls: Arc<rustls::ClientConfig>,
        routes: Routes,
        connector: Arc<Connector>,
        route: SandboxServiceRoute,
        advertisements: watch::Receiver<Option<SupervisorServiceAdvertisement>>,
    }

    async fn fixture() -> Fixture {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let directory = tempfile::tempdir().unwrap();
        let cert =
            rcgen::generate_simple_self_signed(vec!["*.svc.openshell.internal".into()]).unwrap();
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        let config = Config {
            address: "127.0.0.1:0".parse().unwrap(),
            domain: "svc.openshell.internal".into(),
            certificate: cert_path,
            key: key_path,
        };
        let bound = config.bind().await.unwrap();
        let address = bound.listener.local_addr().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let tls = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let routes = Routes::default();
        let route = SandboxServiceRoute {
            endpoint_id: "endpoint-a".into(),
            name: "web".into(),
            target_port: 8080,
            authorization_mode: 1,
            resource_version: 1,
        };
        routes.install(&installed(vec![route.clone()]));
        let connector = Arc::new(Connector {
            calls: AtomicUsize::new(0),
        });
        let (advertisement_sender, advertisements) = watch::channel(None);
        let handle = bound.start(
            routes.clone(),
            "sandbox-a".into(),
            watch::channel("default".into()).1,
            rpc_test::loopback(connector.clone()),
            advertisement_sender,
        );
        Fixture {
            _directory: directory,
            _handle: handle,
            address,
            tls,
            routes,
            connector,
            route,
            advertisements,
        }
    }

    async fn request(f: &Fixture, sni: &str, host: &str, extra: &str) -> String {
        request_method(f, "GET", sni, host, extra).await
    }

    async fn request_method(
        f: &Fixture,
        method: &str,
        sni: &str,
        host: &str,
        extra: &str,
    ) -> String {
        let stream = openshell_core::net::connect_tcp_nodelay_best_effort(&[f.address])
            .await
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(f.tls.clone())
            .connect(server_name, stream)
            .await
            .unwrap();
        let _ = tls
            .write_all(
                format!(
                    "{method} /hello?x=1 HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra}\r\n"
                )
                .as_bytes(),
            )
            .await;
        let mut response = Vec::new();
        // Unknown SNI closes the TLS stream without an HTTP response.
        let _ = tokio::time::timeout(Duration::from_secs(3), tls.read_to_end(&mut response))
            .await
            .unwrap();
        String::from_utf8(response).unwrap()
    }

    #[tokio::test]
    async fn browser_post_preserves_public_authority_and_origin() {
        let f = fixture().await;
        let authority = format!("{HOST}:18443");
        let origin = format!("https://{authority}");
        let response = request_method(
            &f,
            "POST",
            HOST,
            &authority,
            &format!("Origin: {origin}\r\nContent-Length: 0\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response.contains(&format!("/hello?x=1 {authority} stripped {origin}")),
            "{response}"
        );
    }

    #[tokio::test]
    async fn tls_routes_only_matching_sni_and_authority() {
        let f = fixture().await;
        let response = request(
            &f,
            HOST,
            &format!("{HOST}:18443"),
            "Authorization: Bearer app-token\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response.contains(&format!("/hello?x=1 {HOST}:18443 stripped")),
            "{response}"
        );
        let mismatch = request(
            &f,
            HOST,
            "default--sandbox-b--web.svc.openshell.internal",
            "",
        )
        .await;
        assert!(mismatch.starts_with("HTTP/1.1 421"), "{mismatch}");
        let unknown = request(
            &f,
            "default--sandbox-b--web.svc.openshell.internal",
            "default--sandbox-b--web.svc.openshell.internal",
            "",
        )
        .await;
        assert!(unknown.is_empty());
        assert_eq!(f.connector.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn duplicate_host_and_malformed_bearer_never_dial_boundary() {
        let f = fixture().await;
        let duplicate = request(&f, HOST, HOST, &format!("Host: {HOST}\r\n")).await;
        assert!(!duplicate.starts_with("HTTP/1.1 200"));
        f.routes
            .sender
            .send_modify(|snapshot| snapshot.routes.get_mut("web").unwrap().authorization_mode = 2);
        let malformed = request(&f, HOST, HOST, "Authorization: Basic credential\r\n").await;
        assert!(malformed.starts_with("HTTP/1.1 400"));
        let valid = request(&f, HOST, HOST, "Authorization: bEaReR app-token\r\n").await;
        assert!(valid.contains("bEaReR app-token"), "{valid}");
        assert_eq!(f.connector.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn withdrawn_and_expired_routes_never_dial_boundary() {
        let f = fixture().await;
        let (_, old_token) = f
            .routes
            .resolve(HOST, "default--sandbox-a", "svc.openshell.internal")
            .unwrap();
        f.routes.suspend();
        f.routes.install(&installed(vec![f.route.clone()]));
        // Even a quickly restored identical route cannot revive an old stream.
        tokio::time::timeout(
            Duration::from_secs(1),
            f.routes.revoked(&f.route, old_token),
        )
        .await
        .unwrap();
        f.routes.sender.send_modify(|snapshot| {
            snapshot.expires = Some(Instant::now() - Duration::from_secs(1));
        });
        assert!(request(&f, HOST, HOST, "").await.is_empty());
        f.routes.suspend();
        assert!(request(&f, HOST, HOST, "").await.is_empty());
        assert_eq!(f.connector.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn headers_strip_edge_identity_and_connection_named_fields() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "app=session; CF_Authorization=secret".parse().unwrap(),
        );
        headers.insert("x-forwarded-client-cert", "secret".parse().unwrap());
        headers.insert(header::CONNECTION, "x-internal".parse().unwrap());
        headers.insert("x-internal", "secret".parse().unwrap());
        assert!(sanitize_headers(&mut headers, false, false));
        assert_eq!(headers[header::COOKIE], "app=session");
        assert!(!headers.contains_key("x-forwarded-client-cert"));
        assert!(!headers.contains_key("x-internal"));
    }
    #[tokio::test]
    async fn websocket_echo_closes_on_route_withdrawal() {
        let f = fixture().await;
        let stream = openshell_core::net::connect_tcp_nodelay_best_effort(&[f.address])
            .await
            .unwrap();
        let name = rustls::pki_types::ServerName::try_from(HOST.to_string()).unwrap();
        let tls = tokio_rustls::TlsConnector::from(f.tls.clone())
            .connect(name, stream)
            .await
            .unwrap();
        let mut request = format!("wss://{HOST}/echo").into_client_request().unwrap();
        request
            .headers_mut()
            .insert(header::ORIGIN, format!("https://{HOST}").parse().unwrap());
        let (mut ws, response) = tokio_tungstenite::client_async(request, tls).await.unwrap();
        assert_eq!(response.headers()["x-test-upstream-host"], HOST);
        assert_eq!(
            response.headers()["x-test-upstream-origin"],
            format!("https://{HOST}")
        );
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            "hello".into(),
        ))
        .await
        .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .to_text()
                .unwrap(),
            "hello"
        );
        f.routes.suspend();
        let closed = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap();
        assert!(closed.is_none() || closed.unwrap().is_err());
        assert_eq!(f.connector.calls.load(Ordering::SeqCst), 1);
    }

    type TestWebSocket =
        tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

    async fn websocket(f: &Fixture, service: &str) -> TestWebSocket {
        let host = format!("default--sandbox-a--{service}.svc.openshell.internal");
        let stream = openshell_core::net::connect_tcp_nodelay_best_effort(&[f.address])
            .await
            .unwrap();
        let name = rustls::pki_types::ServerName::try_from(host.clone()).unwrap();
        let tls = tokio_rustls::TlsConnector::from(f.tls.clone())
            .connect(name, stream)
            .await
            .unwrap();
        tokio_tungstenite::client_async(format!("wss://{host}/echo"), tls)
            .await
            .unwrap()
            .0
    }

    async fn echo(ws: &mut TestWebSocket, value: &str) {
        ws.send(tokio_tungstenite::tungstenite::Message::Text(value.into()))
            .await
            .unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(echoed.to_text().unwrap(), value);
    }

    async fn closed(ws: &mut TestWebSocket) {
        let next = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("revoked WebSocket must close");
        assert!(next.is_none() || next.unwrap().is_err());
    }

    #[tokio::test]
    async fn service_edits_close_only_affected_websockets() {
        let f = fixture().await;
        let mut web = websocket(&f, "web").await;
        let mut portal = SandboxServiceRoute {
            endpoint_id: "portal-id".into(),
            name: "portal".into(),
            ..f.route.clone()
        };
        f.routes
            .install(&installed(vec![f.route.clone(), portal.clone()]));
        echo(&mut web, "web survives portal addition").await;
        let mut portal_ws = websocket(&f, "portal").await;
        echo(&mut portal_ws, "portal active").await;

        // Renewing identical declarations does not revoke either stream.
        f.routes
            .install(&installed(vec![f.route.clone(), portal.clone()]));
        echo(&mut web, "web renewed").await;
        echo(&mut portal_ws, "portal renewed").await;

        portal.authorization_mode = 2;
        portal.resource_version += 1;
        f.routes
            .install(&installed(vec![f.route.clone(), portal.clone()]));
        closed(&mut portal_ws).await;
        echo(&mut web, "web survives portal edit").await;

        let mut portal_ws = websocket(&f, "portal").await;
        f.routes.install(&installed(vec![f.route.clone()]));
        closed(&mut portal_ws).await;
        echo(&mut web, "web survives portal deletion").await;

        f.routes.install(&installed(vec![f.route.clone(), portal]));
        let mut portal_ws = websocket(&f, "portal").await;
        f.routes.suspend();
        closed(&mut web).await;
        closed(&mut portal_ws).await;
    }

    #[tokio::test]
    async fn coalesced_recreation_and_lease_lapse_cannot_revive_old_streams() {
        let f = fixture().await;
        let (_, original) = f
            .routes
            .resolve(HOST, "default--sandbox-a", "svc.openshell.internal")
            .unwrap();
        // Both updates can occur before a watch receiver observes either one.
        f.routes.install(&installed(Vec::new()));
        f.routes.install(&installed(vec![f.route.clone()]));
        tokio::time::timeout(Duration::from_secs(1), f.routes.revoked(&f.route, original))
            .await
            .unwrap();

        let (_, renewed) = f
            .routes
            .resolve(HOST, "default--sandbox-a", "svc.openshell.internal")
            .unwrap();
        f.routes.sender.send_modify(|snapshot| {
            snapshot.expires = Some(Instant::now() - Duration::from_secs(1));
        });
        f.routes.install(&installed(vec![f.route.clone()]));
        tokio::time::timeout(Duration::from_secs(1), f.routes.revoked(&f.route, renewed))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn advertisements_follow_installed_routes_and_withdrawal() {
        let mut f = fixture().await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while f
                .advertisements
                .borrow_and_update()
                .as_ref()
                .is_none_or(|ad| ad.routes.is_empty())
            {
                f.advertisements.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let report = f.advertisements.borrow().clone().unwrap();
        assert_eq!(report.service_domain, "svc.openshell.internal");
        assert_eq!(report.routes, vec![f.route.clone()]);
        assert!(report.expires_at.is_some());
        f.routes.suspend();
        tokio::time::timeout(Duration::from_secs(2), async {
            while f
                .advertisements
                .borrow_and_update()
                .as_ref()
                .is_some_and(|ad| !ad.routes.is_empty())
            {
                f.advertisements.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(
            f.advertisements
                .borrow()
                .as_ref()
                .unwrap()
                .routes
                .is_empty()
        );
    }
}
