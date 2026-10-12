// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reference integration: gateway discovery -> exact service SNI -> supervisor TLS stream.

#[cfg(test)]
mod tests;

use anyhow::{Context, Result, bail};
use openshell_core::proto::{DiscoveredServiceRoute, ServiceRouteSnapshot};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

const MAX_CLIENT_HELLO: usize = 64 * 1024;
const MAX_ROUTES: usize = 4096;
const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct Route {
    pub declaration: DiscoveredServiceRoute,
    expires: Instant,
}

impl Route {
    fn same_backend(&self, other: &Self) -> bool {
        let a = &self.declaration;
        let b = &other.declaration;
        a.service_id == b.service_id
            && a.service_revision == b.service_revision
            && a.sandbox_id == b.sandbox_id
            && a.supervisor_instance_id == b.supervisor_instance_id
            && a.runtime_generation == b.runtime_generation
            && a.supervisor_app_address == b.supervisor_app_address
            && a.hostname == b.hostname
    }
}

pub type Routes = BTreeMap<String, Route>;

/// Each workspace update replaces its cache. Other workspaces retain their own leases.
pub struct RouteCache {
    workspaces: BTreeMap<String, Routes>,
    publisher: watch::Sender<Routes>,
}

impl RouteCache {
    pub fn new() -> (Self, watch::Receiver<Routes>) {
        let (publisher, receiver) = watch::channel(Routes::new());
        (
            Self {
                workspaces: BTreeMap::new(),
                publisher,
            },
            receiver,
        )
    }

    pub fn replace(&mut self, workspace: &str, snapshot: ServiceRouteSnapshot) -> Result<()> {
        if snapshot.routes.len() > MAX_ROUTES {
            bail!("discovery snapshot exceeds route limit");
        }
        let now = openshell_core::time::now_ms();
        let mut routes = Routes::new();
        let mut ids = BTreeSet::new();
        for declaration in snapshot.routes {
            if declaration.workspace != workspace
                || declaration.service_id.is_empty()
                || declaration.sandbox_id.is_empty()
                || declaration.supervisor_instance_id.is_empty()
                || declaration.runtime_generation.is_empty()
                || !valid_hostname(&declaration.hostname)
                || !ids.insert(declaration.service_id.clone())
            {
                bail!("invalid discovery route identity");
            }
            let address: http::uri::Authority = declaration
                .supervisor_app_address
                .parse()
                .context("invalid discovery app address")?;
            if address.port_u16().is_none_or(|port| port == 0)
                || address.host().is_empty()
                || declaration
                    .supervisor_app_address
                    .contains(['@', '/', '?', '#'])
            {
                bail!("invalid discovery app address");
            }
            let expiry = declaration
                .expires_at
                .as_ref()
                .context("route expiry missing")?;
            let remaining = openshell_core::time::timestamp_to_millis(expiry)
                .map_err(|_| anyhow::anyhow!("invalid route expiry"))?
                .saturating_sub(now);
            if remaining <= 0 {
                continue;
            }
            // Gateway advertisements currently have a 30-second lease. Bound untrusted duration input too.
            let expires =
                Instant::now() + Duration::from_millis(u64::try_from(remaining.min(60_000))?);
            if routes
                .insert(
                    declaration.hostname.clone(),
                    Route {
                        declaration,
                        expires,
                    },
                )
                .is_some()
            {
                bail!("duplicate discovered hostname");
            }
        }
        let mut all = Routes::new();
        for (scope, cached) in &self.workspaces {
            if scope != workspace {
                all.extend(
                    cached
                        .iter()
                        .filter(|(_, route)| route.expires > Instant::now())
                        .map(|(host, route)| (host.clone(), route.clone())),
                );
            }
        }
        for (host, route) in &routes {
            if all.insert(host.clone(), route.clone()).is_some() {
                bail!("hostname appears in multiple workspaces");
            }
        }
        if all.len() > MAX_ROUTES {
            bail!("combined discovery cache exceeds route limit");
        }
        self.workspaces.insert(workspace.into(), routes);
        self.publisher.send_replace(all);
        Ok(())
    }

    pub fn withdraw(&mut self, workspace: &str) {
        self.workspaces.remove(workspace);
        let all = self
            .workspaces
            .values()
            .flat_map(|routes| {
                routes
                    .iter()
                    .map(|(host, route)| (host.clone(), route.clone()))
            })
            .collect();
        self.publisher.send_replace(all);
    }
}

fn valid_hostname(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Parse a bounded, possibly fragmented `ClientHello` without terminating TLS.
/// The exact bytes already read are replayed to the supervisor.
async fn read_sni(client: &mut TcpStream) -> Result<(String, Vec<u8>)> {
    let mut parser = rustls::server::Acceptor::default();
    let mut prefix = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            bail!("client closed before TLS ClientHello");
        }
        if prefix.len() + read > MAX_CLIENT_HELLO {
            bail!("TLS ClientHello exceeds size limit");
        }
        prefix.extend_from_slice(&chunk[..read]);
        parser.read_tls(&mut Cursor::new(&chunk[..read]))?;
        let accepted = parser
            .accept()
            .map_err(|_| anyhow::anyhow!("invalid TLS ClientHello"))?;
        if let Some(accepted) = accepted {
            let host = accepted
                .client_hello()
                .server_name()
                .context("TLS SNI required")?
                .to_ascii_lowercase();
            if !valid_hostname(&host) {
                bail!("invalid service SNI");
            }
            return Ok((host, prefix));
        }
    }
}

fn selected(routes: &watch::Receiver<Routes>, host: &str) -> Result<Route> {
    routes
        .borrow()
        .get(host)
        .filter(|route| route.expires > Instant::now())
        .cloned()
        .context("unknown or expired service SNI")
}

pub async fn proxy_connection(
    mut client: TcpStream,
    mut routes: watch::Receiver<Routes>,
) -> Result<()> {
    openshell_core::net::set_tcp_nodelay_best_effort(&client);
    let (host, prefix) = tokio::time::timeout(SETUP_TIMEOUT, read_sni(&mut client))
        .await
        .context("TLS ClientHello timeout")??;
    let route = selected(&routes, &host)?;
    let mut backend = tokio::time::timeout(SETUP_TIMEOUT, async {
        let addresses = tokio::net::lookup_host(&route.declaration.supervisor_app_address)
            .await?
            .collect::<Vec<_>>();
        openshell_core::net::connect_tcp_nodelay_best_effort(&addresses).await
    })
    .await
    .context("supervisor connection timeout")??;
    let latest = selected(&routes, &host)?;
    if !route.same_backend(&latest) {
        bail!("route changed while connecting");
    }
    tokio::time::timeout(SETUP_TIMEOUT, backend.write_all(&prefix))
        .await
        .context("ClientHello forwarding timeout")??;
    let copy = tokio::io::copy_bidirectional(&mut client, &mut backend);
    tokio::pin!(copy);
    loop {
        let latest = selected(&routes, &host)?;
        if !route.same_backend(&latest) {
            bail!("service route withdrawn or replaced");
        }
        tokio::select! {
            result = &mut copy => { result?; return Ok(()); },
            () = tokio::time::sleep_until(latest.expires) => {},
            changed = routes.changed() => { changed.context("route publisher closed")?; },
        }
    }
}

/// Bounded application-only listener. Dropping this task cancels all connections.
pub async fn serve(
    listener: TcpListener,
    routes: watch::Receiver<Routes>,
    max_connections: usize,
) -> Result<()> {
    if max_connections == 0 {
        bail!("max connections must be nonzero");
    }
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (client, _) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let routes = routes.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = proxy_connection(client, routes).await { tracing::debug!(%error, "application connection closed"); }
                });
            },
            _ = tasks.join_next(), if !tasks.is_empty() => {},
        }
    }
}
