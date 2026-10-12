// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use clap::Parser;
use openshell_core::proto::{WatchServiceRoutesRequest, WorkspaceSelector, workspace_selector};
use openshell_sandbox_proxy::RouteCache;
use openshell_sdk::{AuthConfig, ClientConfig, OpenShellClient};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Clone, Parser)]
#[command(
    version,
    about = "OpenShell sandbox proxy with discovery-driven TLS passthrough ingress"
)]
struct Args {
    #[arg(
        long,
        env = "OPENSHELL_PROXY_LISTEN_ADDRESS",
        default_value = "0.0.0.0:8443"
    )]
    listen_address: SocketAddr,
    #[arg(long, env = "OPENSHELL_PROXY_GATEWAY_ENDPOINT")]
    gateway_endpoint: String,
    /// Explicit discovery workspaces; repeat this flag for each authorized scope.
    #[arg(long, required = true, value_delimiter = ',')]
    workspace: Vec<String>,
    /// Bearer credential file, reread on each watch reconnect. Never sent to applications.
    #[arg(long, env = "OPENSHELL_PROXY_DISCOVERY_TOKEN_FILE")]
    discovery_token_file: Option<PathBuf>,
    /// Public gateway CA certificate. Application TLS stays on supervisors.
    #[arg(long)]
    gateway_ca: Option<PathBuf>,
    /// Permit an unauthenticated plaintext gateway only in a local development cluster.
    #[arg(long)]
    allow_plaintext_development: bool,
    #[arg(long, default_value_t = 256)]
    max_connections: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    validate(&args)?;
    let listener = tokio::net::TcpListener::bind(args.listen_address).await?;
    let (cache, routes) = RouteCache::new();
    let cache = Arc::new(Mutex::new(cache));
    let mut discovery = tokio::task::JoinSet::new();
    for workspace in &args.workspace {
        discovery.spawn(discover(args.clone(), workspace.clone(), cache.clone()));
    }
    tracing::info!(address = %listener.local_addr()?, "sandbox application proxy listening");
    tokio::select! {
        result = openshell_sandbox_proxy::serve(listener, routes, args.max_connections) => result,
        result = discovery.join_next() => { bail!("discovery task ended unexpectedly: {result:?}"); },
        result = tokio::signal::ctrl_c() => { result?; Ok(()) },
    }
}

fn validate(args: &Args) -> Result<()> {
    if args.max_connections == 0 || args.max_connections > 65536 {
        bail!("max connections must be between 1 and 65536");
    }
    if args.workspace.iter().any(String::is_empty)
        || args.workspace.iter().collect::<BTreeSet<_>>().len() != args.workspace.len()
    {
        bail!("discovery workspaces must be nonempty and unique");
    }
    if args.allow_plaintext_development {
        if !args.gateway_endpoint.starts_with("http://") || args.discovery_token_file.is_some() {
            bail!("plaintext development requires an HTTP gateway without bearer credentials");
        }
    } else if !args.gateway_endpoint.starts_with("https://") || args.discovery_token_file.is_none()
    {
        bail!(
            "discovery requires HTTPS and --discovery-token-file; use --allow-plaintext-development only for local testing"
        );
    }
    Ok(())
}

async fn client(args: &Args) -> Result<OpenShellClient> {
    let mut config = ClientConfig::new(&args.gateway_endpoint);
    if let Some(path) = &args.discovery_token_file {
        let token = tokio::fs::read_to_string(path)
            .await
            .context("read discovery credential file")?;
        let token = token.trim();
        if token.is_empty() {
            bail!("empty discovery credential file");
        }
        config.auth = Some(AuthConfig::oidc(token));
    }
    if let Some(path) = &args.gateway_ca {
        config.ca_cert = Some(tokio::fs::read(path).await.context("read gateway CA")?);
    }
    OpenShellClient::connect(config)
        .await
        .map_err(|_| anyhow::anyhow!("gateway discovery connection failed"))
}

async fn discover(args: Args, workspace: String, cache: Arc<Mutex<RouteCache>>) {
    loop {
        let result = watch_once(&args, &workspace, &cache).await;
        if let Err(error) = result {
            if error.downcast_ref::<tonic::Status>().is_some_and(|status| {
                matches!(
                    status.code(),
                    tonic::Code::PermissionDenied | tonic::Code::Unauthenticated
                )
            }) {
                cache.lock().await.withdraw(&workspace);
            }
            // Do not log error bodies or request metadata: they may contain credentials.
            tracing::warn!(%workspace, "discovery interrupted; reconnecting, cached routes retain only their existing leases");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn watch_once(args: &Args, workspace: &str, cache: &Arc<Mutex<RouteCache>>) -> Result<()> {
    let client = client(args).await?;
    let mut grpc = client.raw_grpc_fresh().await?;
    let request = WatchServiceRoutesRequest {
        workspace_scope: Some(WorkspaceSelector {
            selection: Some(workspace_selector::Selection::Workspace(workspace.into())),
        }),
    };
    let response =
        tokio::time::timeout(Duration::from_secs(10), grpc.watch_service_routes(request))
            .await
            .context("discovery watch opening timeout")??;
    let mut stream = response.into_inner();
    while let Some(update) = tokio::time::timeout(Duration::from_secs(70), stream.message())
        .await
        .context("discovery watch stalled")??
    {
        let snapshot = update.snapshot.context("discovery snapshot missing")?;
        let count = snapshot.routes.len();
        let installed = cache.lock().await.replace(workspace, snapshot);
        if let Err(error) = installed {
            cache.lock().await.withdraw(workspace);
            return Err(error);
        }
        tracing::debug!(%workspace, routes = count, "discovery snapshot installed");
    }
    Ok(())
}
