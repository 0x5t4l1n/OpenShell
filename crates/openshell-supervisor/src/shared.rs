// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Idle process lifecycle for the experimental shared supervisor deployment.
//! There is deliberately no session API or gateway authentication in this milestone.

use clap::{Parser, ValueEnum};
use miette::{IntoDiagnostic as _, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Scope {
    Gateway,
    Workspace,
}

#[derive(Parser, Debug)]
#[command(
    name = "openshell-supervisor shared",
    about = "Start an idle experimental shared supervisor (no sandbox sessions)"
)]
struct Args {
    #[arg(long)]
    gateway_id: String,
    #[arg(long, value_enum, default_value = "gateway")]
    scope: Scope,
    #[arg(long, required_if_eq("scope", "workspace"))]
    workspace: Option<String>,
    #[arg(long, default_value_t = 5501)]
    health_port: u16,
}

pub fn main(args: &[String]) -> Result<()> {
    let args = Args::parse_from(args);
    if args.health_port == 0 || (args.scope == Scope::Gateway && args.workspace.is_some()) {
        return Err(miette::miette!(
            "shared supervisor requires a nonzero health port and workspace only with workspace scope"
        ));
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    tokio::runtime::Builder::new_current_thread().enable_all().build().into_diagnostic()?.block_on(async {
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", args.health_port)).await.into_diagnostic()?;
        tracing::info!(gateway_id = %args.gateway_id, scope = ?args.scope, workspace = ?args.workspace,
            "Shared supervisor started; sandbox sessions are not enabled");
        let shutdown = shutdown();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, _) = result.into_diagnostic()?;
                    drop(stream);
                }
                result = &mut shutdown => {
                    result?;
                    tracing::info!("Shared supervisor stopped");
                    return Ok(());
                }
            }
        }
    })
}

async fn shutdown() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .into_diagnostic()?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.into_diagnostic()?,
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await.into_diagnostic()?;
    Ok(())
}
