// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-test context: the SDK client, the run ID, and the resources to clean up.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use openshell_sdk::{
    DeleteOptions, ExecOptions, ListOptions, SandboxPhase, SandboxRef, SandboxRestartPolicy,
    SandboxSpec, SdkError, WorkspaceScopedClient,
};
use rand::Rng;

use crate::error::{Error, Result, ResultExt};

/// Sandbox creation includes image pulls on a cold environment.
pub const READY_TIMEOUT: Duration = Duration::from_mins(10);
pub const DELETE_TIMEOUT: Duration = Duration::from_mins(2);
pub const EXEC_TIMEOUT: Duration = Duration::from_mins(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_mins(2);

/// Names of sandboxes created by a test and not yet confirmed deleted.
type Registry = Arc<Mutex<BTreeSet<String>>>;

/// What a test uses to act on the system under test.
pub struct Context {
    client: WorkspaceScopedClient,
    run_id: String,
    sandboxes: Registry,
}

impl Context {
    pub(crate) fn new(client: WorkspaceScopedClient) -> Self {
        Self {
            client,
            run_id: generate_run_id(),
            sandboxes: Registry::default(),
        }
    }

    /// The ID unique to this test run, used in resource names.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The SDK client, for operations testkit does not wrap.
    pub fn client(&self) -> &WorkspaceScopedClient {
        &self.client
    }

    /// A resource name unique to this run: `test-<run-id>-<suffix>`.
    pub fn name(&self, suffix: &str) -> String {
        format!("test-{}-{suffix}", self.run_id)
    }

    /// Start describing a sandbox named `cx.name(suffix)`.
    pub fn sandbox(&self, suffix: &str) -> SandboxBuilder {
        SandboxBuilder {
            client: self.client.clone(),
            sandboxes: Arc::clone(&self.sandboxes),
            spec: SandboxSpec {
                name: Some(self.name(suffix)),
                ..SandboxSpec::default()
            },
        }
    }

    /// Fail unless the sandbox is gone from both get and list.
    pub async fn expect_absent(&self, sandbox: &Sandbox) -> Result {
        let name = sandbox.name();
        match self.client.get_sandbox(name).await {
            Err(SdkError::NotFound { .. }) => {}
            Err(error) => return Err(Error::from(error).context(format!("get sandbox {name}"))),
            Ok(found) => {
                return Err(Error::msg(format!(
                    "sandbox {name} still exists (id {}, phase {:?})",
                    found.id, found.phase
                )));
            }
        }
        let listed = self
            .client
            .list_all_sandboxes(ListOptions::default())
            .await
            .context("list sandboxes")?;
        crate::ensure!(
            !listed.iter().any(|entry| entry.name == name),
            "sandbox {name} is absent from get but still listed"
        );
        Ok(())
    }

    /// Delete every sandbox the test created and has not deleted. Returns the
    /// cleanup failures; they are reported separately from the test result.
    pub(crate) async fn cleanup(&self) -> Vec<String> {
        let started = Instant::now();
        let names: Vec<String> = lock(&self.sandboxes).iter().cloned().collect();
        let mut failures = Vec::new();
        for name in names {
            let remaining = CLEANUP_TIMEOUT.saturating_sub(started.elapsed());
            let result = async {
                self.client
                    .delete_sandbox(
                        &name,
                        DeleteOptions {
                            allow_missing: true,
                        },
                    )
                    .await?;
                self.client.wait_deleted(&name, remaining, None).await
            }
            .await;
            match result {
                Ok(()) => {
                    lock(&self.sandboxes).remove(&name);
                }
                Err(error) => failures.push(format!("delete sandbox {name}: {error}")),
            }
        }
        failures
    }
}

/// A sandbox to create.
pub struct SandboxBuilder {
    client: WorkspaceScopedClient,
    sandboxes: Registry,
    spec: SandboxSpec,
}

impl SandboxBuilder {
    /// The sandbox's main command. Empty selects the gateway's default.
    #[must_use]
    pub fn command<I, S>(mut self, command: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.spec.command = command.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn restart_policy(mut self, policy: SandboxRestartPolicy) -> Self {
        self.spec.restart_policy = policy;
        self
    }

    /// Full access to the spec for fields without a builder method.
    #[must_use]
    pub fn spec(mut self, update: impl FnOnce(&mut SandboxSpec)) -> Self {
        update(&mut self.spec);
        self
    }

    /// Create the sandbox. It is tracked for cleanup before the request is
    /// sent, so a create that fails after the gateway accepted it is still
    /// cleaned up.
    pub async fn create(self) -> Result<Sandbox> {
        let name = self.spec.name.clone().unwrap_or_default();
        lock(&self.sandboxes).insert(name.clone());
        let created = self
            .client
            .create_sandbox(self.spec)
            .await
            .context(format!("create sandbox {name}"))?;
        Ok(Sandbox {
            client: self.client,
            sandboxes: self.sandboxes,
            name,
            id: created.id,
        })
    }
}

/// A sandbox created by the test.
pub struct Sandbox {
    client: WorkspaceScopedClient,
    sandboxes: Registry,
    name: String,
    id: String,
}

/// The buffered output of an exec.
#[derive(Debug)]
pub struct ExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Sandbox {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Wait until the sandbox is Ready. A sandbox that completes or fails
    /// instead is an error.
    pub async fn wait_ready(&self) -> Result<SandboxRef> {
        let snapshot = self
            .client
            .wait_ready(&self.name, READY_TIMEOUT)
            .await
            .context(format!("wait for sandbox {} to be ready", self.name))?;
        crate::ensure!(
            snapshot.phase == SandboxPhase::Ready,
            "sandbox {} reached phase {:?}; expected Ready",
            self.name,
            snapshot.phase
        );
        Ok(snapshot)
    }

    /// Run a command in the sandbox and buffer its output.
    pub async fn exec<I, S>(&self, command: I) -> Result<ExecOutput>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let command: Vec<String> = command.into_iter().map(Into::into).collect();
        let options = ExecOptions {
            timeout: Some(EXEC_TIMEOUT),
            ..ExecOptions::default()
        };
        let result = self
            .client
            .exec(&self.name, &command, options)
            .await
            .context(format!("exec {command:?} in sandbox {}", self.name))?;
        Ok(ExecOutput {
            exit_code: result.exit_code,
            stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
        })
    }

    /// Delete the sandbox and wait until it is gone.
    pub async fn delete(&self) -> Result {
        self.client
            .delete_sandbox(&self.name, DeleteOptions::default())
            .await
            .context(format!("delete sandbox {}", self.name))?;
        self.client
            .wait_deleted(&self.name, DELETE_TIMEOUT, Some(&self.id))
            .await
            .context(format!("wait for sandbox {} to be deleted", self.name))?;
        lock(&self.sandboxes).remove(&self.name);
        Ok(())
    }
}

fn lock(registry: &Registry) -> std::sync::MutexGuard<'_, BTreeSet<String>> {
    registry.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Short, lowercase, and DNS-label safe, so names work on every driver.
fn generate_run_id() -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::rng();
    (0..8)
        .map(|_| char::from(ALPHABET[rng.random_range(0..ALPHABET.len())]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_ids_are_dns_label_safe() {
        let id = generate_run_id();
        assert_eq!(id.len(), 8);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
            "{id}"
        );
    }
}
