// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serialized persistence of supervisor results for running workloads.
//!
//! Persisting a configuration admission or a sandbox policy result takes the
//! compute sandbox lock, which user mutations such as `UpdateConfig` and
//! provider attachment also take. A fanout acknowledged by N sessions at once
//! would queue N waiters ahead of any user write on that FIFO lock.
//!
//! Once a workload runs, its admission no longer gates startup, so results
//! for running workloads are queued here and written by one task. A user
//! write then waits for at most one result write, and repeated admissions for
//! one sandbox collapse into the newest. Policy results are all kept, because
//! each one settles the status of its own policy revision, but a result that
//! repeats the last one recorded for the sandbox is skipped: every sandbox
//! configuration update reports its policy, even when only settings changed.
//! A recorded result lasts as long as the push session that reported it, so
//! deleted sandboxes and sessions that moved to another replica leave no
//! entry behind.
//!
//! A failed write is retried after a delay. Other sandboxes' writes proceed
//! meanwhile, and results queued for the same sandbox wait behind the retry,
//! so they are still written in order.
//!
//! The session acknowledged these results before they were persisted, so it
//! would suppress the unchanged snapshot on reconciliation. A write that
//! exhausts its retries therefore reopens the session's sandbox
//! configuration: the next reconciliation redelivers it, and the supervisor
//! reports the result again. A dropped result was never recorded, so the
//! repeat is not skipped.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use metrics::{counter, gauge};
use openshell_core::proto::SandboxConfigurationAdmission;
use tokio::sync::Notify;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::ConfigComponentKind;
use crate::ServerState;

/// Attempts per queued write before it is dropped.
const MAX_WRITE_ATTEMPTS: u32 = 5;
/// Delay before retrying a failed write, so a struggling store is not hammered.
const RETRY_DELAY: Duration = Duration::from_millis(500);

/// A sandbox policy load result reported by a supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PolicyResult {
    pub(super) version: u32,
    pub(super) loaded: bool,
    pub(super) error: Option<String>,
}

#[derive(Debug)]
struct QueuedAdmission {
    session_id: String,
    instance_id: String,
    admission: SandboxConfigurationAdmission,
    attempts: u32,
}

#[derive(Debug)]
struct QueuedPolicyResult {
    session_id: String,
    result: PolicyResult,
    attempts: u32,
}

#[derive(Debug, Default)]
struct PendingWrites {
    admission: Option<QueuedAdmission>,
    policy_results: Vec<QueuedPolicyResult>,
}

impl PendingWrites {
    fn is_empty(&self) -> bool {
        self.admission.is_none() && self.policy_results.is_empty()
    }
}

#[derive(Debug, Default)]
struct Queue {
    running: bool,
    /// Sandboxes whose writes are ready, oldest first.
    order: VecDeque<String>,
    /// Sandboxes waiting to retry a failed write. Every retry waits the same
    /// delay, so deadlines stay in order.
    retries: VecDeque<(Instant, String)>,
    /// The sandbox being written. Results queued for it meanwhile wait until
    /// the write finishes, behind anything it retries.
    writing: Option<String>,
    /// Writes for each sandbox in `order` or `retries`, or queued while it
    /// is being written.
    pending: HashMap<String, PendingWrites>,
    /// Last policy result written for each sandbox, kept while the session
    /// that reported it stays registered.
    recorded: HashMap<String, PolicyResult>,
}

/// What the writer does next.
#[derive(Debug)]
enum Next {
    Write(String, PendingWrites),
    WaitUntil(Instant),
    Idle,
}

impl Queue {
    fn entry(&mut self, sandbox_id: &str) -> &mut PendingWrites {
        if !self.pending.contains_key(sandbox_id) && self.writing.as_deref() != Some(sandbox_id) {
            self.order.push_back(sandbox_id.to_string());
        }
        self.pending.entry(sandbox_id.to_string()).or_default()
    }

    /// Take the next sandbox to write. Retries that are due go behind the
    /// sandboxes already waiting.
    fn next(&mut self, now: Instant) -> Next {
        while self
            .retries
            .front()
            .is_some_and(|(retry_at, _)| *retry_at <= now)
        {
            if let Some((_, sandbox_id)) = self.retries.pop_front() {
                self.order.push_back(sandbox_id);
            }
        }
        while let Some(sandbox_id) = self.order.pop_front() {
            if let Some(pending) = self.pending.remove(&sandbox_id) {
                self.writing = Some(sandbox_id.clone());
                return Next::Write(sandbox_id, pending);
            }
        }
        if let Some((retry_at, _)) = self.retries.front() {
            return Next::WaitUntil(*retry_at);
        }
        self.running = false;
        Next::Idle
    }

    /// Settle the write of `sandbox_id`. Failed writes retry at `retry_at`,
    /// ahead of results queued meanwhile, and a newer admission replaces the
    /// retried one.
    fn finish(&mut self, sandbox_id: &str, retry: PendingWrites, retry_at: Instant) {
        self.writing = None;
        if retry.is_empty() {
            if self.pending.contains_key(sandbox_id) {
                self.order.push_back(sandbox_id.to_string());
            }
            return;
        }
        let entry = self.pending.entry(sandbox_id.to_string()).or_default();
        if entry.admission.is_none() {
            entry.admission = retry.admission;
        }
        let newer = std::mem::take(&mut entry.policy_results);
        entry.policy_results = retry.policy_results;
        entry.policy_results.extend(newer);
        self.retries.push_back((retry_at, sandbox_id.to_string()));
    }

    /// Mark the writer running, returning whether the caller must start it.
    fn claim_start(&mut self) -> bool {
        !std::mem::replace(&mut self.running, true)
    }

    /// Whether `result` repeats one already written or queued for the sandbox.
    fn is_duplicate_policy_result(&self, sandbox_id: &str, result: &PolicyResult) -> bool {
        if self.pending.get(sandbox_id).is_some_and(|pending| {
            pending
                .policy_results
                .last()
                .is_some_and(|queued| &queued.result == result)
        }) {
            return true;
        }
        let queued_other = self
            .pending
            .get(sandbox_id)
            .is_some_and(|pending| !pending.policy_results.is_empty());
        !queued_other && self.recorded.get(sandbox_id) == Some(result)
    }

    fn report_pending(&self) {
        let pending = u32::try_from(self.pending.len()).unwrap_or(u32::MAX);
        gauge!("openshell_supervisor_config_result_writes_pending").set(f64::from(pending));
    }
}

/// Queue of result writes drained by a single task.
#[derive(Debug, Default)]
pub struct ResultWriter {
    queue: Mutex<Queue>,
    /// Wakes the writer while it waits for a retry.
    wake: Notify,
}

impl ResultWriter {
    fn queue(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Forget the policy result recorded for a sandbox whose push session
    /// unregistered. A later session reports its results afresh.
    pub(super) fn forget_recorded(&self, sandbox_id: &str) {
        self.queue().recorded.remove(sandbox_id);
    }

    #[cfg(test)]
    pub(super) fn is_idle(&self) -> bool {
        let queue = self.queue();
        !queue.running && queue.pending.is_empty()
    }
}

/// Queue the newest admission of a running workload's session.
pub(super) fn queue_admission(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    instance_id: &str,
    admission: &SandboxConfigurationAdmission,
) {
    let writer = &state.config_delivery.results;
    let start = {
        let mut queue = writer.queue();
        let entry = queue.entry(sandbox_id);
        if entry
            .admission
            .replace(QueuedAdmission {
                session_id: session_id.to_string(),
                instance_id: instance_id.to_string(),
                admission: admission.clone(),
                attempts: 0,
            })
            .is_some()
        {
            counter!(
                "openshell_supervisor_config_result_writes_total",
                "kind" => "admission",
                "outcome" => "coalesced",
            )
            .increment(1);
        }
        queue.report_pending();
        queue.claim_start()
    };
    if start {
        tokio::spawn(run(Arc::clone(state)));
    } else {
        writer.wake.notify_one();
    }
}

/// Queue a sandbox policy load result.
pub(super) fn queue_policy_result(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    result: PolicyResult,
) {
    let writer = &state.config_delivery.results;
    let start = {
        let mut queue = writer.queue();
        if queue.is_duplicate_policy_result(sandbox_id, &result) {
            drop(queue);
            record_write("policy_result", "duplicate");
            return;
        }
        queue
            .entry(sandbox_id)
            .policy_results
            .push(QueuedPolicyResult {
                session_id: session_id.to_string(),
                result,
                attempts: 0,
            });
        queue.report_pending();
        queue.claim_start()
    };
    if start {
        tokio::spawn(run(Arc::clone(state)));
    } else {
        writer.wake.notify_one();
    }
}

async fn run(state: Arc<ServerState>) {
    let writer = &state.config_delivery.results;
    loop {
        let next = {
            let mut queue = writer.queue();
            let next = queue.next(Instant::now());
            queue.report_pending();
            next
        };
        match next {
            Next::Write(sandbox_id, pending) => {
                let retry = write(&state, &sandbox_id, pending).await;
                writer
                    .queue()
                    .finish(&sandbox_id, retry, Instant::now() + RETRY_DELAY);
            }
            Next::WaitUntil(retry_at) => {
                tokio::select! {
                    () = tokio::time::sleep_until(retry_at) => {}
                    () = writer.wake.notified() => {}
                }
            }
            Next::Idle => return,
        }
    }
}

/// Write one sandbox's pending results, returning the writes to retry.
async fn write(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    pending: PendingWrites,
) -> PendingWrites {
    let mut retry = PendingWrites::default();
    for mut queued in pending.policy_results {
        let result = &queued.result;
        match crate::grpc::policy::record_policy_apply_result(
            state,
            sandbox_id,
            result.version,
            result.loaded,
            result.error.as_deref(),
            "stream",
        )
        .await
        {
            Ok(()) => {
                // Unregistering a session removes it before it forgets the
                // recorded result, so checking under the queue lock keeps an
                // ended session from leaving an entry behind.
                let mut queue = state.config_delivery.results.queue();
                if state
                    .config_delivery
                    .is_registered(sandbox_id, &queued.session_id)
                {
                    queue
                        .recorded
                        .insert(sandbox_id.to_string(), result.clone());
                }
                drop(queue);
                record_write("policy_result", "written");
            }
            Err(error) if error.code() == tonic::Code::NotFound => {
                state
                    .config_delivery
                    .results
                    .queue()
                    .recorded
                    .remove(sandbox_id);
                // The sandbox or its revision is gone; nothing left to record.
                debug!(sandbox_id, version = result.version, error = %error, "dropped policy result for a missing revision");
                record_write("policy_result", "dropped");
            }
            Err(error) => {
                queued.attempts += 1;
                if queued.attempts < MAX_WRITE_ATTEMPTS {
                    record_write("policy_result", "retried");
                    retry.policy_results.push(queued);
                } else {
                    warn!(sandbox_id, version = result.version, error = %error, "failed to persist supervisor policy result");
                    record_write("policy_result", "dropped");
                    reopen_for_redelivery(state, sandbox_id, &queued.session_id);
                }
            }
        }
    }
    if let Some(mut queued) = pending.admission {
        if !state
            .supervisor_sessions
            .is_current_session(sandbox_id, &queued.session_id)
        {
            // A newer session reports its own admission.
            record_write("admission", "stale_session");
            return retry;
        }
        match state
            .compute
            .supervisor_session_admission(sandbox_id, &queued.instance_id, &queued.admission)
            .await
        {
            Ok(()) => record_write("admission", "written"),
            Err(error) => {
                queued.attempts += 1;
                if queued.attempts < MAX_WRITE_ATTEMPTS {
                    record_write("admission", "retried");
                    retry.admission = Some(queued);
                } else {
                    warn!(sandbox_id, session_id = %queued.session_id, error = %error, "failed to persist supervisor configuration admission");
                    record_write("admission", "dropped");
                    reopen_for_redelivery(state, sandbox_id, &queued.session_id);
                }
            }
        }
    }
    retry
}

/// Both kinds of result come from a sandbox configuration update. A replaced
/// session is left alone; its replacement's bootstrap reports them again.
fn reopen_for_redelivery(state: &ServerState, sandbox_id: &str, session_id: &str) {
    state.supervisor_sessions.reopen_config_component(
        sandbox_id,
        session_id,
        ConfigComponentKind::SandboxConfig,
    );
}

fn record_write(kind: &'static str, outcome: &'static str) {
    counter!(
        "openshell_supervisor_config_result_writes_total",
        "kind" => kind,
        "outcome" => outcome,
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    include!("result_writer_regression_tests.rs");

    #[test]
    fn queue_keeps_first_seen_order_and_one_entry_per_sandbox() {
        let mut queue = Queue::default();
        queue.entry("a").policy_results.push(QueuedPolicyResult {
            session_id: "session-1".into(),
            result: PolicyResult {
                version: 1,
                loaded: true,
                error: None,
            },
            attempts: 0,
        });
        queue.entry("b");
        queue.entry("a").policy_results.push(QueuedPolicyResult {
            session_id: "session-1".into(),
            result: PolicyResult {
                version: 2,
                loaded: true,
                error: None,
            },
            attempts: 0,
        });
        assert_eq!(
            queue.order,
            VecDeque::from(["a".to_string(), "b".to_string()])
        );
        assert_eq!(queue.pending["a"].policy_results.len(), 2);
    }

    #[test]
    fn repeated_policy_results_are_duplicates_until_another_is_queued() {
        let loaded = |version| PolicyResult {
            version,
            loaded: true,
            error: None,
        };
        let mut queue = Queue::default();
        queue.recorded.insert("a".into(), loaded(3));
        assert!(queue.is_duplicate_policy_result("a", &loaded(3)));
        assert!(!queue.is_duplicate_policy_result("a", &loaded(4)));
        assert!(!queue.is_duplicate_policy_result("b", &loaded(3)));

        // Once version 4 is queued, version 3 settles a different state again.
        queue.entry("a").policy_results.push(QueuedPolicyResult {
            session_id: "session-1".into(),
            result: loaded(4),
            attempts: 0,
        });
        assert!(queue.is_duplicate_policy_result("a", &loaded(4)));
        assert!(!queue.is_duplicate_policy_result("a", &loaded(3)));
    }

    #[test]
    fn results_queued_during_a_failed_write_wait_behind_its_retry() {
        let queued = |version| QueuedPolicyResult {
            session_id: "session-1".into(),
            result: PolicyResult {
                version,
                loaded: true,
                error: None,
            },
            attempts: 0,
        };
        let versions = |pending: &PendingWrites| {
            pending
                .policy_results
                .iter()
                .map(|queued| queued.result.version)
                .collect::<Vec<_>>()
        };
        let now = Instant::now();
        let mut queue = Queue::default();
        queue.entry("a").policy_results.push(queued(1));
        queue.entry("b").policy_results.push(queued(1));
        let Next::Write(sandbox_id, mut pending) = queue.next(now) else {
            panic!("a is ready");
        };
        assert_eq!(sandbox_id, "a");

        // Version 2 arrives while version 1 is written, and version 1 fails.
        queue.entry("a").policy_results.push(queued(2));
        pending.policy_results[0].attempts = 1;
        queue.finish("a", pending, now + RETRY_DELAY);

        let Next::Write(sandbox_id, _) = queue.next(now) else {
            panic!("b does not wait for a's retry");
        };
        assert_eq!(sandbox_id, "b");
        queue.finish("b", PendingWrites::default(), now + RETRY_DELAY);
        assert!(matches!(queue.next(now), Next::WaitUntil(at) if at == now + RETRY_DELAY));

        let Next::Write(sandbox_id, pending) = queue.next(now + RETRY_DELAY) else {
            panic!("a's retry is due");
        };
        assert_eq!(sandbox_id, "a");
        assert_eq!(versions(&pending), [1, 2]);
        queue.finish("a", PendingWrites::default(), now + RETRY_DELAY);
        assert!(matches!(queue.next(now + RETRY_DELAY), Next::Idle));
        assert!(!queue.running);
    }

    #[test]
    fn claim_start_returns_true_only_for_the_first_caller() {
        let mut queue = Queue::default();
        assert!(queue.claim_start());
        assert!(!queue.claim_start());
    }
}
