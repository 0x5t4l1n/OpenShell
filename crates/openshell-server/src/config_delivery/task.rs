// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! One delivery task per push session.
//!
//! A publication only marks the components a session must rebuild, so
//! repeated publications coalesce into one build. The session's task takes
//! the marks after it holds a build permit, so every build reads state at
//! least as new as every publication it covers.
//!
//! Build permits come from one FIFO semaphore sized from the database pool.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use metrics::{Gauge, gauge, histogram};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use super::ConfigComponents;

/// How often a session rebuilds its sandbox configuration, any component
/// its supervisor failed to apply, and both halves of a staged deadlock, to
/// repair a missed publication or retry a failure that may have cleared. A session first reconciles one to two intervals after it
/// registers, at a random offset, so reconciliation is a steady trickle
/// rather than a burst and never repeats the bootstrap it just applied.
pub(super) const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const MIN_FAILURE_BACKOFF: Duration = Duration::from_secs(1);
const MAX_FAILURE_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FanoutScope {
    AllConnected,
    Workspace(String),
    /// Sandboxes in `workspace` that attach the named provider.
    Provider {
        workspace: String,
        name: String,
    },
}

/// A push session as the delivery task sees it.
#[derive(Debug, Clone)]
pub struct Registration {
    pub sandbox_id: String,
    pub session_id: String,
    pub workspace: String,
    pub providers: HashSet<String>,
    /// [`super::ConfigDelivery::publications`] observed before the bootstrap
    /// inputs were read.
    pub captured_seq: u64,
}

#[derive(Debug)]
pub(super) struct SessionRecord {
    pub(super) sandbox_id: String,
    pub(super) session_id: String,
    workspace: String,
    marks: Mutex<Marks>,
    wake: Notify,
}

#[derive(Debug, Default)]
struct Marks {
    dirty: ConfigComponents,
    dirty_since: Option<Instant>,
    dirty_gauge: Option<GaugeGuard>,
    /// Attachments read by the last build, for provider-scoped fanouts.
    providers: HashSet<String>,
    /// A running build may install a new attachment, so provider fanouts
    /// include the session until it finishes.
    building: bool,
    closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Closed,
    Clean,
    Dirty,
}

impl SessionRecord {
    pub(super) fn new(registration: Registration) -> Self {
        Self {
            sandbox_id: registration.sandbox_id,
            session_id: registration.session_id,
            workspace: registration.workspace,
            marks: Mutex::new(Marks {
                providers: registration.providers,
                ..Marks::default()
            }),
            wake: Notify::new(),
        }
    }

    /// Delivery is best effort beside the session lifecycle, so a poisoned
    /// lock must not turn session teardown into a panic.
    fn marks(&self) -> MutexGuard<'_, Marks> {
        self.marks.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wakes the task only when the session becomes dirty, so a waiter keeps
    /// its place in the permit queue.
    pub(super) fn mark(&self, components: ConfigComponents) {
        if self.add_marks(components) {
            self.wake.notify_one();
        }
    }

    /// Returns whether the session became dirty.
    fn add_marks(&self, components: ConfigComponents) -> bool {
        let mut marks = self.marks();
        if marks.closed || components.is_empty() {
            return false;
        }
        let became_dirty = marks.dirty.is_empty();
        if became_dirty {
            marks.dirty_since = Some(Instant::now());
            marks.dirty_gauge = Some(GaugeGuard::acquire(gauge!(DIRTY_SESSIONS)));
        }
        marks.dirty = marks.dirty.union(components);
        became_dirty
    }

    pub(super) fn close(&self) {
        let mut marks = self.marks();
        marks.closed = true;
        marks.dirty = ConfigComponents::default();
        marks.dirty_gauge = None;
        drop(marks);
        self.wake.notify_one();
    }

    pub(super) fn in_scope(&self, scope: &FanoutScope) -> bool {
        match scope {
            FanoutScope::AllConnected => true,
            FanoutScope::Workspace(workspace) => self.workspace == *workspace,
            FanoutScope::Provider { workspace, name } => {
                self.workspace == *workspace && {
                    let marks = self.marks();
                    marks.building || marks.providers.contains(name)
                }
            }
        }
    }

    fn status(&self) -> Status {
        let marks = self.marks();
        if marks.closed {
            Status::Closed
        } else if marks.dirty.is_empty() {
            Status::Clean
        } else {
            Status::Dirty
        }
    }

    /// Take the marked components once a build permit is held.
    fn take(&self) -> Option<ConfigComponents> {
        let mut marks = self.marks();
        if marks.dirty.is_empty() {
            return None;
        }
        let components = std::mem::take(&mut marks.dirty);
        marks.dirty_gauge = None;
        marks.building = true;
        if let Some(since) = marks.dirty_since.take() {
            histogram!("openshell_supervisor_config_queue_wait_seconds")
                .record(since.elapsed().as_secs_f64());
        }
        Some(components)
    }

    fn finish(&self, providers: Option<HashSet<String>>) {
        let mut marks = self.marks();
        marks.building = false;
        if let Some(providers) = providers {
            marks.providers = providers;
        }
    }
}

/// Wait for a build permit while the session is dirty, or return `None` once
/// the session closed.
pub(super) async fn acquire_permit(
    builds: &Arc<Semaphore>,
    record: &SessionRecord,
) -> Option<OwnedSemaphorePermit> {
    loop {
        match record.status() {
            Status::Closed => return None,
            Status::Dirty => tokio::select! {
                permit = Arc::clone(builds).acquire_owned() => {
                    return Some(permit.expect("the build semaphore is never closed"));
                }
                () = record.wake.notified() => {}
            },
            Status::Clean => record.wake.notified().await,
        }
    }
}

/// Build and deliver one taken set of components. Returns the components
/// whose build failed and the attachments the builds read.
pub(super) trait Deliver: Sync {
    fn deliver(
        &self,
        record: &SessionRecord,
        components: ConfigComponents,
    ) -> impl Future<Output = (ConfigComponents, Option<HashSet<String>>)> + Send;

    /// Components reconciliation rebuilds beyond the sandbox configuration:
    /// ones the supervisor failed to apply, and halves staged waiting for
    /// each other.
    fn repair(&self, record: &SessionRecord) -> ConfigComponents;
}

/// Run a session's deliveries until it closes, rebuilding its sandbox
/// configuration and any component needing repair every `reconcile_interval`.
pub(super) async fn run(
    record: Arc<SessionRecord>,
    builds: &Arc<Semaphore>,
    deliver: &impl Deliver,
    reconcile_interval: Duration,
) {
    let mut failures = 0u32;
    let mut next_reconcile = Instant::now() + reconcile_interval + jitter(reconcile_interval);
    loop {
        loop {
            match record.status() {
                Status::Closed => return,
                Status::Dirty => break,
                Status::Clean => {}
            }
            tokio::select! {
                () = record.wake.notified() => {}
                () = tokio::time::sleep_until(next_reconcile) => {
                    next_reconcile = Instant::now() + reconcile_interval;
                    let components = ConfigComponents::SANDBOX_CONFIG.union(deliver.repair(&record));
                    record.mark(components);
                }
            }
        }
        let Some(permit) = acquire_permit(builds, &record).await else {
            return;
        };
        let Some(components) = record.take() else {
            continue;
        };
        let (failed, providers) = deliver.deliver(&record, components).await;
        drop(permit);
        record.finish(providers);
        if failed.is_empty() {
            failures = 0;
            continue;
        }
        // A new publication or session close ends the backoff early.
        let retry_at = Instant::now() + failure_backoff(failures);
        loop {
            tokio::select! {
                () = tokio::time::sleep_until(retry_at) => break,
                () = record.wake.notified() => {
                    if record.status() != Status::Clean {
                        break;
                    }
                }
            }
        }
        failures = failures.saturating_add(1);
        // The task is awake, so the retry needs no wakeup.
        record.add_marks(failed);
    }
}

fn failure_backoff(failures: u32) -> Duration {
    MIN_FAILURE_BACKOFF
        .saturating_mul(1 << failures.min(5))
        .min(MAX_FAILURE_BACKOFF)
}

fn jitter(interval: Duration) -> Duration {
    let millis = u64::try_from(interval.as_millis())
        .unwrap_or(u64::MAX)
        .max(1);
    Duration::from_millis(rand::random_range(0..millis))
}

const DIRTY_SESSIONS: &str = "openshell_supervisor_config_dirty_sessions";

/// One unit of a gauge, released through the same handle when dropped.
#[derive(Debug)]
struct GaugeGuard(Gauge);

impl GaugeGuard {
    fn acquire(gauge: Gauge) -> Self {
        gauge.increment(1.0);
        Self(gauge)
    }
}

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.0.decrement(1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_delivery::ConfigComponentKind;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Long enough that the reconcile timer never fires in a test that does
    /// not ask for it.
    const NO_RECONCILE: Duration = Duration::from_hours(24);

    fn record(sandbox_id: &str, workspace: &str, providers: &[&str]) -> Arc<SessionRecord> {
        Arc::new(SessionRecord::new(Registration {
            sandbox_id: sandbox_id.to_string(),
            session_id: format!("{sandbox_id}-session"),
            workspace: workspace.to_string(),
            providers: providers.iter().map(ToString::to_string).collect(),
            captured_seq: 0,
        }))
    }

    fn builds(permits: usize) -> Arc<Semaphore> {
        Arc::new(Semaphore::new(permits))
    }

    /// Records each delivery and fails the components in `fail`. Reports the
    /// components in `rejected` as rejected by the supervisor.
    #[derive(Default)]
    struct Recorder {
        delivered: Mutex<Vec<ConfigComponents>>,
        fail: Mutex<ConfigComponents>,
        rejected: Mutex<ConfigComponents>,
        gate: Option<Arc<Semaphore>>,
        calls: AtomicUsize,
    }

    impl Deliver for Recorder {
        async fn deliver(
            &self,
            _record: &SessionRecord,
            components: ConfigComponents,
        ) -> (ConfigComponents, Option<HashSet<String>>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = &self.gate {
                gate.acquire().await.unwrap().forget();
            }
            self.delivered.lock().unwrap().push(components);
            (*self.fail.lock().unwrap(), None)
        }

        fn repair(&self, _record: &SessionRecord) -> ConfigComponents {
            *self.rejected.lock().unwrap()
        }
    }

    impl Recorder {
        fn delivered(&self) -> Vec<ConfigComponents> {
            self.delivered.lock().unwrap().clone()
        }
    }

    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[test]
    fn marks_coalesce_until_taken() {
        let record = record("sb", "ws", &[]);
        assert!(record.add_marks(ConfigComponents::SANDBOX_CONFIG));
        assert!(!record.add_marks(ConfigComponents::SANDBOX_CONFIG));
        assert!(!record.add_marks(ConfigComponents::only(
            ConfigComponentKind::ProviderEnvironment
        )));
        assert_eq!(record.take(), Some(ConfigComponents::ALL));
        assert_eq!(record.take(), None);
    }

    #[test]
    fn provider_scope_includes_attached_or_building_sessions() {
        let attached = record("a", "ws", &["github"]);
        let other = record("b", "ws", &[]);
        let scope = FanoutScope::Provider {
            workspace: "ws".into(),
            name: "github".into(),
        };
        assert!(attached.in_scope(&scope));
        assert!(!other.in_scope(&scope));
        assert!(!record("c", "other", &["github"]).in_scope(&scope));

        other.mark(ConfigComponents::ALL);
        other.take().unwrap();
        assert!(other.in_scope(&scope), "a running build may attach it");
        other.finish(Some(HashSet::from(["github".to_string()])));
        assert!(other.in_scope(&scope));
        attached.finish(Some(HashSet::new()));
        assert!(!attached.in_scope(&scope));
    }

    #[tokio::test(start_paused = true)]
    async fn publications_during_a_build_coalesce_into_one_rebuild() {
        let builds = builds(4);
        let gate = Arc::new(Semaphore::new(0));
        let recorder = Arc::new(Recorder {
            gate: Some(Arc::clone(&gate)),
            ..Recorder::default()
        });
        let session = record("sb", "ws", &[]);
        session.mark(ConfigComponents::SANDBOX_CONFIG);
        let task = tokio::spawn({
            let session = Arc::clone(&session);
            let recorder = Arc::clone(&recorder);
            async move { run(session, &builds, recorder.as_ref(), NO_RECONCILE).await }
        });
        settle().await;
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 1);

        for _ in 0..5 {
            session.mark(ConfigComponents::SANDBOX_CONFIG);
        }
        session.mark(ConfigComponents::only(
            ConfigComponentKind::ProviderEnvironment,
        ));
        gate.add_permits(2);
        settle().await;
        assert_eq!(
            recorder.delivered(),
            [ConfigComponents::SANDBOX_CONFIG, ConfigComponents::ALL]
        );

        session.close();
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn failed_builds_retry_with_backoff_until_they_succeed() {
        let builds = builds(4);
        let recorder = Arc::new(Recorder::default());
        *recorder.fail.lock().unwrap() = ConfigComponents::SANDBOX_CONFIG;
        let session = record("sb", "ws", &[]);
        session.mark(ConfigComponents::SANDBOX_CONFIG);
        let task = tokio::spawn({
            let session = Arc::clone(&session);
            let recorder = Arc::clone(&recorder);
            async move { run(session, &builds, recorder.as_ref(), NO_RECONCILE).await }
        });
        settle().await;
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_millis(999)).await;
        settle().await;
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 1, "backs off 1 s");
        tokio::time::advance(Duration::from_millis(1)).await;
        settle().await;
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 2);

        *recorder.fail.lock().unwrap() = ConfigComponents::default();
        tokio::time::advance(Duration::from_secs(2)).await;
        settle().await;
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 3, "then 2 s");

        session.close();
        task.await.unwrap();
    }

    #[test]
    fn failure_backoff_doubles_up_to_thirty_seconds() {
        let backoff: Vec<_> = (0..7).map(|n| failure_backoff(n).as_secs()).collect();
        assert_eq!(backoff, [1, 2, 4, 8, 16, 30, 30]);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_sessions_reconcile_their_sandbox_configuration() {
        let builds = builds(4);
        let recorder = Arc::new(Recorder::default());
        let session = record("sb", "ws", &[]);
        let task = tokio::spawn({
            let session = Arc::clone(&session);
            let recorder = Arc::clone(&recorder);
            async move { run(session, &builds, recorder.as_ref(), RECONCILE_INTERVAL).await }
        });
        settle().await;

        tokio::time::advance(RECONCILE_INTERVAL).await;
        settle().await;
        assert!(recorder.delivered().is_empty(), "not right after bootstrap");
        tokio::time::advance(RECONCILE_INTERVAL).await;
        settle().await;
        assert_eq!(recorder.delivered(), [ConfigComponents::SANDBOX_CONFIG]);
        tokio::time::advance(RECONCILE_INTERVAL).await;
        settle().await;
        assert_eq!(recorder.delivered().len(), 2);

        session.close();
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn reconciliation_retries_rejected_components() {
        let builds = builds(4);
        let recorder = Arc::new(Recorder::default());
        *recorder.rejected.lock().unwrap() =
            ConfigComponents::only(ConfigComponentKind::ProviderEnvironment);
        let session = record("sb", "ws", &[]);
        let task = tokio::spawn({
            let session = Arc::clone(&session);
            let recorder = Arc::clone(&recorder);
            async move { run(session, &builds, recorder.as_ref(), RECONCILE_INTERVAL).await }
        });
        settle().await;

        tokio::time::advance(RECONCILE_INTERVAL * 2).await;
        settle().await;
        assert_eq!(recorder.delivered(), [ConfigComponents::ALL]);

        *recorder.rejected.lock().unwrap() = ConfigComponents::default();
        tokio::time::advance(RECONCILE_INTERVAL).await;
        settle().await;
        assert_eq!(recorder.delivered()[1], ConfigComponents::SANDBOX_CONFIG);

        session.close();
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn closing_a_session_ends_its_task_and_drops_its_marks() {
        let builds = builds(1);
        let _held = Arc::clone(&builds).acquire_owned().await.unwrap();
        let recorder = Arc::new(Recorder::default());
        let session = record("sb", "ws", &[]);
        session.mark(ConfigComponents::ALL);
        let task = tokio::spawn({
            let session = Arc::clone(&session);
            let builds = Arc::clone(&builds);
            let recorder = Arc::clone(&recorder);
            async move { run(session, &builds, recorder.as_ref(), NO_RECONCILE).await }
        });
        settle().await;

        session.close();
        task.await.unwrap();
        assert!(recorder.delivered().is_empty());
        session.mark(ConfigComponents::ALL);
        assert_eq!(session.take(), None);
    }
}
