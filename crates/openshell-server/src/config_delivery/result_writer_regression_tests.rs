// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

async fn regression_state_with_policy(sandbox_id: &str) -> Arc<ServerState> {
    use crate::policy_store::PolicyStoreExt as _;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{Sandbox, SandboxPolicy};
    use prost::Message as _;

    let state = crate::grpc::test_support::test_server_state().await;
    state
        .store
        .put_message(&Sandbox {
            metadata: Some(ObjectMeta {
                id: sandbox_id.into(),
                name: sandbox_id.into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    state
        .store
        .put_policy_revision(
            &format!("policy-{sandbox_id}"),
            sandbox_id,
            "default",
            1,
            &SandboxPolicy::default().encode_to_vec(),
            "policy-hash",
        )
        .await
        .unwrap();
    state
}

fn regression_queue_policy(state: &ServerState, sandbox_id: &str) {
    state
        .config_delivery
        .results
        .queue()
        .entry(sandbox_id)
        .policy_results
        .push(QueuedPolicyResult {
            session_id: "session-1".into(),
            result: PolicyResult {
                version: 1,
                loaded: true,
                error: None,
            },
            attempts: 0,
        });
}

#[tokio::test]
async fn config_push_regression_failed_write_does_not_block_healthy_results() {
    use crate::policy_store::PolicyStoreExt as _;
    use openshell_core::proto::Sandbox;

    let failing_id = "sb-failing-result";
    let healthy_id = "sb-healthy-result";
    let state = regression_state_with_policy(failing_id).await;
    let mut healthy = state
        .store
        .get_message::<Sandbox>(failing_id)
        .await
        .unwrap()
        .unwrap();
    healthy.metadata.as_mut().unwrap().id = healthy_id.into();
    healthy.metadata.as_mut().unwrap().name = healthy_id.into();
    state.store.put_message(&healthy).await.unwrap();
    let original = state
        .store
        .get_policy_by_version(failing_id, 1)
        .await
        .unwrap()
        .unwrap();
    state
        .store
        .put_policy_revision(
            "policy-healthy",
            healthy_id,
            "default",
            1,
            &original.policy_payload,
            &original.policy_hash,
        )
        .await
        .unwrap();
    state
        .store
        .execute_for_test(
            r#"
CREATE TRIGGER fail_one_result BEFORE UPDATE ON "objects"
WHEN OLD."object_type" = 'sandbox_policy' AND OLD."scope" = 'sb-failing-result'
BEGIN SELECT RAISE(ABORT, 'injected failure for one sandbox'); END;
"#,
        )
        .await;
    regression_queue_policy(&state, failing_id);
    regression_queue_policy(&state, healthy_id);
    assert!(state.config_delivery.results.queue().claim_start());

    // Keep virtual time still while SQLite's worker threads make progress.
    // The healthy result must drain without waiting for A's retry timer.
    let keep_clock_running = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    tokio::time::pause();
    let writer = tokio::spawn(run(Arc::clone(&state)));
    let checking_state = Arc::clone(&state);
    let healthy_result = tokio::spawn(async move {
        loop {
            let record = checking_state
                .store
                .get_policy_by_version(healthy_id, 1)
                .await
                .unwrap()
                .unwrap();
            if record.status == "loaded" {
                return;
            }
            tokio::task::yield_now().await;
        }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !healthy_result.is_finished() && std::time::Instant::now() < deadline {
        tokio::task::yield_now().await;
    }
    let healthy_finished = healthy_result.is_finished();
    writer.abort();
    healthy_result.abort();
    keep_clock_running.abort();
    let _ = writer.await;
    let _ = healthy_result.await;
    let _ = keep_clock_running.await;
    tokio::time::resume();
    assert!(
        healthy_finished,
        "a failed sandbox's retry timer must not block another sandbox's policy result"
    );
}

#[tokio::test]
async fn config_push_regression_session_end_evicts_recorded_policy_result() {
    use openshell_core::proto::Sandbox;

    let sandbox_id = "sb-deleted-result";
    let state = regression_state_with_policy(sandbox_id).await;
    let sandbox = state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .unwrap()
        .unwrap();
    let _session =
        crate::config_delivery::register_test_apply_session(&state, &sandbox, "session-1");
    regression_queue_policy(&state, sandbox_id);
    assert!(state.config_delivery.results.queue().claim_start());
    run(Arc::clone(&state)).await;
    assert!(
        state
            .config_delivery
            .results
            .queue()
            .recorded
            .contains_key(sandbox_id)
    );

    // Deleting a sandbox ends its session on the replica that holds it.
    crate::config_delivery::unregister_session(&state, sandbox_id, "session-1");
    assert!(
        !state
            .config_delivery
            .results
            .queue()
            .recorded
            .contains_key(sandbox_id),
        "an ended session must remove its result from the deduplication cache"
    );
}

#[tokio::test]
async fn config_push_regression_result_of_an_ended_session_is_not_recorded() {
    let sandbox_id = "sb-ended-session-result";
    let state = regression_state_with_policy(sandbox_id).await;
    // The result was queued by session-1, which unregistered before the
    // write finished.
    regression_queue_policy(&state, sandbox_id);
    assert!(state.config_delivery.results.queue().claim_start());
    run(Arc::clone(&state)).await;
    assert!(
        !state
            .config_delivery
            .results
            .queue()
            .recorded
            .contains_key(sandbox_id)
    );
}
