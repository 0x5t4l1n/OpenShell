// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[tokio::test]
async fn config_push_regression_global_policy_repair_wakes_pending_startup() {
    use openshell_core::proto::UpdateConfigRequest;
    use openshell_core::proto::open_shell_server::OpenShell as _;

    let sandbox_id = "sb-global-startup-repair";
    let state = state_with_startup_policy(sandbox_id, None).await;
    let connecting_state = Arc::clone(&state);
    let mut connection = tokio::spawn(async move {
        build_session_bootstrap(
            &connecting_state,
            sandbox_id,
            &ImagePolicyAdmission::Invalid,
        )
        .await
    });

    // Wait for the actual rejection, not an arbitrary delay that could let
    // the global write overtake the bootstrap's first database reads.
    tokio::time::timeout(Duration::from_secs(5), async {
        while !STARTUP_REPAIR_WAITS.lock().unwrap().contains(sandbox_id) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("startup waits on the invalid image policy");

    let repaired_policy = openshell_policy::restrictive_default_policy();
    crate::grpc::OpenShellService::new(Arc::clone(&state))
        .update_config(crate::grpc::test_support::authed_request(
            UpdateConfigRequest {
                global: true,
                policy: Some(repaired_policy.clone()),
                ..Default::default()
            },
        ))
        .await
        .expect("operator saves a valid global policy");

    let repaired = tokio::time::timeout(Duration::from_secs(2), &mut connection).await;
    if repaired.is_err() {
        connection.abort();
        let _ = connection.await;
    }
    let bootstrap = repaired
        .expect("a global policy repair must wake startup without an unrelated sandbox update")
        .expect("startup task")
        .expect("valid repaired bootstrap");
    assert_eq!(
        bootstrap.sandbox_config.unwrap().policy,
        Some(repaired_policy)
    );
}

#[tokio::test]
async fn config_push_regression_admission_precedes_the_next_configuration() {
    use openshell_core::proto::ConfigurationAdmissionState;
    use tokio_stream::StreamExt as _;

    let sandbox_id = "sb-admission-order";
    let state = state_with_sandbox(sandbox_id).await;
    let (session_tx, _session_rx) = mpsc::channel(4);
    let (control_tx, control_rx) = mpsc::channel(4);
    let slots = Arc::new(ConfigSlots::default());
    state.supervisor_sessions.register_with_mode(
        sandbox_id.into(),
        "session-1".into(),
        session_tx.clone(),
        make_shutdown(),
        SessionMode::Push(Arc::clone(&slots)),
    );
    let mut outbound = SessionOutbound::new(control_rx, slots);
    let first_snapshot = sandbox_config(1);
    assert_eq!(
        state
            .supervisor_sessions
            .deliver_config(sandbox_id, "session-1", first_snapshot.clone()),
        DeliveryDisposition::Queued
    );
    let first_update = sent_update(outbound.next().await.unwrap().unwrap());
    assert_eq!(
        state
            .supervisor_sessions
            .deliver_config(sandbox_id, "session-1", sandbox_config(2)),
        DeliveryDisposition::Coalesced
    );
    let revision = config_message_revision(&first_snapshot);
    let result = ConfigUpdateResult {
        update_id: first_update.update_id,
        component_sequence: first_update.component_sequence,
        result: Some(ConfigComponentApplyResult {
            component: ConfigComponent::SandboxConfig.into(),
            requested_revision: Some(revision.clone()),
            applied_revision: Some(revision),
            outcome: ConfigApplyOutcome::Applied.into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let completed = state
        .supervisor_sessions
        .complete_config_update(sandbox_id, "session-1", &result)
        .unwrap();
    let admission = SandboxConfigurationAdmission {
        state: ConfigurationAdmissionState::Accepted.into(),
        config_revision: 1,
        ..Default::default()
    };
    // As on a real session, `tx` reaches the stream through a forwarder and
    // `control` is the stream's own control channel.
    let session = AcceptedSession {
        control: control_tx,
        ..accepted_session(&state, sandbox_id, session_tx)
    };
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), send_admission(&session, &admission))
            .await
            .expect("admission is queued"),
        AdmissionAck::Acknowledged
    ));
    state
        .supervisor_sessions
        .finalize_config_update(sandbox_id, "session-1", &completed, true);

    // Finalizing released the newer configuration. It must not overtake
    // the older admission on the public stream.
    let first_message = outbound.next().await.unwrap().unwrap();
    assert_eq!(
        first_message.payload,
        Some(gateway_message::Payload::ConfigurationAdmission(admission)),
        "startup approval must precede a subsequent configuration update on the public stream"
    );
    let second_update = sent_update(
        tokio::time::timeout(Duration::from_secs(2), outbound.next())
            .await
            .expect("the next configuration follows admission")
            .unwrap()
            .unwrap(),
    );
    let Some(config_update::Component::SandboxConfig(snapshot)) = second_update.component else {
        panic!("expected sandbox configuration");
    };
    assert_eq!(snapshot.config_revision, 2);
}
