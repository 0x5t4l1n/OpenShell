// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Conformance suite: sandbox-lifecycle.

use testkit::Context;
use testkit::sdk::{SandboxPhase, SandboxRestartPolicy};

/// A long-running sandbox becomes ready, runs a command with exec, and is gone
/// from get and list after delete.
#[testkit::test(id = "t-3tfdx240")]
async fn long_running_exec_delete(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("lr")
        .command(["sleep", "infinity"])
        .create()
        .await?;
    sandbox.wait_ready().await?;

    let marker = format!("openshell-conformance-{}", cx.run_id());
    let output = sandbox.exec(["echo", marker.as_str()]).await?;
    testkit::ensure!(
        output.exit_code == 0,
        "exec exited with {}; stderr: {}",
        output.exit_code,
        output.stderr
    );
    testkit::ensure!(
        output.stdout == format!("{marker}\n"),
        "exec stdout was {:?}; expected {:?}",
        output.stdout,
        format!("{marker}\n")
    );

    sandbox.delete().await?;
    cx.expect_absent(&sandbox).await
}

/// A sandbox whose main command exits 0, with restart policy Never, reaches
/// Completed with exit code 0 and is not restarted. It is gone from get and
/// list after delete.
#[testkit::test(id = "t-nyiaw3g8")]
async fn run_to_completion_exit_delete(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("rtc")
        .command(["sh", "-c", "exit 0"])
        .restart_policy(SandboxRestartPolicy::Never)
        .create()
        .await?;

    let finished = sandbox.wait_finished().await?;
    testkit::ensure!(
        finished.phase == SandboxPhase::Completed,
        "sandbox finished in phase {:?} with exit code {:?}; expected Completed",
        finished.phase,
        finished.exit_code
    );
    testkit::ensure!(
        finished.exit_code == Some(0),
        "exit code was {:?}; expected Some(0)",
        finished.exit_code
    );
    testkit::ensure!(
        finished.restart_count == 0,
        "restart count was {}; expected 0",
        finished.restart_count
    );

    // Completed is final under Never: a later read must not show a restart.
    let again = sandbox.get().await?;
    testkit::ensure!(
        again.phase == SandboxPhase::Completed && again.restart_count == 0,
        "sandbox left Completed: phase {:?}, restart count {}",
        again.phase,
        again.restart_count
    );

    sandbox.delete().await?;
    cx.expect_absent(&sandbox).await
}
