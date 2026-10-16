// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Wait until the target's gateway is ready for tests.
//!
//! Usage: `testkit-ready [TIMEOUT_SECS]` (default 60), with the target file
//! named by `OPENSHELL_TEST_TARGET`. Run it once per environment before the
//! test binaries; exits non-zero with the last error if the gateway is not
//! healthy in time.

use std::process::ExitCode;
use std::time::Duration;

use testkit::Target;

const DEFAULT_TIMEOUT_SECS: u64 = 60;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let timeout = match std::env::args().nth(1).map(|arg| arg.parse::<u64>()) {
        None => DEFAULT_TIMEOUT_SECS,
        Some(Ok(secs)) => secs,
        Some(Err(error)) => {
            eprintln!("testkit-ready: invalid timeout: {error}");
            return ExitCode::from(2);
        }
    };
    let result = match Target::from_env() {
        Ok(target) => target.wait_ready(Duration::from_secs(timeout)).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(health) => {
            eprintln!("testkit-ready: gateway {} is healthy", health.version);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("testkit-ready: {error}");
            ExitCode::FAILURE
        }
    }
}
