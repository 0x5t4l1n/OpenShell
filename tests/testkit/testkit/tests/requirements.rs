// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A test that declares `requires` fails when the environment does not
//! provide the capability, before it looks for a gateway.
//!
//! `#[testkit::test]` rejects `#[should_panic]`, so these call `testkit::run`
//! directly and check the panic it raises. They need
//! `OPENSHELL_TEST_CAPABILITIES` to be unset or not to list the capabilities
//! below, which is the case wherever the testkit unit tests run.

use std::any::Any;
use std::panic::AssertUnwindSafe;

use futures::FutureExt as _;
use testkit::{Capability, Context, TestInfo};

/// The message of a panic raised by `testkit::run`.
fn message(payload: Box<dyn Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => payload
            .downcast_ref::<&str>()
            .map(|message| (*message).to_string())
            .unwrap_or_default(),
    }
}

async fn run_requiring(requires: &'static [Capability]) -> String {
    let info = TestInfo {
        name: "requires",
        id: Some("t-0a1b2c3d"),
        description: "Declares requirements the environment does not provide.",
        requires,
    };
    let outcome = AssertUnwindSafe(testkit::run(info, async |_cx: &mut Context| Ok(())))
        .catch_unwind()
        .await;
    message(outcome.expect_err("a test whose requirements are missing must fail"))
}

#[tokio::test]
async fn requirement_not_provided_fails_the_test() {
    let message = run_requiring(&[Capability::Gpu]).await;
    assert!(message.contains("requires gpu"), "{message}");
}

#[tokio::test]
async fn every_missing_requirement_is_named() {
    let message =
        run_requiring(&[Capability::ServiceExposure, Capability::PersistentWorkspace]).await;
    assert!(
        message.contains("requires service_exposure, persistent_workspace"),
        "{message}"
    );
}
