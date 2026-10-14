// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn assert_push_startup_preserves_non_secret_values(reason: ProviderReadinessReason) {
    let mut provider = tests::startup_provider(10);
    provider.readiness_reason = reason;
    provider
        .environment
        .insert("PROJECT_ID".into(), "example-project".into());
    provider
        .non_secret_environment_keys
        .push("PROJECT_ID".into());

    let polling = prepare_provider_environment(&provider).expect("valid withheld environment");
    let polling_environment = polling.snapshot().child_env.clone();
    assert!(
        polling_environment.contains_key("PROJECT_ID"),
        "the existing polling path preserves the non-secret value"
    );

    let pushed = initial_provider_credentials(provider, &ProviderReadinessTracker::new());
    assert_eq!(
        pushed.snapshot().child_env,
        polling_environment,
        "withholding credentials must not remove non-secret workload configuration"
    );
}

#[test]
fn config_push_regression_startup_preserves_non_secret_values_with_withheld_credentials() {
    assert_push_startup_preserves_non_secret_values(ProviderReadinessReason::CredentialsWithheld);
}

#[test]
fn config_push_regression_startup_preserves_non_secret_values_with_expired_credentials() {
    assert_push_startup_preserves_non_secret_values(ProviderReadinessReason::CredentialExpired);
}
