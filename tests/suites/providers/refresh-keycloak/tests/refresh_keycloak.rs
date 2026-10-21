// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

//! Provider OAuth refresh recovery against Keycloak.
//!
//! OpenShell itself uses the local gateway's mTLS authentication. Keycloak is
//! only the provider token issuer: the test refreshes a valid grant, revokes
//! its Keycloak session, and verifies that the gateway reports the next
//! refresh as requiring user reauthorization.

use std::io::Write as _;
use std::process::Stdio;

use serde_json::Value;
use tempfile::{Builder as TempFileBuilder, NamedTempFile};
use testkit::{CliOutput, Context, Error, ResultExt as _};
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

const CREDENTIAL_KEY: &str = "KEYCLOAK_ACCESS_TOKEN";

fn combined_output(output: &CliOutput) -> String {
    format!("{}{}", output.stdout, output.stderr)
}

fn required_env(name: &str) -> testkit::Result<String> {
    std::env::var(name).map_err(|_| Error::msg(format!("{name} is required")))
}

/// Run the CLI and return stdout and stderr together; fail on a non-zero exit.
async fn cli_success(cx: &Context, args: &[&str], env: &[(&str, &str)]) -> testkit::Result<String> {
    let output = cx.cli_env(env, args.iter().copied()).await?.success()?;
    Ok(combined_output(&output))
}

async fn acquire_keycloak_grant(
    issuer: &str,
    username: &str,
    password: &str,
) -> testkit::Result<(String, String)> {
    let token_endpoint = format!("{issuer}/protocol/openid-connect/token");
    let username_form = format!("username={username}");
    let password_form = format!("password={password}");
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--request",
            "POST",
            &token_endpoint,
            "--data-urlencode",
            "grant_type=password",
            "--data-urlencode",
            "client_id=openshell-cli",
            "--data-urlencode",
            &username_form,
            "--data-urlencode",
            &password_form,
            "--data-urlencode",
            "scope=openid",
        ])
        .output()
        .await
        .map_err(|error| Error::from_error(&error))
        .context("request Keycloak grant")?;
    testkit::ensure!(
        output.status.success(),
        "Keycloak grant request failed (exit {:?}): {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let response: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| Error::from_error(&error))
        .context("decode Keycloak grant response")?;
    let access_token = response
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::msg("Keycloak grant response omitted access_token"))?;
    let refresh_token = response
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::msg("Keycloak grant response omitted refresh_token"))?;
    Ok((access_token.to_string(), refresh_token.to_string()))
}

async fn revoke_keycloak_grant(issuer: &str, refresh_token: &str) -> testkit::Result {
    let logout_endpoint = format!("{issuer}/protocol/openid-connect/logout");
    let mut child = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--output",
            "/dev/null",
            "--request",
            "POST",
            &logout_endpoint,
            "--data-urlencode",
            "client_id=openshell-cli",
            "--data-urlencode",
            "refresh_token@-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Error::from_error(&error))
        .context("start Keycloak logout request")?;
    child
        .stdin
        .take()
        .ok_or_else(|| Error::msg("Keycloak logout stdin was not piped"))?
        .write_all(refresh_token.as_bytes())
        .await
        .map_err(|error| Error::from_error(&error))
        .context("write Keycloak logout request")?;
    let output = child
        .wait_with_output()
        .await
        .map_err(|error| Error::from_error(&error))
        .context("wait for Keycloak logout request")?;
    testkit::ensure!(
        output.status.success(),
        "Keycloak logout failed (exit {:?}): {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn write_profile(profile_id: &str, issuer: &str) -> testkit::Result<NamedTempFile> {
    let mut file = TempFileBuilder::new()
        .suffix(".yaml")
        .tempfile()
        .map_err(|error| Error::from_error(&error))
        .context("create provider profile")?;
    let profile = format!(
        r#"id: {profile_id}
display_name: Keycloak provider refresh E2E
category: other
credentials:
  - name: access_token
    env_vars: [{CREDENTIAL_KEY}]
    required: true
    auth_style: bearer
    header_name: authorization
    refresh:
      strategy: oauth2_refresh_token
      token_url: {issuer}/protocol/openid-connect/token
      scopes: [openid]
      refresh_before_seconds: 60
      max_lifetime_seconds: 3600
      material:
        - name: client_id
          required: true
        - name: refresh_token
          required: true
          secret: true
endpoints:
  - host: keycloak.test.invalid
    port: 443
    protocol: rest
    access: read-only
    enforcement: enforce
binaries:
  - /usr/bin/curl
"#
    );
    file.write_all(profile.as_bytes())
        .map_err(|error| Error::from_error(&error))
        .context("write provider profile")?;
    file.flush()
        .map_err(|error| Error::from_error(&error))
        .context("flush provider profile")?;
    Ok(file)
}

/// Testkit does not clean up providers or profiles, so delete them here. A
/// failure to delete is ignored: after a failed run they may not exist.
async fn delete_provider_resources(cx: &Context, provider: &str, profile_id: &str) {
    let _ = cx.cli(["provider", "delete", provider]).await;
    let _ = cx.cli(["profile", "delete", profile_id]).await;
}

/// A refresh grant revoked in Keycloak makes the next rotation fail with
/// invalid_grant, and the gateway then reports the credential as requiring
/// user reauthorization.
#[testkit::test]
async fn revoked_refresh_grant_requires_user_reauthorization(cx: &mut Context) -> testkit::Result {
    let issuer = required_env("OPENSHELL_E2E_OIDC_ISSUER")?;
    let username = required_env("OPENSHELL_E2E_OIDC_USERNAME")?;
    let password = required_env("OPENSHELL_E2E_OIDC_PASSWORD")?;
    let (access_token, refresh_token) =
        acquire_keycloak_grant(&issuer, &username, &password).await?;
    let provider = cx.name("keycloak-refresh");
    let profile_id = provider.clone();
    let profile = write_profile(&profile_id, &issuer)?;
    let profile_path = profile.path().to_string_lossy().into_owned();

    delete_provider_resources(cx, &provider, &profile_id).await;
    let result = async {
        cli_success(cx, &["profile", "import", "--file", &profile_path], &[]).await?;
        cli_success(
            cx,
            &[
                "provider",
                "create",
                "--name",
                &provider,
                "--type",
                &profile_id,
                "--credential",
                CREDENTIAL_KEY,
            ],
            &[(CREDENTIAL_KEY, &access_token)],
        )
        .await?;
        cli_success(
            cx,
            &[
                "provider",
                "refresh",
                "configure",
                &provider,
                "--credential-key",
                CREDENTIAL_KEY,
                "--strategy",
                "oauth2-refresh-token",
                "--material",
                "client_id=openshell-cli",
                "--secret-material-env",
                "refresh_token=KEYCLOAK_REFRESH_TOKEN",
            ],
            &[("KEYCLOAK_REFRESH_TOKEN", &refresh_token)],
        )
        .await?;

        let rotate = [
            "provider",
            "refresh",
            "rotate",
            provider.as_str(),
            "--credential-key",
            CREDENTIAL_KEY,
        ];
        let status = [
            "provider",
            "refresh",
            "status",
            provider.as_str(),
            "--credential-key",
            CREDENTIAL_KEY,
        ];

        cli_success(cx, &rotate, &[]).await?;
        let valid_status = cli_success(cx, &status, &[]).await?;
        testkit::ensure!(
            valid_status.contains("refreshed"),
            "valid Keycloak refresh did not reach refreshed state:\n{valid_status}"
        );

        revoke_keycloak_grant(&issuer, &refresh_token).await?;
        let failed_rotation = cx.cli(rotate).await?;
        let failed_rotation_output = combined_output(&failed_rotation);
        testkit::ensure!(
            failed_rotation.exit_code != 0 && failed_rotation_output.contains("invalid_grant"),
            "revoked Keycloak refresh did not fail with invalid_grant:\n{failed_rotation_output}"
        );

        let revoked_status = cli_success(cx, &status, &[]).await?;
        for expected in [
            "reauthorization_required",
            "reauthorize",
            "oauth_invalid_grant",
        ] {
            testkit::ensure!(
                revoked_status.contains(expected),
                "revoked refresh status omitted {expected}:\n{revoked_status}"
            );
        }
        testkit::ensure!(
            !revoked_status.contains("292278994"),
            "parked refresh rendered the i64::MAX scheduling sentinel as a date:\n{revoked_status}"
        );
        Ok(())
    }
    .await;

    delete_provider_resources(cx, &provider, &profile_id).await;
    result
}
