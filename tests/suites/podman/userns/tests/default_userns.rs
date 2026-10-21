// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman-driver user-namespace integration tests.

mod support;

use std::fs;
use std::path::PathBuf;

use support::assert_podman_gateway;
use testkit::{Context, Error};

const PODMAN_TEST_INPUT_DIR_ENV: &str = "OPENSHELL_TEST_INPUT_DIR";
const PODMAN_TEST_IMAGE_ENV: &str = "OPENSHELL_PODMAN_TEST_IMAGE";

const WORKSPACE_AND_UID_MAP_PROBE: &str = r#"set -eu
workload_owner="$(id -u):$(id -g)"
workspace_owner="$(stat -c '%u:%g' /sandbox)"
printf 'workload-owner=%s\nworkspace-owner=%s\n' "$workload_owner" "$workspace_owner"
test "$(id -u)" -ne 0
test "$workspace_owner" = "$workload_owner"
probe=$(mktemp /sandbox/userns-probe.XXXXXX)
printf 'workspace probe\n' > "$probe"
rm "$probe"
echo podman-userns-workspace-ok
cat /proc/self/uid_map
"#;

/// Verify that the gateway's user-namespace configuration matches Podman's
/// direct behavior for the same profile and preserves workspace access.
///
/// The test runs a short-lived sandbox command and compares its user-namespace
/// mapping with the direct-Podman reference stored at
/// `OPENSHELL_TEST_INPUT_DIR/reference-uid-map`. The tmachine pre-test
/// playbook creates that reference in the same gateway-user context. This deliberately
/// avoids baking a particular Podman mapping into OpenShell's test contract.
/// The workload also verifies that the managed workspace is owned by its
/// non-root UID/GID and that it can create, write, and remove a file there.
#[testkit::test]
async fn configured_userns_matches_podman_reference(cx: &mut Context) -> testkit::Result {
    assert_podman_gateway(cx).await?;

    let test_input_dir = std::env::var_os(PODMAN_TEST_INPUT_DIR_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            Error::msg(format!(
                "{PODMAN_TEST_INPUT_DIR_ENV} must name the Podman test-input directory"
            ))
        })?;
    let expected_path = test_input_dir.join("reference-uid-map");
    let expected_uid_map = fs::read_to_string(&expected_path).map_err(|error| {
        Error::msg(format!(
            "could not read Podman reference UID map {}: {error}",
            expected_path.display()
        ))
    })?;
    let expected_uid_map = normalize_uid_map(&expected_uid_map).ok_or_else(|| {
        Error::msg(format!(
            "Podman reference UID map {} contains no mappings",
            expected_path.display()
        ))
    })?;

    let workload_image = std::env::var(PODMAN_TEST_IMAGE_ENV)
        .ok()
        .filter(|image| !image.trim().is_empty());
    // The sandbox is created through the CLI, so testkit does not know about
    // it. Track it for cleanup before creating it.
    let sandbox_name = cx.name("pu");
    cx.track(&sandbox_name);
    let mut create_args = vec!["sandbox", "create", "--name", &sandbox_name];
    if let Some(image) = workload_image.as_deref() {
        create_args.extend(["--from", image]);
    }
    create_args.extend(["--no-tty", "--", "sh", "-c", WORKSPACE_AND_UID_MAP_PROBE]);
    let run = cx.cli(create_args).await?.success()?;
    testkit::ensure!(
        run.stdout.contains("podman-userns-workspace-ok"),
        "non-root workload did not own and write to /sandbox\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
    let sandbox_uid_map = normalize_uid_map(&run.stdout).ok_or_else(|| {
        Error::msg(format!(
            "sandbox did not return a non-empty UID map\nstdout:\n{}\nstderr:\n{}",
            run.stdout, run.stderr
        ))
    })?;
    testkit::ensure!(
        sandbox_uid_map == expected_uid_map,
        "sandbox UID map differs from the direct Podman reference:\nexpected:\n{expected_uid_map}\nactual:\n{sandbox_uid_map}"
    );
    Ok(())
}

fn normalize_uid_map(value: &str) -> Option<String> {
    let mut mappings: Vec<(u64, u64, u64)> = Vec::new();
    for line in value.lines() {
        let fields = line
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>();
        let Ok(fields) = fields else { continue };
        let [inside, outside, length] = fields.as_slice() else {
            continue;
        };
        if let Some(previous) = mappings.last_mut()
            && previous.0.checked_add(previous.2) == Some(*inside)
            && previous.1.checked_add(previous.2) == Some(*outside)
        {
            previous.2 += *length;
        } else {
            mappings.push((*inside, *outside, *length));
        }
    }
    (!mappings.is_empty()).then(|| {
        mappings
            .iter()
            .map(|(inside, outside, length)| format!("{inside} {outside} {length}"))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

#[test]
fn adjacent_uid_ranges_match_a_combined_mapping() {
    assert_eq!(
        normalize_uid_map("0 0 1\n1 1 65535\n"),
        normalize_uid_map("0 0 65536\n")
    );
}
