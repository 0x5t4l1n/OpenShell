// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The CI matrix, generated from plans.
//!
//! A workflow runs one job per entry of `openshell-test test --plan <plan>
//! --emit-github-matrix`, so which environments run is decided by the plan and
//! by what each environment provides, not by a list copied into a workflow.
//!
//! `tests/expected-matrix.json` checks that list in: for every plan, the
//! generated job entries and, for each environment, the tests that run there.
//! Dropping a capability from an environment, adding a test that needs one, or
//! changing a plan changes the generated file, so the change shows up as a diff
//! in review and `openshell-test check-matrix` fails until the file is
//! regenerated with `--write`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::catalog::Catalog;
use crate::environments::{Arch, Catalog as Environments};
use crate::jobs::{self, Narrowing};
use crate::plan::Plan;
use crate::waivers::Waivers;

/// The checked-in expected matrix, relative to the repository root.
pub const EXPECTED_MATRIX: &str = "tests/expected-matrix.json";
/// Where plans live, relative to the repository root.
pub const PLANS_DIR: &str = "tests/plans";

/// One CI job: a plan run in one environment.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct GithubJob {
    pub plan: String,
    /// The environment ID, for `openshell-test test --env`.
    pub environment: String,
    /// The GitHub runner label that can boot the environment.
    pub runner: String,
    /// How many tests the job must run, as a quick check in the workflow.
    pub expected_tests: usize,
}

/// The strategy matrix a workflow reads with `fromJSON`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct GithubMatrix {
    pub include: Vec<GithubJob>,
}

/// What the checked-in file records for one plan.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct ExpectedPlan {
    pub github_matrix: GithubMatrix,
    /// For each environment, the tests that run there as
    /// `family/suite/test`.
    pub tests: BTreeMap<String, Vec<String>>,
}

/// The checked-in file: the expected matrix of every plan, by plan name.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Expected {
    pub plans: BTreeMap<String, ExpectedPlan>,
}

/// The GitHub-hosted runner that can boot guests of `arch`: tmachine boots
/// guests of the host's architecture only.
pub const fn runner_label(arch: Arch) -> &'static str {
    match arch {
        Arch::Amd64 => "ubuntu-24.04",
        Arch::Arm64 => "ubuntu-24.04-arm",
    }
}

/// Expand a plan the way a lane would and describe what it runs, ignoring
/// which host generates the matrix.
///
/// # Errors
///
/// Fails if the plan names an unknown family, suite or environment, or if the
/// plan selects an environment where no test is left to run: a CI lane that
/// would pass without testing anything.
pub fn expected_plan(
    plan_name: &str,
    plan: &Plan,
    catalog: &Catalog,
    environments: &Environments,
    waivers: &Waivers,
) -> Result<ExpectedPlan> {
    let jobs = jobs::expand(
        plan,
        catalog,
        environments,
        waivers,
        None,
        &Narrowing::default(),
    )?;
    if jobs.is_empty() {
        bail!("plan {plan_name} selects no tests");
    }

    let mut expected = ExpectedPlan::default();
    for job in &jobs {
        let id = &job.environment.id;
        let mut tests = Vec::new();
        for family in &job.families {
            if !family.has_tests() {
                bail!(
                    "plan {plan_name} selects {id} / {}, but every selected test is excluded there (missing capabilities or waivers)",
                    family.family
                );
            }
            for suite in &family.suites {
                tests.extend(
                    suite
                        .run
                        .iter()
                        .map(|name| format!("{}/{}/{name}", family.family, suite.suite.suite)),
                );
            }
        }
        tests.sort();
        expected.github_matrix.include.push(GithubJob {
            plan: plan_name.to_string(),
            environment: id.clone(),
            runner: runner_label(job.environment.machine.arch).to_string(),
            expected_tests: tests.len(),
        });
        expected.tests.insert(id.clone(), tests);
    }
    expected
        .github_matrix
        .include
        .sort_by(|a, b| a.environment.cmp(&b.environment));
    Ok(expected)
}

/// The expected matrix of every plan in `plans_dir`.
///
/// # Errors
///
/// Fails if a plan cannot be read or does not expand to a runnable job in
/// every environment it names.
pub fn expected(
    plans_dir: &Path,
    catalog: &Catalog,
    environments: &Environments,
    waivers: &Waivers,
) -> Result<Expected> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(plans_dir)
        .with_context(|| format!("read {}", plans_dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<_>>()
        .with_context(|| format!("read {}", plans_dir.display()))?;
    paths.retain(|path| path.extension().is_some_and(|ext| ext == "yaml"));
    paths.sort();

    let mut plans = BTreeMap::new();
    for path in paths {
        let name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .with_context(|| format!("plan file name {} is not UTF-8", path.display()))?
            .to_string();
        let plan = Plan::load(&path)?;
        let entry = expected_plan(&name, &plan, catalog, environments, waivers)
            .with_context(|| format!("expand plan {name}"))?;
        plans.insert(name, entry);
    }
    Ok(Expected { plans })
}

/// The file's contents for an expected matrix: pretty JSON ending in a newline.
///
/// # Errors
///
/// Fails only if the matrix cannot be serialized.
pub fn render(expected: &Expected) -> Result<String> {
    let mut text = serde_json::to_string_pretty(expected)?;
    text.push('\n');
    Ok(text)
}

/// How the checked-in file differs from the generated one, as `-`/`+` lines
/// (checked in / generated). Empty when they match.
pub fn diff(checked_in: &str, generated: &str) -> Vec<String> {
    use std::collections::BTreeSet;

    if checked_in == generated {
        return Vec::new();
    }
    let old: BTreeSet<&str> = checked_in.lines().collect();
    let new: BTreeSet<&str> = generated.lines().collect();
    let mut lines: Vec<String> = Vec::new();
    lines.extend(
        checked_in
            .lines()
            .filter(|line| !new.contains(line))
            .map(|line| format!("- {line}")),
    );
    lines.extend(
        generated
            .lines()
            .filter(|line| !old.contains(line))
            .map(|line| format!("+ {line}")),
    );
    if lines.is_empty() {
        // The same lines in a different order, or whitespace only.
        lines.push("the files differ in ordering or whitespace".to_string());
    }
    lines
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::catalog::{Family, Suite, Test};

    const AMD64: &str = "tmachine.ubuntu2404-amd64.docker-rootful.deb";
    const ARM64: &str = "tmachine.ubuntu2404-arm64.docker-rootful.deb";

    fn environments(capabilities: &str) -> Environments {
        let mut yaml = String::from("environments:\n");
        for arch in ["amd64", "arm64"] {
            yaml.push_str(&format!(
                "  - id: tmachine.ubuntu2404-{arch}.docker-rootful.deb\n    backend: tmachine\n    machine: {{ os: ubuntu, version: \"24.04\", arch: {arch} }}\n    runtime: docker-rootful\n    installer: deb\n    tmachine: {{ environment: ubuntu-docker-rootful, installer: deb }}\n    capabilities: {capabilities}\n"
            ));
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("docker.yaml"), yaml).unwrap();
        Environments::load_dir(dir.path()).unwrap()
    }

    fn catalog() -> Catalog {
        let test = |name: &str, requires: &[&str]| Test {
            id: None,
            name: name.to_string(),
            description: "d".to_string(),
            requires: requires.iter().map(ToString::to_string).collect(),
        };
        let suite = Suite {
            suite: "lifecycle".to_string(),
            binary: "lifecycle".to_string(),
            package: "pkg".to_string(),
            tests: vec![
                test("plain", &[]),
                test("keeps_workspace", &["persistent_workspace"]),
            ],
        };
        Catalog {
            families: BTreeMap::from([(
                "sandbox".to_string(),
                Family {
                    name: "sandbox".to_string(),
                    workspace: PathBuf::new(),
                    suites: BTreeMap::from([("lifecycle".to_string(), suite)]),
                },
            )]),
        }
    }

    fn plan() -> Plan {
        Plan::parse(&format!(
            "matrix:\n  - type: sandbox\n    environments: [{AMD64}, {ARM64}]\n"
        ))
        .unwrap()
    }

    fn generate(capabilities: &str) -> ExpectedPlan {
        expected_plan(
            "p",
            &plan(),
            &catalog(),
            &environments(capabilities),
            &Waivers::default(),
        )
        .unwrap()
    }

    #[test]
    fn generates_a_job_per_environment_with_its_runner_and_test_count() {
        let expected = generate("{ persistent_workspace: true }");
        assert_eq!(
            expected.github_matrix.include,
            [
                GithubJob {
                    plan: "p".to_string(),
                    environment: AMD64.to_string(),
                    runner: "ubuntu-24.04".to_string(),
                    expected_tests: 2,
                },
                GithubJob {
                    plan: "p".to_string(),
                    environment: ARM64.to_string(),
                    runner: "ubuntu-24.04-arm".to_string(),
                    expected_tests: 2,
                },
            ]
        );
        assert_eq!(
            expected.tests[AMD64],
            [
                "sandbox/lifecycle/keeps_workspace",
                "sandbox/lifecycle/plain"
            ]
        );
    }

    #[test]
    fn dropping_a_capability_changes_the_generated_matrix() {
        let with = render(&Expected {
            plans: BTreeMap::from([("p".to_string(), generate("{ persistent_workspace: true }"))]),
        })
        .unwrap();
        let without = render(&Expected {
            plans: BTreeMap::from([("p".to_string(), generate("{ persistent_workspace: false }"))]),
        })
        .unwrap();
        let changes = diff(&with, &without);
        assert!(
            changes
                .iter()
                .any(|line| line.starts_with("- ")
                    && line.contains("sandbox/lifecycle/keeps_workspace")),
            "{changes:#?}"
        );
        assert!(
            changes
                .iter()
                .any(|line| line.contains("\"expected_tests\": 1")),
            "{changes:#?}"
        );
        assert!(diff(&with, &with).is_empty());
    }

    #[test]
    fn an_environment_with_nothing_left_to_run_is_an_error() {
        let mut catalog = catalog();
        catalog
            .families
            .get_mut("sandbox")
            .unwrap()
            .suites
            .get_mut("lifecycle")
            .unwrap()
            .tests
            .remove(0);
        let err = expected_plan(
            "p",
            &plan(),
            &catalog,
            &environments("{ persistent_workspace: false }"),
            &Waivers::default(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("every selected test is excluded"),
            "{err}"
        );
    }

    #[test]
    fn the_matrix_does_not_depend_on_the_host() {
        // `expand` is given no host, so no environment is dropped as
        // unsupported; both architectures appear.
        assert_eq!(generate("{}").github_matrix.include.len(), 2);
    }

    #[test]
    fn the_checked_in_matrix_is_up_to_date() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let catalog = Catalog::load(&root).unwrap();
        let environments = Environments::load_dir(&root.join("tests/environments")).unwrap();
        let waivers =
            Waivers::load(&root.join("tests/waivers.yaml"), &catalog, &environments).unwrap();
        let generated =
            render(&expected(&root.join(PLANS_DIR), &catalog, &environments, &waivers).unwrap())
                .unwrap();
        let checked_in = std::fs::read_to_string(root.join(EXPECTED_MATRIX)).unwrap();
        assert!(
            diff(&checked_in, &generated).is_empty(),
            "{EXPECTED_MATRIX} is out of date; run `cargo run --manifest-path tests/runner/Cargo.toml -- check-matrix --write`:\n{}",
            diff(&checked_in, &generated).join("\n")
        );
    }
}
