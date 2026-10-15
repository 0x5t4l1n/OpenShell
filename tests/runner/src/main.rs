// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell-test`: run `OpenShell` test plans.
//!
//! Run it through `nix run .#test-runner -- <command>`, which provides the
//! guest cross-compilation toolchain, QEMU, Ansible, and the tmachine
//! configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use openshell_test_runner::bundle::{self, Bundle};
use openshell_test_runner::catalog::Catalog;
use openshell_test_runner::environments::{Arch, Catalog as Environments};
use openshell_test_runner::execute::{self, Options};
use openshell_test_runner::jobs::{self, Job, Narrowing};
use openshell_test_runner::plan::Plan;
use openshell_test_runner::report;

#[derive(Parser)]
#[command(name = "openshell-test", about = "Run OpenShell test plans")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a test plan.
    Test {
        /// The plan to run, e.g. tests/plans/cpu-tests.yaml.
        #[arg(long)]
        plan: PathBuf,
        /// Print the resolved jobs without building or provisioning anything.
        #[arg(long)]
        dry_run: bool,
        /// Keep each environment running after its tests until Enter is pressed.
        #[arg(long)]
        keep: bool,
        /// Only run these environments from the plan.
        #[arg(long = "env", value_name = "ID")]
        environments: Vec<String>,
        /// Only run these suites from the plan.
        #[arg(long = "suite", value_name = "NAME")]
        suites: Vec<String>,
        /// Results directory [default: artifacts/test-results/<plan name>].
        #[arg(long)]
        results: Option<PathBuf>,
    },
    /// Print the test catalog as JSON.
    Catalog,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let root = repo_root()?;
    let catalog = Catalog::load(&root)?;

    match cli.command {
        Command::Catalog => {
            println!("{}", serde_json::to_string_pretty(&catalog)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Test {
            plan,
            dry_run,
            keep,
            environments,
            suites,
            results,
        } => {
            let plan_path = plan;
            let plan = Plan::load(&plan_path)?;
            let environments_catalog = Environments::load_dir(&root.join("tests/environments"))?;
            let host = Arch::host();
            let narrowing = Narrowing {
                environments,
                suites,
            };
            let jobs = jobs::expand(&plan, &catalog, &environments_catalog, host, &narrowing)?;
            print_jobs(&jobs);
            if dry_run {
                return Ok(ExitCode::SUCCESS);
            }

            let results = match results {
                Some(results) => results,
                None => root.join("artifacts/test-results").join(
                    plan_path
                        .file_stem()
                        .context("plan path has no file name")?,
                ),
            };
            std::fs::create_dir_all(&results)
                .with_context(|| format!("create {}", results.display()))?;
            std::fs::write(
                results.join("suites.json"),
                serde_json::to_string_pretty(&catalog)?,
            )?;

            let bundles = build_bundles(&jobs, &catalog, host)?;
            let tmachine = load_tmachine(&root)?;
            let options = Options {
                tmachine: &tmachine,
                bundles: &bundles,
                results: &results,
                keep,
            };
            let mut outcomes = Vec::new();
            for job in &jobs {
                outcomes.extend(execute::run(job, &options).await);
            }

            eprintln!("{}", report::summary(&outcomes));
            eprintln!("Results: {}", results.display());
            Ok(
                if outcomes.iter().any(|outcome| outcome.status.is_failure()) {
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                },
            )
        }
    }
}

fn print_jobs(jobs: &[Job]) {
    for job in jobs {
        eprintln!("{}", job.environment.id);
        if let Some(reason) = &job.unsupported {
            eprintln!("  unsupported on this host: {reason}");
        }
        for family in &job.families {
            eprintln!("  {}: -E '{}'", family.family, family.filterset());
            for suite in &family.suites {
                eprintln!("    {}: {}", suite.suite.suite, suite.run.join(", "));
                for test in &suite.unsupported {
                    eprintln!(
                        "    {}: {} unsupported (needs {})",
                        suite.suite.suite,
                        test.id,
                        test.missing.join(", ")
                    );
                }
            }
        }
    }
}

/// Build one bundle per family, covering every suite that will run.
fn build_bundles(
    jobs: &[Job],
    catalog: &Catalog,
    host: Option<Arch>,
) -> Result<BTreeMap<String, Bundle>> {
    let mut suites: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for job in jobs.iter().filter(|job| job.unsupported.is_none()) {
        for family in &job.families {
            for suite in family.suites.iter().filter(|suite| !suite.run.is_empty()) {
                suites
                    .entry(family.family.as_str())
                    .or_default()
                    .insert(suite.suite.suite.as_str());
            }
        }
    }

    let mut bundles = BTreeMap::new();
    if suites.is_empty() {
        return Ok(bundles);
    }
    let target = bundle::guest_target(host.context("the host architecture is not supported")?);
    for (family_name, suite_names) in suites {
        let family = catalog.family(family_name)?;
        let binaries = suite_names
            .iter()
            .map(|name| family.suite(name).map(|suite| suite.binary.clone()))
            .collect::<Result<_>>()?;
        eprintln!("==> building {family_name} bundle for {target}");
        let bundle = bundle::build(
            family,
            &family.packages(suite_names.iter().copied()),
            &binaries,
            target,
        )?;
        bundles.insert(family_name.to_string(), bundle);
    }
    Ok(bundles)
}

/// Load the tmachine configuration and prepare the process to drive it.
///
/// tmachine configs name playbooks and inputs relative to `tests/`, and its
/// Ansible runs read `ANSIBLE_CONFIG`.
fn load_tmachine(root: &Path) -> Result<tmachine::config::Config> {
    let path = std::env::var_os("TMACHINE_CONFIG").context(
        "TMACHINE_CONFIG is not set; run through `nix run .#test-runner`, which provides it",
    )?;
    let config = tmachine::config::Config::load(Path::new(&path))?;
    let tests = root.join("tests");
    std::env::set_current_dir(&tests).with_context(|| format!("enter {}", tests.display()))?;
    if std::env::var_os("ANSIBLE_CONFIG").is_none() {
        // SAFETY: single-threaded at this point; no other thread reads the
        // environment concurrently.
        unsafe { std::env::set_var("ANSIBLE_CONFIG", tests.join("ansible/ansible.cfg")) };
    }
    Ok(config)
}

fn repo_root() -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("run git rev-parse")?;
    anyhow::ensure!(
        output.status.success(),
        "not inside the OpenShell repository"
    );
    Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
}
