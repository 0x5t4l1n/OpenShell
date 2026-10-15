// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Job outcomes and the run summary.

use std::fmt::Write as _;

/// The outcome of one family in one environment.
#[derive(Debug)]
pub struct Outcome {
    pub environment: String,
    pub family: String,
    pub status: Status,
    /// Tests excluded because the environment lacks a capability.
    pub unsupported_tests: usize,
}

#[derive(Debug)]
pub enum Status {
    Passed {
        tests: u32,
    },
    Failed {
        tests: u32,
        failures: u32,
    },
    /// The environment can't be provisioned on this host.
    Unsupported(String),
    /// Every selected test needs a capability the environment lacks.
    NothingToRun,
    /// The runner could not complete the job.
    Error(String),
}

impl Status {
    pub const fn is_failure(&self) -> bool {
        matches!(self, Self::Failed { .. } | Self::Error(_))
    }
}

/// Test and failure counts from a `JUnit` report's root element.
pub fn junit_counts(xml: &str) -> Option<(u32, u32)> {
    let start = xml.find("<testsuites")?;
    let end = start + xml[start..].find('>')?;
    let root = &xml[start..end];
    let attr = |name: &str| -> Option<u32> {
        let key = format!(" {name}=\"");
        let value_start = root.find(&key)? + key.len();
        let value_end = value_start + root[value_start..].find('"')?;
        root[value_start..value_end].parse().ok()
    };
    let tests = attr("tests")?;
    let failures = attr("failures").unwrap_or(0) + attr("errors").unwrap_or(0);
    Some((tests, failures))
}

/// A human-readable summary of every outcome.
pub fn summary(outcomes: &[Outcome]) -> String {
    let mut out = String::from("\nSummary\n");
    for outcome in outcomes {
        let status = match &outcome.status {
            Status::Passed { tests } => format!("PASS        {tests} passed"),
            Status::Failed { tests, failures } => {
                format!("FAIL        {failures} of {tests} failed")
            }
            Status::Unsupported(reason) => format!("UNSUPPORTED {reason}"),
            Status::NothingToRun => {
                "UNSUPPORTED every selected test needs a missing capability".to_string()
            }
            Status::Error(error) => format!("ERROR       {error}"),
        };
        let unsupported = if outcome.unsupported_tests > 0 {
            format!(" ({} tests unsupported)", outcome.unsupported_tests)
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "  {} / {}: {status}{unsupported}",
            outcome.environment, outcome.family
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_junit_counts() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="3" failures="1" errors="1" uuid="x" timestamp="t" time="1.0">
<testsuite name="a" tests="3"></testsuite></testsuites>"#;
        assert_eq!(junit_counts(xml), Some((3, 2)));
    }

    #[test]
    fn missing_root_has_no_counts() {
        assert_eq!(junit_counts("<testsuite tests=\"1\"/>"), None);
    }

    #[test]
    fn summarizes_outcomes() {
        let text = summary(&[
            Outcome {
                environment: "env-a".to_string(),
                family: "conformance".to_string(),
                status: Status::Passed { tests: 2 },
                unsupported_tests: 1,
            },
            Outcome {
                environment: "env-b".to_string(),
                family: "conformance".to_string(),
                status: Status::Unsupported("arch".to_string()),
                unsupported_tests: 0,
            },
        ]);
        assert!(
            text.contains("env-a / conformance: PASS        2 passed (1 tests unsupported)"),
            "{text}"
        );
        assert!(
            text.contains("env-b / conformance: UNSUPPORTED arch"),
            "{text}"
        );
    }
}
