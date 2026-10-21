#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml"]
# ///

"""Check that the release workflow matrices match the testkit plan.

The tmachine lanes in the release workflows list `environment`, `installer` and
`testsuite` by hand. tests/plans/testkit.yaml says which suites run in which
environments, and tests/environments/*.yaml say how each environment is
provisioned. This check derives the lane triples from the plan and fails when a
workflow matrix lists something different, so the two cannot drift apart. It also
checks that each testsuite's `suite_expected_tests` in tests/tmachine/config.nix equals the
number of tests the plan expects, using tests/expected-matrix.json.

Each plan entry's suite maps to a tmachine testsuite name below.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

PLAN = "tests/plans/testkit.yaml"
CONFIG = "tests/tmachine/config.nix"
EXPECTED = "tests/expected-matrix.json"
WORKFLOWS = (
    ".github/workflows/release-qualification.yml",
    ".github/workflows/release-dev.yml",
    ".github/workflows/branch-e2e.yml",
)
# (plan family, suite or None for the family default) -> tmachine testsuite.
TESTSUITES = {
    ("sandbox", "oci-image"): "oci-image",
    ("sandbox", None): "sandbox",
    ("providers", None): "provider-refresh",
}


def root() -> Path:
    return Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )


def environments(base: Path) -> dict[str, tuple[str, str]]:
    found = {}
    for path in sorted((base / "tests/environments").glob("*.yaml")):
        for env in yaml.safe_load(path.read_text())["environments"]:
            tm = env["tmachine"]
            found[env["id"]] = (tm["environment"], tm["installer"])
    return found


def selects(testsuite: str, test: str) -> bool:
    """Whether a catalog entry `family/suite/test` belongs to a testsuite."""
    family, suite, _ = test.split("/", 2)
    if testsuite == "oci-image":
        return (family, suite) == ("sandbox", "oci-image")
    if testsuite == "sandbox":
        return family == "sandbox" and suite != "oci-image"
    if testsuite == "provider-refresh":
        return family == "providers"
    return False


def configured_counts(base: Path) -> dict[str, int]:
    """`suite_expected_tests` for each testsuite in tests/tmachine/config.nix."""
    text = (base / CONFIG).read_text()
    counts = {}
    for match in re.finditer(r'name = "([^"]+)";', text):
        rest = text[match.end() :]
        end = re.search(r'\n      \{', rest)
        block = rest[: end.start()] if end else rest
        count = re.search(r'suite_expected_tests = "(\d+)"', block)
        if count:
            counts[match.group(1)] = int(count.group(1))
    return counts


def count_problems(base: Path) -> list[str]:
    """Each lane's `suite_expected_tests` must equal what the plan expects."""
    tests = json.loads((base / EXPECTED).read_text())["plans"]["testkit"]["tests"]
    configured = configured_counts(base)
    problems = []
    for (environment, installer, testsuite), env_id in sorted(plan_lanes(base)):
        expected = sum(selects(testsuite, test) for test in tests[env_id])
        if configured.get(testsuite) != expected:
            problems.append(
                f"error: {CONFIG} sets suite_expected_tests={configured.get(testsuite)} for "
                f"{testsuite}, but {PLAN} expects {expected} tests in {environment}"
            )
    return problems


def from_plan(base: Path) -> set[tuple[str, str, str]]:
    return {triple for triple, _ in plan_lanes(base)}


def plan_lanes(base: Path) -> set[tuple[tuple[str, str, str], str]]:
    """Each lane as ((environment, installer, testsuite), plan environment id)."""
    envs = environments(base)
    plan = yaml.safe_load((base / PLAN).read_text())
    triples = set()
    for entry in plan["matrix"]:
        family, suites = entry["type"], entry.get("suites") or [None]
        names = {
            TESTSUITES.get((family, suite if suite == "oci-image" else None))
            for suite in suites
        }
        for name in names:
            if name is None:
                raise SystemExit(f"error: no tmachine testsuite for {family} {suites}")
            for env_id in entry["environments"]:
                environment, installer = envs[env_id]
                triples.add(((environment, installer, name), env_id))
    return triples


def from_workflow(path: Path) -> set[tuple[str, str, str]]:
    triples = set()
    managed = set(TESTSUITES.values())
    for job in yaml.safe_load(path.read_text())["jobs"].values():
        matrix = (job.get("with") or {}).get("test-matrix")
        if not matrix:
            continue
        for item in json.loads(matrix):
            if item["testsuite"] in managed:
                triples.add((item["environment"], item["installer"], item["testsuite"]))
    return triples


def main() -> int:
    base = root()
    expected = from_plan(base)
    failed = False
    for workflow in WORKFLOWS:
        actual = from_workflow(base / workflow)
        # Release Dev runs a subset of the plan; it must not run anything the
        # plan does not list.
        extra = actual - expected
        missing = expected - actual if workflow.endswith("qualification.yml") else set()
        for triple in sorted(extra):
            print(f"error: {workflow} runs {triple}, which {PLAN} does not list", file=sys.stderr)
        for triple in sorted(missing):
            print(f"error: {workflow} is missing {triple} from {PLAN}", file=sys.stderr)
        failed |= bool(extra or missing)
    problems = count_problems(base)
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if failed or problems else 0


if __name__ == "__main__":
    sys.exit(main())
