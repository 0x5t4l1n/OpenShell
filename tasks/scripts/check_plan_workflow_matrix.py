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
workflow matrix lists something different, so the two cannot drift apart.

Each plan entry's suite maps to a tmachine testsuite name below.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

PLAN = "tests/plans/testkit.yaml"
WORKFLOWS = (
    ".github/workflows/release-qualification.yml",
    ".github/workflows/release-dev.yml",
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


def from_plan(base: Path) -> set[tuple[str, str, str]]:
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
                triples.add((environment, installer, name))
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
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
