# Sandbox suites

End-to-end suites for sandbox behavior, written on
[testkit](../../testkit/README.md). Each member crate is one suite. Tests run
against whichever gateway the environment registered, so the same test covers
every compute driver.

| Suite | Covers |
|---|---|
| `lifecycle` | Create, ready, exec, stop, start and delete through the SDK, plus the same flow through the CLI |
| `file-transfer` | Upload and download round trips, Git filtering, and path safety |
| `policy-advisor` | Denied connections produce draft rules; `policy.local` accepts proposals |
| `oci-image` | Image user and working-directory behavior on the Docker and Podman drivers |

Run them against a local Docker gateway with `mise run e2e:testkit`, or against
Podman with `mise run e2e:testkit:podman`. `oci-image` needs
`OPENSHELL_TEST_CONTAINER_ENGINE`; use `mise run e2e:oci-image`.

Driver-specific tests live in their own test file so a playbook can exclude
them with a nextest filter. `lifecycle/tests/persistent_workspace.rs` needs a
driver that keeps `/sandbox` across stop and start.

## Adding a test

Add a `#[testkit::test]` function to an existing suite, or a new member crate to
`Cargo.toml` for a new area. The `sandbox` tmachine testsuite runs the
`lifecycle`, `file-transfer` and `policy-advisor` crates from one nextest
archive, so a test added there runs in every conformance lane. Raise
`suite_expected_tests` in `tests/tmachine/config.nix` when you add one. A crate
with its own environment needs, like `oci-image`, gets its own archive in
`tests/tmachine/artifacts.nix` and its own testsuite in `config.nix`.

## What a test may assert

These tests run on every compute driver, so they check the public contract and
leave driver behavior alone.

- Assert only what the public contract promises: the proto comments and the
  published docs.
- Assert `phase` and `exit_code`. Don't assert condition reasons.
- Check that something did not happen by reading state, not by sleeping.
- If a behavior is left to the driver, declare it with
  `#[testkit::test(requires = [...])]`. The runner supplies the environment's
  capabilities, and the test fails if one is missing.
- Use the CLI for upload, download, connect and forward. Rely on its exit code
  and `--output json`.
- Add a testkit helper instead of calling raw gRPC from a test.

Guidance adapted from NVIDIA/OpenShell#4629 by Evan Lezar.
