# Sandbox suites

End-to-end suites for sandbox behavior, written on
[testkit](../../testkit/README.md). Each member crate is one suite. Tests run
against whichever gateway the environment registered, so the same test covers
every compute driver.

| Suite | Covers |
|---|---|
| `lifecycle` | Create, wait for ready, exec, delete |

Run them against a local Docker gateway with `mise run e2e:testkit`, or against
Podman with `mise run e2e:testkit:podman`.

## Adding a test

Add a `#[testkit::test]` function to an existing suite, or a new member crate to
`Cargo.toml` for a new area. A new crate also needs its own entry in
`tests/artifacts.nix` and `tests/config.nix`, and a playbook
that checks the test count. Copy `ansible/playbooks/suites/sandbox-lifecycle.yaml`.

## What a test may assert

These tests run on every compute driver, so they check the public contract and
leave driver behavior alone.

- Assert only what the public contract promises: the proto comments and the
  published docs.
- Assert `phase` and `exit_code`. Don't assert condition reasons.
- Check that something did not happen by reading state, not by sleeping.
- If a behavior is left to the driver, it needs a capability. Until testkit has
  capabilities, keep that test out of this suite.
- Use the CLI for upload, download, connect and forward. Rely on its exit code
  and `--output json`.
- Add a testkit helper instead of calling raw gRPC from a test.

Guidance adapted from NVIDIA/OpenShell#4629 by Evan Lezar.
