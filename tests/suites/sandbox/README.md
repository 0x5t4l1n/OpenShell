# Sandbox suites

End-to-end suites for sandbox behavior, written on
[testkit](../../testkit/README.md). Each member crate is one suite. Tests run
against whichever gateway the environment provides, so the same test covers
every compute driver.

| Suite | Covers |
|---|---|
| `lifecycle` | Create, wait for ready, exec, delete |

Run them against a local Docker gateway with `mise run e2e:testkit`. CI runs the
same task in the `testkit-e2e` job of Branch E2E (`test:e2e` label).

Add a test as a `#[testkit::test]` function in an existing suite, or add a
member crate to `Cargo.toml` for a new area.

## What a test may assert

These tests run on every compute driver, so they check the public contract and
leave driver behavior alone.

- Assert only what the public contract promises: the proto comments and the
  published docs.
- Assert `phase` and `exit_code`. Don't assert condition reasons.
- Check that something did not happen by reading state, not by sleeping.
- Use the CLI for upload, download, connect and forward. Rely on its exit code
  and `--output json`.
- Add a testkit helper instead of calling raw gRPC from a test.

Guidance adapted from NVIDIA/OpenShell#4629 by Evan Lezar.
