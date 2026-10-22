# Sandbox conformance suite

The `sandbox` crate holds testkit suites for sandbox behavior that every compute
driver must provide. It is a member of the `conformance` workspace, which a plan
selects with `type: conformance`. Each file in `tests/` is one suite; suite names
are the file names.

| Suite | Covers |
|---|---|
| `smoke` | Create a sandbox, run `echo` in it, delete it |

The suite is small on purpose. It proves that a plan can run a real test through
the runner on CI. The older suites move to testkit by adding suites here (or a
new family under `tests/suites/`) and listing them in a plan.

## Running it

Against a local Docker gateway:

```shell
mise run e2e:testkit
```

Against any gateway the CLI can reach, with the testkit environment variables
described in [tests/testkit/README.md](../../../testkit/README.md):

```shell
OPENSHELL_GATEWAY=<name> cargo nextest run --locked \
  --manifest-path tests/suites/conformance/Cargo.toml -p sandbox --test-threads 1
```

On CI, `tests/plans/cpu-tests.yaml` runs it through
[the plan runner](../../../plans/README.md).

## Adding a test

Add a `#[testkit::test]` function to a suite, or a new file in `tests/` for a new
area. No playbook, test archive or workflow entry is needed: the runner discovers
tests from source and the plan selects them.

## What a test may assert

These tests run on every compute driver, so they check the public contract and
leave driver behavior alone.

- Assert only what the public contract promises: the proto comments and the
  published docs.
- Assert `phase` and `exit_code`. Don't assert condition reasons.
- Check that something did not happen by reading state, not by sleeping.
- If a behavior is left to the driver, declare it with
  `#[testkit::test(requires = [...])]`.
- Use the CLI for upload, download, connect and forward. Rely on its exit code
  and `--output json`.
- Add a testkit helper instead of calling raw gRPC from a test.

Guidance adapted from NVIDIA/OpenShell#4629 by Evan Lezar.
