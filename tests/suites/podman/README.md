# Podman driver suites

End-to-end suites for behavior specific to the Podman compute driver, written on
[testkit](../../testkit/README.md). Each member crate is one suite. These
suites fail, rather than skip, when the gateway's only compute driver is not
Podman.

| Suite | Covers |
|---|---|
| `userns` | The sandbox's user-namespace mapping matches direct Podman for the configured profile, and the workload can write to its workspace |

`fixtures/` holds the gateway configuration for each user-namespace profile
(`auto`, `keep-id`, `private`). The tmachine playbooks apply one fixture, record
Podman's own UID map as the reference, and then run the suite. The suite reads
these environment variables:

| Variable | Meaning |
|---|---|
| `OPENSHELL_TEST_INPUT_DIR` | Directory holding `reference-uid-map`, written by the playbook |
| `OPENSHELL_PODMAN_TEST_IMAGE` | Optional sandbox image, passed as `--from` |
