# Network supervisor

This crate forbids unsafe code, including its local tests. Typed socket APIs
provide original-destination lookup for transparent proxying.

Socket attribution tests pass a duplicate connected socket as a spawned child's
stdin. Re-executing the test binary checks multiple holders with the same binary
identity; executing a different binary checks ambiguous shared-socket identity.
The fixture kills and reaps the child when the parent test ends.

The manual proxy performance baseline still counts allocations. Its test-only
global allocator uses `openshell-driver-vm::allocation_tracking`; the unsafe
allocator implementation belongs to the VM crate. The VM dependency disables
default features, so this instrumentation does not
require the compute runtime or Unix-only sandbox library. It is a development
dependency only.

## Session inputs

`run_networking` takes a `NetworkSession` with the sandbox identity, the
session's `GatewayEndpoint`, the workload identity source for provider token
grants, the `policy.local` denial source, and proxy CA files. None of these
are read from the process environment, so one process can run several
sessions. Each session owns its provider token cache and HTTP client; a token
acquired for one sandbox is never served to another. Without an identity
source, token grants fail closed.

A dedicated supervisor's identity source is its SPIFFE Workload API socket. A
shared supervisor's is `spiffe_delegation`: the sandbox's stable JWT-SVID from
the SPIRE agent's Delegated Identity API on a private Unix admin socket. Before
each new SVID, the session's current gateway JWT must verify against the
gateway's session keys and name the registered sandbox, runtime generation, and
credential epoch, and an authenticated gateway read must confirm the generation
is current. The agent is asked for the one selector
`openshell:sandbox:<gateway-id>:<sandbox-id>`; exactly one SVID with the
expected SPIFFE ID must return, verified against the agent's JWT bundle. The
session is re-authorized after each wait and before a cached token is served or
a new one cached, and a failed check clears its cache. The wire messages are
transcribed from `spire-api-sdk` v1.15.3 (Apache-2.0); provenance is in the
source. `mise run test:spire-delegation` runs these rules against a pinned SPIRE
server and agent. A process hosting several sessions serves
`/v1/denials` from a per-session `SessionDenialLog` instead of the shared
shorthand log files.
