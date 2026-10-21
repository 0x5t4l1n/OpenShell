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

## Connections without inspection

Before the supervisor forwards a connection it cannot inspect (`tls: skip`, transparent TCP, h2c, unsupported tunnels, SQL passthrough), `uninspectable_traffic_decision` evaluates the matching middleware chain. Entries whose service binds `UNINSPECTABLE_NETWORK/PRE_FORWARD` decide through `UninspectableNetworkMiddleware.Evaluate`, and any failure denies. Other entries follow `on_error`: `fail_closed` denies, and `fail_open` relays the connection with a bypass finding. That `fail_open` exception is deprecated and removed in 0.2.0. For `tls: skip`, the decision runs before `200 Connection Established`, so a denial is a `403`.
