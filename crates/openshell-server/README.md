<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# OpenShell gateway server

The server owns control-plane RPCs, authentication, provider credential delivery,
and sandbox lifecycle orchestration. The `openshell-gateway` crate composes the
server with selected compute drivers.

## Operator credential export

`GetProviderCredentials` exports selected profile-declared runtime environment
keys from one provider in an explicitly named workspace. It requires the distinct
`Principal::Operator`, established only from a verified TLS leaf certificate with
`OU=operator` when `mtls_auth.operator_enabled` is enabled. The TLS listener supplies
its certificate fingerprint separately from user identity; the ordinary
identity-only serving path cannot establish an operator.

Operators explicitly inherit user/platform-admin permissions, but not sandbox or
peer identities. Descriptor authorization and a handler guard both protect the
export RPC. Operator mutation admission uses a separate caller namespace from
ordinary mTLS users with the same certificate subject. Credential responses never
enter durable mutation replay or generic interceptor routing.

The export resolver validates the entire selection before minting, resolves only
selected credential handles, and fences provider revisions, refresh epochs, and
profile declarations before delivery. Driver expiration and provider expiration
combine using the earlier timestamp. OAuth minting inputs, broker-only keys, and
supervisor-bound dynamic grants are not exportable. A failed response can still
have committed refresh effects. Missing refresh-owned stored outputs trigger
refresh-on-read; missing static outputs and other credential-backend errors fail
closed without falling back to inline values.

## Refresh coordination

Explicit rotation, background refresh, and operator refresh-on-read share the
same refresh coordination:

- A process-local weak keyed mutex coalesces waiters without retaining deleted
  providers indefinitely.
- A bounded admission queue and executor pool limit detached refresh work.
- PostgreSQL deployments also take a dedicated per-provider/per-credential
  advisory lock; SQLite uses the local mutex. Worker secret cleanup takes the
  same locks and reloads state before changing its resource version.
- A durable `refresh_in_progress` marker precedes upstream minting. A
  `refresh_committing` marker protects the interval between grant persistence
  and provider-handle persistence. Only a completed provider commit publishes
  `refreshed` state, with a unique completed-mint identity in metadata
  annotations. Waiters coalesce against that identity, not bookkeeping changes
  to the resource version.
- Automatic callers recheck live recovery and retry deadlines under both locks.
  A failed mint blocks queued automatic exchanges without disabling scheduled
  worker retries or a separately requested manual rotation.
- Detached refresh tasks complete despite request cancellation, preserving
  replacement refresh tokens returned by the issuer.
- Existing generation/CAS fencing remains active for deletion and
  reconfiguration. An ambiguous rotating-token exchange is parked for recovery
  rather than automatically consuming the grant again.

A crash or lost database-lock session can leave a parked marker. Reconfigure or
reauthorize the refresh grant after investigating its issuer state. Changing a
marker directly is not a supported recovery workflow.

## Focused verification

```shell
cargo test -p openshell-server --features test-support,prebuilt-z3
cargo clippy -p openshell-server --all-targets --features test-support,prebuilt-z3 -- -D warnings
```

The ignored `refresh_locks_coordinate_independent_replica_sessions` test requires
`OPENSHELL_REFRESH_TEST_DATABASE_URL` pointing to a disposable PostgreSQL database.
It exercises independent sessions without the local mutex. Do not point this
fixture at an existing deployment database.

## Supervisor service discovery

The supervisor sends installed app-route snapshots on its authenticated session. The gateway validates the current session/owner, runtime identity, declaration revisions, domain, sequence, and expiry, then stores bounded installation evidence as private expiring `supervisor_service_advertisement` JSON records. Operator configuration supplies the app address template; supervisors cannot advertise arbitrary backend addresses. These records are not restored as authority: every discovery read checks the shared live owner, current declaration, admitted configuration, and lease.

`GetServiceRouteSnapshot` and `WatchServiceRoutes` expose read-only, explicitly workspace-scoped snapshots with the existing bearer read scope. Watch updates are complete replacements identified by an opaque content fingerprint, with no event journal or resume cursor. The POC polls shared state once per second, uses a one-message stream buffer, rechecks membership, and closes streams after 60 seconds for reauthentication. Routes carry expiry and installation identity; routers must expire caches independently and reconnect after EOF. See the [manual ingress test](../../e2e/kubernetes/app-listener/README.md).

Snapshots scan records in keyset pages of 128, with a 10-second build deadline. Limits apply to 1,000 eligible advertisements and 4,096 published routes, excluding expired, withdrawn, and otherwise ineligible evidence. A background worker inspects at most 128 records every 30 seconds, with a 10-second deadline. It conditionally deletes records for deleted sandboxes or superseded publishing sessions. Expiry or withdrawal alone never deletes a current session's report-sequence fence; neither does missing owner evidence. Cleanup rechecks the paged record under the publisher's mutation lock, preserving concurrent renewals and replacements, including records recreated with a reset resource version.
