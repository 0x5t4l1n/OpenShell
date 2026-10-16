# OpenShell sandbox proxy

This optional reference integration reads gateway service discovery and forwards TLS streams to supervisor app listeners. It selects an exact discovered hostname from SNI, without terminating application TLS or handling HTTP credentials. Supervisors enforce Host/SNI agreement and declared loopback destinations.

```shell
cargo run -p openshell-sandbox-proxy -- \
  --gateway-endpoint https://gateway.example.com \
  --workspace default \
  --discovery-token-file /run/secrets/discovery-token \
  --listen-address 0.0.0.0:8443
```

Discovery requires bearer `sandbox:read` credentials and membership in every configured workspace. Repeat `--workspace` for additional scopes. Use `--gateway-ca` for a private gateway CA. The credential file is reread on every watch reconnect; rotate it externally. The proxy does not use application certificates or receive their private keys. Plaintext gateway access requires an explicit `--allow-plaintext-development` flag and accepts no bearer credential.

The proxy replaces each workspace cache with every snapshot and resolves the advertised supervisor address for each connection. Headless Kubernetes Services provide stable DNS names that resolve directly to ready supervisor Pod addresses. Application traffic does not traverse the gateway.

Unknown or expired SNI never opens a backend connection. Withdrawal, declaration changes, and runtime replacement close affected streams. Advertisement renewal extends leases without disrupting a stream on the same backend. Discovery outages retain existing leases only; authorization failures immediately withdraw that workspace. Watches reconnect after EOF, with a one-second retry delay. There is no gateway fallback.

The POC bounds TLS ClientHello input to 64 KiB, setup operations to 10 seconds, and the route cache to 4,096 entries. It defaults to 256 connections. TLS ClientHello bytes, HTTP, and WebSockets pass unchanged to supervisors. Connection tasks are separate from discovery tasks. Remaining production work includes metrics, differentiated quotas, retry backoff, certificate lifecycle, and stronger readiness reporting.

For the Helm fixture and multiple sandbox services, see the [proxy smoke test](../../e2e/kubernetes/app-listener/README.md#test-through-the-sandbox-proxy).

## Certificate-authenticated discovery

Use HTTPS with `--discovery-client-cert` and `--discovery-client-key` instead
of `--discovery-token-file`. Optionally pin the gateway CA with `--gateway-ca`.
The proxy reads the certificate, key, and CA on every discovery reconnect and
sends no Authorization header in certificate mode. The gateway must trust the
client CA and enable operator authentication for an `OU=operator` certificate.
Operator identities have gateway-wide privileges, including provider credential
retrieval. Keep the client key confined to the proxy and automate renewal.

Helm selects this mode with `sandboxProxy.discoveryClientTlsSecret`, referencing
only `tls.crt` and `tls.key`. It is mutually exclusive with
`sandboxProxy.discoveryTokenSecret` and plaintext development mode. Application
TLS still terminates at the supervisor; the discovery identity is never sent
to applications.
