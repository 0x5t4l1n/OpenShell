# Supervisor app listener smoke test

This opt-in development path exercises supervisor TLS/SNI routing through driver-managed headless supervisor Services. Direct listener testing needs no proxy component or ingress controller. Use the repository's Helm dev environment and a CLI built from this checkout.

## Deploy

Create the cluster with a short name and preload the test image:

```shell
export HELM_K3S_CLUSTER_NAME=openshell-app-listener
HELM_K3S_PRELOAD_SANDBOX_IMAGE=python:3.12-slim mise run helm:k3s:create
```

Create a short-lived test certificate in a temporary directory; keep its key outside the checkout:

```shell
app_tls_dir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=app-listener-dev' \
  -addext 'subjectAltName=DNS:*.svc.openshell.internal' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$app_tls_dir/tls.key" -out "$app_tls_dir/tls.crt"
KUBECONFIG=kubeconfig kubectl create namespace openshell --dry-run=client -o yaml | \
  KUBECONFIG=kubeconfig kubectl apply -f -
KUBECONFIG=kubeconfig kubectl -n openshell create secret tls openshell-app-tls \
  --cert="$app_tls_dir/tls.crt" --key="$app_tls_dir/tls.key"
```

Deploy using the `app-listener` Skaffold profile. It also configures the gateway to publish installed routes at driver-managed `os-app-<sandbox-id>` headless Services in `openshell`:

```shell
KUBECONFIG=../../../kubeconfig mise exec -- skaffold run -p app-listener
```

Run that command from `deploy/helm/openshell`. From the repository root, run `mise run helm:k3s:forward` in another terminal. Register the gateway at `http://127.0.0.1:8090` if it is not already selected, and create a sandbox:

```shell
openshell gateway add http://127.0.0.1:8090 --local --name app-listener-dev
openshell sandbox create --name app-a --from python:3.12-slim \
  --expose 8080 --detach -- python3 -m http.server 8080 --bind 127.0.0.1
openshell service expose app-a 8080 web
```

Allow one successful configuration poll (normally 10 seconds) for the named route to install. The listener requires gateway-managed policy and does not accept local policy overrides. The printed service URL still belongs to the existing gateway path in this slice; use the supervisor URL below.

## Inspect the headless Service

The profile sets `app_listener.create_service: true`. Resolve the sandbox ID and inspect `os-app-<sandbox-id>` in its namespace. Confirm `clusterIP: None`, the supervisor-only selector, and ready EndpointSlices. Headless DNS resolves directly to supervisor Pod IPs; use port 8443 because it does not translate port 443.

The Sandbox CR owns the Service, which survives stop/start and disappears on sandbox deletion. Leave `create_service` false to supply your own endpoints.

The existing SSH ingress policy blocks the app port. Add a separate policy that allows your ingress client or controller to reach only supervisor app ports. For a same-namespace test client labeled `openshell.ai/app-ingress-client=true`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-listener-test
  namespace: openshell
spec:
  podSelector:
    matchLabels:
      openshell.ai/component: supervisor
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              openshell.ai/app-ingress-client: "true"
      ports:
        - protocol: TCP
          port: 8443
```

Keep workload network policies in place. Adapt the source selector and namespace for your ingress controller.

```shell
KUBECONFIG=kubeconfig kubectl -n openshell get endpointslices \
  -l kubernetes.io/service-name=os-app-REPLACE_WITH_SANDBOX_ID -o wide
KUBECONFIG=kubeconfig kubectl -n openshell port-forward svc/os-app-REPLACE_WITH_SANDBOX_ID 18443:8443
```

## Verify routing

Send matching SNI and Host with certificate verification enabled:

```shell
curl --noproxy '*' --cacert "$app_tls_dir/tls.crt" \
  --resolve default--app-a--web.svc.openshell.internal:18443:127.0.0.1 \
  https://default--app-a--web.svc.openshell.internal:18443/
```

Expected: HTTP 200 from the sandbox server. Repeat with `-H 'Host: default--app-b--web.svc.openshell.internal'`: expect HTTP 421 and no sandbox connection. An unknown service or sandbox in SNI closes the connection even though the wildcard certificate matches. No-SNI clients are also rejected.

The app listener preserves the validated public `Host` (including its public port) and browser `Origin` for HTTP and WebSocket requests while connecting to the declared loopback port. For browser-facing applications, verify cookie login with an `Origin` header and verify WebSocket upgrades; bearer API access alone does not test browser same-origin checks.

The app listener preserves existing `Authorization` stripping and opt-in bearer passthrough. Bearer passthrough rejects duplicate or malformed credentials. Service deletion/updates revoke that service's connections on the next accepted configuration poll; other services stay connected. If configuration stops refreshing, the 30-second route lease closes ingress connections. A stopped workload closes the listener.

Port-forwarding verifies routing and a selected backend, but bypasses normal Service/network-policy forwarding. Also send the same request from an in-cluster client, using the Service DNS name as the connection target while preserving the public SNI/Host with curl's `--connect-to`:

```shell
curl --cacert /tmp/app-cert.crt \
  --connect-to default--app-a--web.svc.openshell.internal:443:os-app-REPLACE_WITH_SANDBOX_ID.openshell.svc.cluster.local:8443 \
  https://default--app-a--web.svc.openshell.internal/
```

Supply the public certificate to that client without copying the private key. Verify a second sandbox with a different policy cannot be selected through the first sandbox's listener. Exercise WebSocket echo, route deletion/port updates, supervisor restart, and control-plane operations under application load before claiming the slice complete.

## Limitations

This is HTTP/1.1 plus WebSockets, with 64 connections per supervisor, 10-second TLS/header/connect deadlines, and a 30-second route freshness lease. TLS credentials reload on supervisor recreation. There is no native user/workspace ingress authorization or new ingress policy schema; gateway-authorized declarations form the ingress allowlist. Restrict listener reachability if edge authentication is required.

## Discover installed routes

After exposure and configuration sync, query the gateway from the repository root:

```shell
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -d '{"workspaceScope":{"workspace":"default"}}' \
  127.0.0.1:8090 openshell.v1.OpenShell/GetServiceRouteSnapshot
```

Use `WatchServiceRoutes` with the same request to receive complete replacement snapshots. The local profile enables development authentication; production callers need bearer read credentials and membership in the selected workspace. The POC watch ends after 60 seconds and must be reopened. Clients replace their route cache and discard expired entries.

Confirm the `web` route uses the headless supervisor Service address and expected service hostname. Change or delete the declaration and verify its old revision disappears from the watch. Recreate the supervisor and verify discovery publishes the new runtime identity only after it accepts the route. Application health is not inferred from an advertisement.

## Test through the sandbox proxy

Deploy the `sandbox-proxy` profile instead of `app-listener`:

```shell
KUBECONFIG=../../../kubeconfig mise exec -- skaffold run -p sandbox-proxy
```

This builds the proxy image, enables headless supervisor endpoints and discovery, and deploys `openshell-sandbox-proxy`. It permits that proxy to reach the supervisor app port in the shared namespace. Discovery uses development authentication only in this profile. Production deployment requires an HTTPS gateway, workspace-scoped bearer credentials in `sandboxProxy.discoveryTokenSecret` (key `token`), and any private gateway CA in `sandboxProxy.gatewayCaSecret` (key `ca.crt`). Operator-managed workspace namespaces need corresponding app ingress policies and address templates.

The expected external path is `client → Kubernetes Gateway API ingress → sandbox proxy → supervisor → sandbox service`. For the public base domain `api.openshell-sandbox-proxy-ingress.my-domain`, a service URL is `https://default--sandbox-a--web.api.openshell-sandbox-proxy-ingress.my-domain/`. Wildcard DNS points at ingress; TLS passthrough preserves the service SNI to the supervisor. The API address and internal headless endpoints are configured separately. The [gateway configuration reference](../../../docs/how-it-works/gateways/configuration.mdx#application-ingress-architecture) describes this deployment example. The port-forward below tests the proxy directly; use the Gateway API fixture below to exercise ingress and public CLI/SDK URLs.

## Validate public URLs through Gateway API ingress

Create an operator-owned `openshell-public-app-tls` Secret in `openshell`, with a certificate for `*.api.openshell-sandbox-proxy-ingress.my-domain`. Use the certificate procedure above with that hostname and Secret name. Keep its private key outside the checkout and supply only the public certificate to clients.

Deploy the combined profiles from `deploy/helm/openshell`:

```shell
KUBECONFIG=../../../kubeconfig mise exec -- skaffold run \
  -p sandbox-proxy,sandbox-proxy-ingress
```

This installs the pinned Envoy Gateway controller and configures the gateway to return supervisor-mode URLs at `https://api.openshell-sandbox-proxy-ingress.my-domain:28443`. Application TLS remains on supervisors; the controller and sandbox proxy receive no app private keys. Recreate existing supervisors to apply the new domain and TLS Secret, or create fresh fixtures.

Apply the ingress objects from the repository root after the controller installs its CRDs:

```shell
KUBECONFIG=kubeconfig kubectl apply \
  -f e2e/kubernetes/app-listener/gateway-api.yaml
KUBECONFIG=kubeconfig kubectl -n openshell get gateway openshell-app-ingress
KUBECONFIG=kubeconfig kubectl -n openshell get tlsroute openshell-app-ingress
KUBECONFIG=kubeconfig kubectl get svc -A \
  -l gateway.envoyproxy.io/owning-gateway-name=openshell-app-ingress
```

Require the Gateway to be programmed and the TLSRoute to be accepted with resolved references. Forward the discovered **Envoy** Service's port 443 to local port 28443. Keep the OpenShell API on a different port, such as 8090, and expose the four fixture services. Each printed URL must use the public domain and port 28443. Also check create-time unnamed exposure and SDK creation URLs.

```shell
uv run python e2e/kubernetes/app-listener/proxy-smoke.py \
  --ca /path/to/public-app-certificate.crt \
  --domain api.openshell-sandbox-proxy-ingress.my-domain --proxy-port 28443
```

These requests traverse Envoy, the sandbox proxy, headless supervisor DNS, and the sandbox boundary. The smoke client substitutes local resolution for production wildcard DNS while preserving SNI and verifying the supervisor certificate. Check service list/get status before installation, after advertisement, after a target revision changes, and after stop/start. Configured URLs may exist before advertisements and are not health results. Verify gateway-mode URL behavior with supervisor ingress disabled.

Create three detached Python sandboxes from the repository root:

```shell
uv run python - <<'PY'
from pathlib import Path
import subprocess

cli = ["target/debug/openshell", "--gateway-endpoint", "http://127.0.0.1:8090"]
app = Path("e2e/kubernetes/app-listener/app.py").read_text()
for suffix in ("a", "b", "c"):
    name = f"proxy-poc-{suffix}"
    subprocess.run(cli + ["sandbox", "create", "--name", name,
        "--from", "python:3.12-slim", "--detach", "--",
        "python3", "-u", "-c", app, "--identity", name], check=True)
    subprocess.run(cli + ["service", "expose", name, "8080", "web"], check=True)
subprocess.run(cli + ["service", "expose", "proxy-poc-b", "9090", "portal"], check=True)
PY
```

These fixtures use one sandbox per supervisor; shared-supervisor runtime remains a future feature.

Forward only the proxy for application requests:

```shell
KUBECONFIG=kubeconfig kubectl -n openshell port-forward \
  svc/openshell-sandbox-proxy 25443:443
uv run python e2e/kubernetes/app-listener/proxy-smoke.py \
  --ca /path/to/public-app-certificate.crt
```

The smoke test verifies HTTPS and WebSocket echo for A/web, B/web, B/portal, and C/web through the same proxy address. It checks distinct sandbox/port responses, Host mismatches, and undeclared SNI. It preserves service SNI and verifies the supervisor certificate; no private app keys belong in the proxy.

Inspect headless EndpointSlices and confirm their addresses match supervisor Pods. Stop/start a fixture and verify its Service DNS name stays stable while its Pod address and discovered runtime change; repeat the smoke test. Delete a fixture and verify its Service is garbage-collected and its route closes. Leave a watch running past 60 seconds to verify proxy reconnects. During gateway outages, new connections must fail after the remaining route lease expires.
