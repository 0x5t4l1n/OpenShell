# Supervisor app listener smoke test

This opt-in development path exercises supervisor TLS/SNI routing through a manually created Kubernetes Service. It needs no discovery API, proxy component, or ingress controller. Use the repository's Helm dev environment and a CLI built from this checkout.

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

Deploy using the `app-listener` Skaffold profile. It also configures the gateway to publish installed routes at manually created `<sandbox>-ingress` Services in `openshell`:

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

## Create the Service

Find the supervisor pod for `app-a`, inspect its `openshell.ai/sandbox-id` label, and substitute that ID:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: app-a-ingress
  namespace: openshell
spec:
  selector:
    openshell.ai/sandbox-id: REPLACE_WITH_SANDBOX_ID
    openshell.ai/component: supervisor
  ports:
    - name: app-https
      port: 443
      targetPort: 8443
```

Apply it manually. Confirm its EndpointSlice selects the supervisor, not the workload pod. The Secret and Service must be in the sandbox's actual namespace; this profile assumes shared placement in `openshell`.

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
  -l kubernetes.io/service-name=app-a-ingress -o wide
KUBECONFIG=kubeconfig kubectl -n openshell port-forward svc/app-a-ingress 18443:443
```

## Verify routing

Send matching SNI and Host with certificate verification enabled:

```shell
curl --noproxy '*' --cacert "$app_tls_dir/tls.crt" \
  --resolve default--app-a--web.svc.openshell.internal:18443:127.0.0.1 \
  https://default--app-a--web.svc.openshell.internal:18443/
```

Expected: HTTP 200 from the sandbox server. Repeat with `-H 'Host: default--app-b--web.svc.openshell.internal'`: expect HTTP 421 and no sandbox connection. An unknown service or sandbox in SNI closes the connection even though the wildcard certificate matches. No-SNI clients are also rejected.

The app listener preserves existing `Authorization` stripping and opt-in bearer passthrough. Bearer passthrough rejects duplicate or malformed credentials. Service deletion/updates revoke connections on the next accepted configuration poll. If configuration stops refreshing, the 30-second route lease closes ingress connections. A stopped workload closes the listener.

Port-forwarding verifies routing and a selected backend, but bypasses normal Service/network-policy forwarding. Also send the same request from an in-cluster client, using the Service DNS name as the connection target while preserving the public SNI/Host with curl's `--connect-to`:

```shell
curl --cacert /tmp/app-cert.crt \
  --connect-to default--app-a--web.svc.openshell.internal:443:app-a-ingress.openshell.svc.cluster.local:443 \
  https://default--app-a--web.svc.openshell.internal/
```

Supply the public certificate to that client without copying the private key. Verify a second sandbox with a different policy cannot be selected through the first sandbox's listener. Exercise WebSocket echo, route deletion/port updates, supervisor restart, and control-plane operations under application load before claiming the slice complete.

## Limitations

This is HTTP/1.1 plus WebSockets, with 64 connections per supervisor, 10-second TLS/header/connect deadlines, and a 30-second route freshness lease. TLS credentials reload on supervisor recreation. There is no native user/workspace ingress authorization or new ingress policy schema; gateway-authorized declarations form the ingress allowlist. Restrict listener reachability if edge authentication is required.
