# Kubernetes Deployment

## Prerequisites

- Kubernetes cluster with a default StorageClass
- Docker Hub image built and pushed (see root README)

## Steps

### 1. Set your Datadog site

Edit `configmap-bridge.yaml` and set `DD_LOG_HOST` to match your org:

| Site | DD_LOG_HOST |
|---|---|
| US1 | `http-intake.logs.datadoghq.com` |
| US3 | `http-intake.logs.us3.datadoghq.com` |
| US5 | `http-intake.logs.us5.datadoghq.com` |
| EU  | `http-intake.logs.datadoghq.eu` |
| AP1 | `http-intake.logs.ap1.datadoghq.com` |

### 2. Set your image

Edit `deployment.yaml` and set your Docker Hub image path.

### 3. Apply manifests

```sh
kubectl apply -f namespace.yaml
kubectl apply -f configmap-bridge.yaml
kubectl apply -f configmap-fluent-bit.yaml
kubectl apply -f pvc-logs.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

### 4. Create the secret

Use `--from-literal` — do NOT pre-base64-encode, kubectl handles encoding automatically:

```sh
kubectl create secret generic datadog-secret \
  -n sysdig-datadog-bridge \
  --from-literal=DD_API_KEY='your-datadog-api-key' \
  --from-literal=WEBHOOK_TOKEN='your-webhook-token' \
  --save-config \
  --dry-run=client -o yaml | kubectl apply -f -
```

### 5. Get the external IP

```sh
kubectl get svc -n sysdig-datadog-bridge
```

> If Sysdig requires a hostname instead of a bare IP, use [nip.io](https://nip.io) for testing — e.g. `http://1.2.3.4.nip.io/sysdig-webhook`. See [Production Endpoints](#production-endpoints) for real deployments.

## Verify

```sh
# Check pods are healthy (expect 2/2 Running)
kubectl get pods -n sysdig-datadog-bridge

# Test auth
curl -X POST http://<external-ip>/sysdig-webhook \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"eventName":"Test","severity":"high","ruleName":"Test Rule"}'
```

## Debug Mode

Enable raw payload logging without rebuilding:

```sh
kubectl set env deployment/sysdig-datadog-bridge \
  -n sysdig-datadog-bridge -c receiver DEBUG=true

kubectl logs -n sysdig-datadog-bridge \
  -l app=sysdig-datadog-bridge -c receiver -f
```

Disable:
```sh
kubectl set env deployment/sysdig-datadog-bridge \
  -n sysdig-datadog-bridge -c receiver DEBUG-
```

## Production Endpoints

nip.io is for testing only. For production:

**Option A — Cloudflare Tunnel (easiest, no domain required)**

Free, HTTPS, no ingress or cert setup needed.

1. Install cloudflared in your cluster:
```sh
kubectl create namespace cloudflare
helm repo add cloudflare https://cloudflare.github.io/helm-charts
helm install cloudflared cloudflare/cloudflared \
  -n cloudflare \
  --set tunnelToken=<your-tunnel-token>
```
2. Create a tunnel in the [Cloudflare Zero Trust dashboard](https://one.dash.cloudflare.com) and route it to `http://sysdig-datadog-bridge.sysdig-datadog-bridge.svc.cluster.local`
3. Use the assigned hostname as the Sysdig endpoint

**Option B — Own domain + cert-manager**

1. Point a DNS A record at the LoadBalancer IP
2. Install cert-manager and configure Let's Encrypt
3. Create an Ingress with TLS annotation

**Option C — Cloud provider managed certificate**

Annotate the Service or Ingress for ACM (AWS), Google-managed SSL, or Azure managed certs.

## Gotchas

- Use `--from-literal` for secrets — never pre-base64-encode (causes double-encoding)
- `echo` adds a newline — use `echo -n` if manually encoding anything
- `fsGroup: 1001` on the pod spec is required so the PVC is writable by the non-root container
- Sysdig requires a hostname in the endpoint URL — bare IPs are rejected
