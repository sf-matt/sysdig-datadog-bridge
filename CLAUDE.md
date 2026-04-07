# SysdigDatadog Bridge

Webhook bridge that receives Sysdig security events and forwards them to Datadog SIEM via Fluent Bit.

## Architecture

```
Sysdig (webhook POST + Bearer token)
  → receiver/app.py (Python stdlib HTTP server, port 8080)
  → /logs/events.log (JSON Lines)
  → Fluent Bit (tails log file)
  → Datadog Logs intake
```

## Key Files

- `receiver/app.py` — HTTP server, bearer token auth, event normalization, writes JSONL
- `fluent-bit/fluent-bit.conf` — standalone (docker-compose) Fluent Bit config
- `deploy/docker-compose.yml` — local/VM deployment
- `deploy/kubernetes/` — K8s manifests (namespace, deployment, service, secrets, configmaps)

## Environment Variables

| Variable | Used by | Description |
|---|---|---|
| `WEBHOOK_TOKEN` | receiver | Bearer token Sysdig must send in `Authorization` header |
| `DD_API_KEY` | fluent-bit | Datadog API key (secret) |
| `DD_LOG_HOST` | fluent-bit | Datadog log intake hostname (see sites below) |
| `LISTEN_HOST` | receiver | Bind address (default `0.0.0.0`) |
| `LISTEN_PORT` | receiver | Bind port (default `8080`) |
| `LOG_PATH` | receiver | Path to write events (default `/logs/events.log`) |

### Datadog Sites

| Site | DD_LOG_HOST |
|---|---|
| US1 | `http-intake.logs.datadoghq.com` |
| US3 | `http-intake.logs.us3.datadoghq.com` |
| US5 | `http-intake.logs.us5.datadoghq.com` |
| EU  | `http-intake.logs.datadoghq.eu` |
| AP1 | `http-intake.logs.ap1.datadoghq.com` |

## Local Dev (docker-compose)

```sh
cp .env.example .env
# fill in DD_API_KEY, DD_LOG_HOST, WEBHOOK_TOKEN
docker compose -f deploy/docker-compose.yml up
```

Test the webhook:
```sh
curl -X POST http://localhost:8080/sysdig-webhook \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"eventName":"Test","severity":"high","ruleName":"Test Rule"}'
```

## Kubernetes Deploy

```sh
# 1. Fill placeholders in secret-datadog.yaml
echo -n 'your-dd-api-key' | base64   # → DD_API_KEY
echo -n 'your-webhook-token' | base64  # → WEBHOOK_TOKEN

# 2. Set your DD site in configmap-bridge.yaml (DD_LOG_HOST)

# 3. Set your image in deployment.yaml

# 4. Apply
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/configmap-bridge.yaml
kubectl apply -f deploy/kubernetes/configmap-fluent-bit.yaml
kubectl apply -f deploy/kubernetes/secret-datadog.yaml
kubectl apply -f deploy/kubernetes/pvc-logs.yaml
kubectl apply -f deploy/kubernetes/deployment.yaml
kubectl apply -f deploy/kubernetes/service.yaml
```

## Sysdig Webhook Config

In the Sysdig UI, create a webhook notification channel pointing to the LoadBalancer IP/hostname on port 80. Add a custom header:

```
Authorization: Bearer <WEBHOOK_TOKEN value>
```

## Event Normalization

Incoming Sysdig fields mapped to output:

| Sysdig field | Output field |
|---|---|
| `eventName` / `name` | `title` |
| `details` / `body` | `message` |
| `severity` | `severity` + `status` (low→info, medium→warning, high/critical→error) |
| `ruleName` | `rule` |
| `policyName` | `policy` |
| `eventUrl` | `event_url` |
| `scope` (parsed) | `cluster`, `node` |
