# SysdigDatadog Bridge

Webhook bridge that receives Sysdig security events and forwards them to Datadog SIEM via Fluent Bit.

## Architecture

```
Sysdig Event Forwarder (webhook POST + Bearer token)
  → receiver/app.py (Python stdlib HTTP server, port 8080)
  → /logs/events.log (JSON Lines)
  → Fluent Bit (tails log file)
  → Datadog Logs intake (source:sysdig)
```

## Key Files

- `receiver/app.py` — HTTP server, bearer token auth, event normalization, writes JSONL
- `receiver/Dockerfile` — non-root (uid 1001), includes HEALTHCHECK
- `fluent-bit/fluent-bit.conf` — standalone (docker-compose) Fluent Bit config
- `deploy/docker-compose.yml` — local/VM deployment
- `deploy/kubernetes/` — K8s manifests (namespace, deployment, service, secrets, configmaps, PVC)
- `.github/workflows/docker-publish.yml` — builds multi-arch image and pushes to Docker Hub on main/tag

## Environment Variables

| Variable | Used by | Description |
|---|---|---|
| `WEBHOOK_TOKEN` | receiver | Bearer token Sysdig must send in `Authorization` header |
| `DD_API_KEY` | fluent-bit | Datadog API key (secret) |
| `DD_LOG_HOST` | fluent-bit | Datadog log intake hostname |
| `DEBUG` | receiver | Set to `true` to log raw payloads to stdout |
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

## Sysdig Event Schema

The receiver handles two Sysdig schemas:

**Event Forwarder** (primary) — detected by presence of `content` or `labels` keys:
- `severity` is an integer (1-7), not a string
- `content.ruleName` → `rule`
- `name` → `policy`
- `content.output` → `message`
- `labels.kubernetes.cluster.name` → `cluster`
- `labels.kubernetes.node.name` → `node`
- `content.fields.*` → `proc_name`, `proc_cmdline`, `user_name`, `container_name`
- `content.ruleTags` → `mitre_tactics`, `mitre_techniques`, `rule_tags`

**Notification Channel** (legacy fallback):
- `eventName` / `name` → `title`
- `details` / `body` → `message`
- `severity` is a string (low/medium/high/critical)
- `scope` parsed for cluster/node

## Severity Mapping (Event Forwarder)

From Sysdig API docs: 0-3=High, 4-5=Medium, 6=Low, 7=Info

| Sysdig int | Sysdig label | DD log status | DD SIEM signal |
|---|---|---|---|
| 0-3 | High | `error` | `high` |
| 4-5 | Medium | `warning` | `medium` |
| 6 | Low | `info` | `low` |
| 7 | Info | `info` | `info` |

## Kubernetes Deploy

**Critical gotchas learned in testing:**
- Use `kubectl create secret --from-literal` with raw values — never pre-base64-encode, it causes double-encoding
- `echo` adds a newline — always use `echo -n` if manually encoding anything
- `fsGroup: 1001` on the pod spec is required so the PVC is writable by the non-root container
- GH Action build context must be `receiver` not `.` (Dockerfile is in a subdirectory)
- Sysdig requires a hostname in the endpoint URL — use nip.io for quick DNS: `http://<ip>.nip.io/sysdig-webhook`

**Apply order:**
```sh
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/configmap-bridge.yaml
kubectl apply -f deploy/kubernetes/configmap-fluent-bit.yaml
kubectl apply -f deploy/kubernetes/secret-datadog.yaml
kubectl apply -f deploy/kubernetes/pvc-logs.yaml
kubectl apply -f deploy/kubernetes/deployment.yaml
kubectl apply -f deploy/kubernetes/service.yaml
```

**Create secret correctly:**
```sh
kubectl create secret generic datadog-secret \
  -n sysdig-datadog-bridge \
  --from-literal=DD_API_KEY='your-key' \
  --from-literal=WEBHOOK_TOKEN='your-token' \
  --save-config \
  --dry-run=client -o yaml | kubectl apply -f -
```

**Debug mode (no rebuild needed):**
```sh
kubectl set env deployment/sysdig-datadog-bridge -n sysdig-datadog-bridge -c receiver DEBUG=true
kubectl set env deployment/sysdig-datadog-bridge -n sysdig-datadog-bridge -c receiver DEBUG-
```

## Sysdig Webhook Config

In Sysdig Secure: **Integrations → Add Integrations → Webhook — SIEM & Data Platforms**
- Authentication: Bearer Token
- Secret: raw WEBHOOK_TOKEN value

## Datadog Detection Rule Queries

```
source:sysdig @rule:"Read sensitive file untrusted"
source:sysdig @mitre_tactics:*TA0006*
source:sysdig @status:error
source:sysdig @user_name:root @proc_cmdline:*shadow*
```
