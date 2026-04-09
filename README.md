# Sysdig → Datadog Bridge

Receives Sysdig security event webhooks and forwards them to Datadog SIEM via Fluent Bit.

## How it works

```
Sysdig Event Forwarder (webhook + Bearer token)
  → Python receiver (port 8080)
  → /logs/events.log
  → Fluent Bit
  → Datadog Logs (source:sysdig)
```

The receiver normalizes Sysdig's event schema and promotes key security fields (rule, MITRE tags, process, user, cluster) to top-level log attributes so they can be targeted by Datadog Cloud SIEM detection rules.

## Prerequisites

- Docker Hub account (to host the receiver image)
- Datadog API key
- Sysdig Secure access with the Event Forwarder enabled

## Configuration

Copy `.env.example` to `.env` and fill in the values:

```sh
cp .env.example .env
```

| Variable | Description |
|---|---|
| `DD_API_KEY` | Datadog API key |
| `DD_LOG_HOST` | Datadog log intake host (see [sites](#datadog-sites)) |
| `WEBHOOK_TOKEN` | Shared secret — Sysdig sends this as `Authorization: Bearer <token>` |

### Datadog Sites

| Site | DD_LOG_HOST |
|---|---|
| US1 | `http-intake.logs.datadoghq.com` |
| US3 | `http-intake.logs.us3.datadoghq.com` |
| US5 | `http-intake.logs.us5.datadoghq.com` |
| EU  | `http-intake.logs.datadoghq.eu` |
| AP1 | `http-intake.logs.ap1.datadoghq.com` |

## Deploy: Kubernetes

**1. Set your Datadog site**

Edit `deploy/kubernetes/configmap-bridge.yaml` and set `DD_LOG_HOST` to match your org.

**2. Set your image**

Edit `deploy/kubernetes/deployment.yaml` and set your Docker Hub image path.

**3. Apply manifests**

```sh
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/configmap-bridge.yaml
kubectl apply -f deploy/kubernetes/configmap-fluent-bit.yaml
kubectl apply -f deploy/kubernetes/pvc-logs.yaml
kubectl apply -f deploy/kubernetes/deployment.yaml
kubectl apply -f deploy/kubernetes/service.yaml
```

**4. Create the secret**

Use `--from-literal` — do NOT pre-base64-encode the values, kubectl handles encoding automatically:

```sh
kubectl create secret generic datadog-secret \
  -n sysdig-datadog-bridge \
  --from-literal=DD_API_KEY='your-datadog-api-key' \
  --from-literal=WEBHOOK_TOKEN='your-webhook-token' \
  --save-config \
  --dry-run=client -o yaml | kubectl apply -f -
```

**5. Get the external IP**

```sh
kubectl get svc -n sysdig-datadog-bridge
```

> If Sysdig requires a hostname instead of a bare IP, use [nip.io](https://nip.io) — e.g. `http://1.2.3.4.nip.io/sysdig-webhook` resolves to your IP with no DNS setup required.

## Deploy: Docker Compose

```sh
docker compose -f deploy/docker-compose.yml up -d
```

## Sysdig Event Forwarder Setup

> Before configuring, ensure your firewall allows inbound traffic from [Sysdig's outbound IPs](https://docs.sysdig.com/en/docs/administration/saas-regions-and-ip-ranges/) for your region.

1. In Sysdig Secure, go to **Integrations → Add Integrations**
2. Select **Webhook — SIEM & Data Platforms**
3. Fill in the fields:
   - **Integration Name:** e.g. `Datadog Bridge`
   - **Endpoint:** `http://<external-ip-or-hostname>/sysdig-webhook`
   - **Authentication:** Bearer Token
   - **Secret:** your `WEBHOOK_TOKEN` value
4. Under **Data to Send**, select the event types you want forwarded
5. Save and use the **Test** button to send a sample event

> Note: Sysdig batches events by time proximity and sends them as JSON arrays. The receiver handles both single events and arrays.

## Production: Exposing the Endpoint

The LoadBalancer gives you an external IP, but Sysdig requires a valid hostname and HTTPS for production use. Three options:

### Option A — Cloudflare Tunnel (easiest, no domain required)

Free, gives you a real HTTPS hostname with no ingress or cert setup needed.

1. Install cloudflared in your cluster:
```sh
kubectl create namespace cloudflare
helm repo add cloudflare https://cloudflare.github.io/helm-charts
helm install cloudflared cloudflare/cloudflared \
  -n cloudflare \
  --set tunnelToken=<your-tunnel-token>
```
2. Create a tunnel in the [Cloudflare Zero Trust dashboard](https://one.dash.cloudflare.com) and route it to `http://sysdig-datadog-bridge.sysdig-datadog-bridge.svc.cluster.local`
3. Use the assigned `*.trycloudflare.com` URL (or your own domain) as the Sysdig endpoint

### Option B — Own domain + cert-manager (self-contained K8s)

1. Point a DNS A record at the LoadBalancer IP
2. Install cert-manager:
```sh
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
```
3. Create a `ClusterIssuer` for Let's Encrypt and an `Ingress` resource for the bridge — cert-manager handles TLS automatically

### Option C — Cloud provider managed certificate

If you're on EKS, GKE, or AKS, you can annotate the Service or Ingress to provision a managed TLS certificate from ACM (AWS), Google-managed SSL, or Azure. No cert-manager required.

> **nip.io** (`http://<ip>.nip.io/sysdig-webhook`) is fine for testing only — it has no authentication and resolves to your IP publicly.

## Building the Image

The GitHub Actions workflow in `.github/workflows/docker-publish.yml` builds and pushes to Docker Hub automatically on push to `main` or on a version tag.

Requires two GitHub secrets: `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.

To trigger a versioned release:
```sh
git tag v0.1.0 && git push --tags
```

## Datadog Log Schema

Events land in Datadog Logs under `source:sysdig` with these top-level attributes:

| Attribute | Description | Example |
|---|---|---|
| `rule` | Falco rule name | `Read sensitive file untrusted` |
| `policy` | Sysdig policy name | `Sysdig Runtime Notable Events` |
| `status` | DD log level (mapped from severity) | `warning` |
| `sysdig_severity` | Raw Sysdig integer severity (1-7) | `5` |
| `cluster` | Kubernetes cluster name | `kubernetes` |
| `node` | Kubernetes node name | `cp` |
| `host` | Host name | `cp` |
| `container_name` | Container name | `host` |
| `proc_name` | Process name | `cat` |
| `proc_cmdline` | Full process command | `cat /etc/shadow` |
| `user_name` | User that triggered the event | `root` |
| `mitre_tactics` | MITRE ATT&CK tactic tags | `["MITRE_TA0006_credential_access"]` |
| `mitre_techniques` | MITRE ATT&CK technique tags | `["MITRE_T1552_unsecured_credentials"]` |
| `message` | Full Falco output string | `Sensitive file /etc/shadow opened...` |

### Sysdig Severity Mapping

| Sysdig integer | Sysdig label | Datadog log status | Datadog SIEM signal |
|---|---|---|---|
| 0-3 | High | `error` | `high` |
| 4-5 | Medium | `warning` | `medium` |
| 6 | Low | `info` | `low` |
| 7 | Info | `info` | `info` |

## Datadog Cloud SIEM Setup

### 1. Enable the Log Source

Sysdig events arrive via Fluent Bit as standard Datadog logs — no additional log pipeline setup is needed. However, Cloud SIEM must be told to analyze them:

1. In Datadog, go to **Security → Cloud SIEM → Setup**
2. Under **Log Sources**, click **Add a log source**
3. Select **Other Logs**
4. Set the filter to `source:sysdig`
5. Save — Cloud SIEM will now analyze all incoming Sysdig events for signal generation

### 2. Configure Log Retention

By default Datadog log retention is short. For compliance use cases (SOC2, NIST, HIPAA etc.) you need logs retained long enough to satisfy your audit requirements.

1. In Datadog, go to **Logs → Configuration → Indexes**
2. Find or create an index for `source:sysdig`
3. Set the retention period to match your compliance requirement (typically 90 days minimum, 1 year for many frameworks)

> This is important — Sysdig's own retention is limited. Datadog is the long-term record of all security findings.

### 3. Create Detection Rules

Datadog signal severity is fixed per rule, not dynamically mapped from a field. Create one rule per severity bucket so every Sysdig event generates a signal with the correct severity.

**Option A — Automated (recommended)**

You'll need a Datadog Application Key with `security_monitoring_rules_write` scope:
- Datadog → **Organization Settings → Application Keys → New Key**

```sh
DD_API_KEY='your-api-key' \
DD_APP_KEY='your-app-key' \
DD_API_HOST='api.us5.datadoghq.com' \
python3 scripts/create_siem_rules.py
```

This creates all four rules in one shot. `DD_API_HOST` defaults to `api.datadoghq.com` (US1) — adjust for your site.

**Option B — Manual**

Go to **Security → Cloud SIEM → Detection Rules → New Rule → Log Detection** and create four rules:

| Rule query | Signal severity | Signal title |
|---|---|---|
| `source:sysdig @severity:high` | High | `Sysdig: {{@rule}}` |
| `source:sysdig @severity:medium` | Medium | `Sysdig: {{@rule}}` |
| `source:sysdig @severity:low` | Low | `Sysdig: {{@rule}}` |
| `source:sysdig @severity:info` | Info | `Sysdig: {{@rule}}` |

For each rule:
- **Group by:** `@rule` — one signal per unique Sysdig rule firing
- **Evaluation window:** 5 minutes
- **Signal title:** `Sysdig: {{@rule}}` — signal name reflects the actual finding

This means every event Sysdig sends becomes a signal, severity automatically reflects the Sysdig rating, and signals are named by the specific rule that fired.

### 4. Compliance Queries

All Sysdig compliance framework tags are forwarded in `@rule_tags` and can be used to query the full audit trail:

```
# SOC2
source:sysdig @rule_tags:SOC2*

# NIST 800-53
source:sysdig @rule_tags:NIST_800-53*

# HIPAA
source:sysdig @rule_tags:HIPAA*

# HITRUST
source:sysdig @rule_tags:HITRUST*

# MITRE credential access
source:sysdig @mitre_tactics:*TA0006*

# Specific rule across all time
source:sysdig @rule:"Read sensitive file untrusted"

# All root activity
source:sysdig @user_name:root
```

These queries work in both Datadog Logs (full event detail) and Cloud SIEM (correlated signals), giving auditors a complete picture of security findings against each compliance framework.

## Debugging

Enable raw payload logging without rebuilding the image:

```sh
kubectl set env deployment/sysdig-datadog-bridge \
  -n sysdig-datadog-bridge -c receiver DEBUG=true

kubectl logs -n sysdig-datadog-bridge \
  -l app=sysdig-datadog-bridge -c receiver -f
```

Disable when done:
```sh
kubectl set env deployment/sysdig-datadog-bridge \
  -n sysdig-datadog-bridge -c receiver DEBUG-
```

## Verifying

```sh
curl -X POST http://<external-ip>/sysdig-webhook \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"eventName":"Test Alert","severity":"high","ruleName":"Test Rule"}'
```

Check Datadog Logs filtered by `source:sysdig`.
