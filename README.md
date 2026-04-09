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
| `DD_LOG_HOST` | Datadog log intake host (see [Datadog Sites](#datadog-sites)) |
| `WEBHOOK_TOKEN` | Shared secret — Sysdig sends this as `Authorization: Bearer <token>` |

### Datadog Sites

| Site | DD_LOG_HOST |
|---|---|
| US1 | `http-intake.logs.datadoghq.com` |
| US3 | `http-intake.logs.us3.datadoghq.com` |
| US5 | `http-intake.logs.us5.datadoghq.com` |
| EU  | `http-intake.logs.datadoghq.eu` |
| AP1 | `http-intake.logs.ap1.datadoghq.com` |

## Deployment

**[Kubernetes](deploy/kubernetes/README.md)** — recommended for production. Covers applying manifests, creating secrets, getting the external IP, debug mode, and production endpoint options (Cloudflare Tunnel, cert-manager, cloud provider certs).

**[Docker Compose](deploy/README.md)** — for local development or VM deployments. Simpler setup using a bind-mounted log volume and a `.env` file for configuration.

## Building the Image

The GitHub Actions workflow in `.github/workflows/docker-publish.yml` builds and pushes to Docker Hub automatically on push to `main` or on a version tag.

Requires two GitHub secrets: `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.

To trigger a versioned release:
```sh
git tag v1.0.0 && git push --tags
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

## Datadog Log Schema

Events land in Datadog Logs under `source:sysdig` with these top-level attributes:

| Attribute | Description | Example |
|---|---|---|
| `rule` | Falco rule name | `Read sensitive file untrusted` |
| `policy` | Sysdig policy name | `Sysdig Runtime Notable Events` |
| `severity` | Sysdig severity label | `high`, `medium`, `low`, `info` |
| `status` | Datadog log level | `error`, `warning`, `info` |
| `cluster` | Kubernetes cluster name | `kubernetes` |
| `node` | Kubernetes node name | `cp` |
| `host` | Host name | `cp` |
| `container_name` | Container name | `nginx` |
| `proc_name` | Process name | `cat` |
| `proc_cmdline` | Full process command | `cat /etc/shadow` |
| `user_name` | User that triggered the event | `root` |
| `mitre_tactics` | MITRE ATT&CK tactic tags | `["MITRE_TA0006_credential_access"]` |
| `mitre_techniques` | MITRE ATT&CK technique tags | `["MITRE_T1552_unsecured_credentials"]` |
| `message` | Full Falco output string | `Sensitive file /etc/shadow opened...` |

### Severity Mapping

| Sysdig integer | Sysdig label | Datadog log status | Datadog SIEM signal |
|---|---|---|---|
| 0-3 | High | `error` | `high` |
| 4-5 | Medium | `warning` | `medium` |
| 6 | Low | `info` | `low` |
| 7 | Info | `info` | `info` |

## Datadog Cloud SIEM

See **[scripts/README.md](scripts/README.md)** for the full setup guide. This covers:
- Enabling `source:sysdig` as a Cloud SIEM log source
- Configuring log retention for compliance (SOC2, NIST, HIPAA, HITRUST)
- Running the automated script to create all four severity-mapped detection rules
- Compliance query examples using `@rule_tags`, `@mitre_tactics`, and other forwarded fields
