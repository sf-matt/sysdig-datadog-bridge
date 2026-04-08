# Sysdig → Datadog Bridge

Receives Sysdig security event webhooks and forwards them to Datadog SIEM via Fluent Bit.

## How it works

```
Sysdig (webhook + Bearer token)
  → Python receiver (port 8080)
  → /logs/events.log
  → Fluent Bit
  → Datadog Logs
```

## Prerequisites

- Docker Hub account (for the receiver image)
- Datadog API key
- Sysdig notification channel (webhook type)

## Configuration

Copy `.env.example` to `.env` and fill in the values:

```sh
cp .env.example .env
```

| Variable | Description |
|---|---|
| `DD_API_KEY` | Datadog API key |
| `DD_LOG_HOST` | Datadog log intake host (see [sites](#datadog-sites)) |
| `WEBHOOK_TOKEN` | Bearer token Sysdig sends in the `Authorization` header |

### Datadog Sites

| Site | DD_LOG_HOST |
|---|---|
| US1 | `http-intake.logs.datadoghq.com` |
| US3 | `http-intake.logs.us3.datadoghq.com` |
| US5 | `http-intake.logs.us5.datadoghq.com` |
| EU  | `http-intake.logs.datadoghq.eu` |
| AP1 | `http-intake.logs.ap1.datadoghq.com` |

## Deploy: Docker Compose

```sh
docker compose -f deploy/docker-compose.yml up -d
```

## Deploy: Kubernetes

1. Base64-encode your secrets:
```sh
echo -n 'your-dd-api-key' | base64
echo -n 'your-webhook-token' | base64
```

2. Fill in `deploy/kubernetes/secret-datadog.yaml` with the encoded values

3. Set `DD_LOG_HOST` in `deploy/kubernetes/configmap-bridge.yaml`

4. Set your image in `deploy/kubernetes/deployment.yaml`

5. Apply:
```sh
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/configmap-bridge.yaml
kubectl apply -f deploy/kubernetes/configmap-fluent-bit.yaml
kubectl apply -f deploy/kubernetes/secret-datadog.yaml
kubectl apply -f deploy/kubernetes/pvc-logs.yaml
kubectl apply -f deploy/kubernetes/deployment.yaml
kubectl apply -f deploy/kubernetes/service.yaml
```

6. Get the external IP:
```sh
kubectl get svc -n sysdig-datadog-bridge
```

## Sysdig Webhook Setup

> Before configuring, ensure your firewall allows inbound traffic from [Sysdig's outbound IPs](https://docs.sysdig.com/en/docs/administration/saas-regions-and-ip-ranges/) for your region.

1. In Sysdig Secure, go to **Integrations → Add Integrations**
2. Select **Webhook — SIEM & Data Platforms**
3. Fill in the fields:
   - **Integration Name:** e.g. `Datadog Bridge`
   - **Endpoint:** `http://<external-ip>/sysdig-webhook`
   - **Authentication:** Bearer Token
   - **Secret:** your `WEBHOOK_TOKEN` value
4. Under **Data to Send**, select the event types you want forwarded
5. Save and use the **Test** button to send a sample event

> Note: Sysdig batches events by time proximity and sends them as JSON arrays in a single request. The receiver handles both single events and arrays.

## Building the Image

The GitHub Actions workflow in `.github/workflows/docker-publish.yml` builds and pushes to Docker Hub automatically on push to `main` or on a version tag.

Requires two GitHub secrets: `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.

To trigger a versioned release:
```sh
git tag v0.1.0 && git push --tags
```

## Datadog Detection Rules

> Coming soon — detection rules and Cloud SIEM signal configuration will be documented here after testing.

## Verifying

```sh
curl -X POST http://<external-ip>/sysdig-webhook \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"eventName":"Test Alert","severity":"high","ruleName":"Test Rule"}'
```

Check Datadog Logs filtered by `source:sysdig`.
