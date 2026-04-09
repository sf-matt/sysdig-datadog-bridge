# Docker Compose Deployment

For local development or VM-based deployments.

## Steps

### 1. Configure environment

```sh
cp .env.example .env
```

Fill in `.env`:

```
DD_API_KEY=your-datadog-api-key
DD_LOG_HOST=http-intake.logs.us5.datadoghq.com
WEBHOOK_TOKEN=your-webhook-token
```

### 2. Set your image

Edit `docker-compose.yml` and set your Docker Hub image path.

### 3. Start

```sh
docker compose -f deploy/docker-compose.yml up -d
```

### 4. Verify

```sh
# Test the webhook
curl -X POST http://localhost:8080/sysdig-webhook \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{"eventName":"Test","severity":"high","ruleName":"Test Rule"}'

# Check logs
docker logs sysdig-webhook-receiver
docker logs sysdig-fluent-bit
```

## Notes

- Logs are written to `../logs/events.log` (bind mount, survives container restarts)
- Fluent Bit config is mounted from `fluent-bit/fluent-bit.conf`
- Set `DEBUG=true` in `.env` to log raw payloads to stdout
