# Datadog Cloud SIEM Setup

## 1. Enable the Log Source

Sysdig events arrive via Fluent Bit as standard Datadog logs. Cloud SIEM must be told to analyze them:

1. In Datadog, go to **Security → Cloud SIEM → Setup**
2. Under **Log Sources**, click **Add a log source**
3. Select **Other Logs**
4. Set the filter to `source:sysdig`
5. Save

## 2. Configure Log Retention

For compliance use cases (SOC2, NIST, HIPAA etc.) configure retention to match your audit requirements:

1. Go to **Logs → Configuration → Indexes**
2. Find or create an index for `source:sysdig`
3. Set retention period (90 days minimum, 1 year for most frameworks)

> Sysdig's own retention is limited — Datadog is the long-term record of all security findings.

## 3. Create Detection Rules

Run the script to create all four severity rules automatically:

### Prerequisites

You need a Datadog **Application Key** with `security_monitoring_rules_write` scope:
- Datadog → **Organization Settings → Application Keys → New Key**

### Run

```sh
DD_API_KEY='your-api-key' \
DD_APP_KEY='your-app-key' \
DD_API_HOST='api.us5.datadoghq.com' \
python3 scripts/create_siem_rules.py
```

`DD_API_HOST` defaults to `api.datadoghq.com` (US1) — adjust for your site:

| Site | DD_API_HOST |
|---|---|
| US1 | `api.datadoghq.com` |
| US3 | `api.us3.datadoghq.com` |
| US5 | `api.us5.datadoghq.com` |
| EU  | `api.datadoghq.eu` |
| AP1 | `api.ap1.datadoghq.com` |

### What gets created

| Rule query | Signal severity | Signal title |
|---|---|---|
| `source:sysdig @severity:high` | High | `Sysdig: {{@rule}}` |
| `source:sysdig @severity:medium` | Medium | `Sysdig: {{@rule}}` |
| `source:sysdig @severity:low` | Low | `Sysdig: {{@rule}}` |
| `source:sysdig @severity:info` | Info | `Sysdig: {{@rule}}` |

Rules are grouped by `@rule` — one signal per unique Sysdig rule firing per 5-minute window. Signal names reflect the specific rule that fired (e.g. `Sysdig: Read sensitive file untrusted`).

> To recreate rules, delete them in **Security → Cloud SIEM → Detection Rules** first — the script skips existing names.

## 4. Compliance Queries

All Sysdig compliance tags are forwarded in `@rule_tags`:

```
source:sysdig @rule_tags:SOC2*
source:sysdig @rule_tags:NIST_800-53*
source:sysdig @rule_tags:HIPAA*
source:sysdig @rule_tags:HITRUST*
source:sysdig @mitre_tactics:*TA0006*
source:sysdig @rule:"Read sensitive file untrusted"
source:sysdig @user_name:root
```
