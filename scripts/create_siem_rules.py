#!/usr/bin/env python3
"""
Creates Datadog Cloud SIEM detection rules for the Sysdig bridge.
One rule per severity bucket so every Sysdig event generates a signal.

Requirements:
  DD_API_KEY  - Datadog API key
  DD_APP_KEY  - Datadog Application key (needs security_monitoring_rules_write scope)
  DD_API_HOST - Datadog API host (default: api.datadoghq.com)

Usage:
  DD_API_KEY=xxx DD_APP_KEY=yyy python3 scripts/create_siem_rules.py

Datadog API hosts by site:
  US1: api.datadoghq.com
  US3: api.us3.datadoghq.com
  US5: api.us5.datadoghq.com
  EU:  api.datadoghq.eu
  AP1: api.ap1.datadoghq.com
"""

import json
import os
import urllib.request
import urllib.error

DD_API_KEY = os.environ["DD_API_KEY"]
DD_APP_KEY = os.environ["DD_APP_KEY"]
DD_API_HOST = os.getenv("DD_API_HOST", "api.datadoghq.com")

URL = f"https://{DD_API_HOST}/api/v2/security_monitoring/rules"

RULES = [
    {
        "status": "critical",
        "signal_severity": "critical",
        "name": "Sysdig - Critical Severity Events",
    },
    {
        "status": "error",
        "signal_severity": "high",
        "name": "Sysdig - High Severity Events",
    },
    {
        "status": "warning",
        "signal_severity": "medium",
        "name": "Sysdig - Medium Severity Events",
    },
    {
        "status": "info",
        "signal_severity": "info",
        "name": "Sysdig - Info Severity Events",
    },
]


def create_rule(rule: dict) -> dict:
    query_name = f"sysdig_{rule['status']}"
    payload = {
        "name": rule["name"],
        "type": "log_detection",
        "isEnabled": True,
        "queries": [
            {
                "query": f"source:sysdig @status:{rule['status']}",
                "groupByFields": ["@rule"],
                "aggregation": "count",
                "name": query_name,
            }
        ],
        "cases": [
            {
                "condition": f"{query_name} > 0",
                "status": rule["signal_severity"],
                "name": "Sysdig: {{@rule}}",
                "notifications": [],
            }
        ],
        "options": {
            "evaluationWindow": 300,
            "keepAlive": 3600,
            "maxSignalDuration": 86400,
        },
        "message": (
            "Sysdig detected a security event.\n\n"
            "**Rule:** {{@rule}}\n"
            "**Policy:** {{@policy}}\n"
            "**Host:** {{@host}}\n"
            "**Cluster:** {{@cluster}}\n"
            "**User:** {{@user_name}}\n"
            "**Process:** {{@proc_cmdline}}\n"
            "**MITRE Tactics:** {{@mitre_tactics}}\n"
        ),
        "tags": ["source:sysdig", "integration:sysdig-datadog-bridge"],
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        URL,
        data=data,
        headers={
            "Content-Type": "application/json",
            "DD-API-KEY": DD_API_KEY,
            "DD-APPLICATION-KEY": DD_APP_KEY,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            print(f"  created: {rule['name']} (id: {result['id']})")
            return result
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  failed:  {rule['name']} — {e.code} {body}")
        raise


def main():
    print(f"Creating Sysdig SIEM detection rules on {DD_API_HOST}\n")
    for rule in RULES:
        create_rule(rule)
    print("\nDone. Rules are visible in Security → Cloud SIEM → Detection Rules.")


if __name__ == "__main__":
    main()
