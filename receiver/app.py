import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
LOG_PATH = os.getenv("LOG_PATH", "/logs/events.log")
WEBHOOK_TOKEN = os.getenv("WEBHOOK_TOKEN", "")
DEBUG = os.getenv("DEBUG", "").lower() in ("1", "true", "yes")


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_record(record: dict) -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


def normalize_payload(body: dict) -> dict:
    # Sysdig Event Forwarder schema
    # severity is an integer: 1=emergency,2=alert,3=critical,4=error,5=warning,6=notice,7=debug
    if "content" in body or "labels" in body:
        content = body.get("content", {})
        labels = body.get("labels", {})

        title = content.get("ruleName") or body.get("name") or "Sysdig Event"
        policy = body.get("name")
        message = content.get("output") or policy or title
        rule = content.get("ruleName")
        rule_tags = content.get("ruleTags", [])
        event_type = body.get("type")
        category = body.get("category")
        engine = body.get("engine")
        cluster = labels.get("kubernetes.cluster.name")
        node = labels.get("kubernetes.node.name")
        host = labels.get("host.hostName")
        container_id = body.get("containerId") or content.get("fields", {}).get("container.id")
        container_name = content.get("fields", {}).get("container.name")
        proc_name = content.get("fields", {}).get("proc.name")
        proc_cmdline = content.get("fields", {}).get("proc.cmdline")
        user_name = content.get("fields", {}).get("user.name")
        mitre_tactics = [t for t in rule_tags if t.startswith("MITRE_TA")]
        mitre_techniques = [t for t in rule_tags if t.startswith("MITRE_T") and not t.startswith("MITRE_TA")]

        int_severity_map = {
            1: ("emergency", "critical"),
            2: ("alert", "critical"),
            3: ("critical", "error"),
            4: ("error", "error"),
            5: ("warning", "warning"),
            6: ("notice", "info"),
            7: ("debug", "info"),
        }
        raw_sev = body.get("severity", 6)
        severity_label, status = int_severity_map.get(int(raw_sev), ("info", "info"))

        return {
            "timestamp": body.get("timestampRFC3339Nano") or now_utc(),
            "source": "sysdig",
            "service": "sysdig-webhook-bridge",
            "status": status,
            "severity": severity_label,
            "sysdig_severity": raw_sev,
            "title": title,
            "message": message,
            "rule": rule,
            "policy": policy,
            "event_type": event_type,
            "category": category,
            "engine": engine,
            "cluster": cluster,
            "node": node,
            "host": host,
            "container_id": container_id,
            "container_name": container_name,
            "proc_name": proc_name,
            "proc_cmdline": proc_cmdline,
            "user_name": user_name,
            "mitre_tactics": mitre_tactics,
            "mitre_techniques": mitre_techniques,
            "rule_tags": rule_tags,
            "raw": body,
        }

    # Sysdig Notification Channel schema (legacy)
    title = body.get("eventName") or body.get("name") or "Sysdig Event"
    message = body.get("details") or body.get("body") or title
    severity = str(body.get("severity", "info")).lower()
    rule = body.get("ruleName")
    policy = body.get("policyName")
    event_url = body.get("eventUrl")
    scope = body.get("scope", "")

    severity_map = {
        "low": "info",
        "medium": "warning",
        "high": "error",
        "critical": "error",
    }
    status = severity_map.get(severity, "info")

    cluster = None
    node = None

    if isinstance(scope, str):
        parts = [p.strip() for p in scope.split(",")]
        for p in parts:
            if p.startswith("kubernetes.cluster.name:"):
                cluster = p.split(":", 1)[1].strip()
            elif p.startswith("kubernetes.node.name:"):
                node = p.split(":", 1)[1].strip()

    return {
        "timestamp": now_utc(),
        "source": "sysdig",
        "service": "sysdig-webhook-bridge",
        "status": status,
        "severity": severity,
        "title": title,
        "message": message,
        "rule": rule,
        "policy": policy,
        "cluster": cluster,
        "node": node,
        "event_url": event_url,
        "raw": body,
    }


def normalize_records(payload) -> list[dict]:
    if isinstance(payload, list):
        items = payload
    else:
        items = [payload]

    normalized = []
    for item in items:
        if isinstance(item, dict):
            normalized.append(normalize_payload(item))
        else:
            normalized.append({
                "timestamp": now_utc(),
                "source": "sysdig",
                "service": "sysdig-webhook-bridge",
                "status": "info",
                "severity": "info",
                "title": "Sysdig Event",
                "message": str(item),
                "rule": None,
                "policy": None,
                "cluster": None,
                "node": None,
                "event_url": None,
                "raw": item,
            })
    return normalized


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, body: dict):
        response = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"ok": True})
            return
        self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if self.path != "/sysdig-webhook":
            self._send_json(404, {"ok": False, "error": "not found"})
            return

        if WEBHOOK_TOKEN:
            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer ") or auth_header[7:] != WEBHOOK_TOKEN:
                self._send_json(401, {"ok": False, "error": "unauthorized"})
                return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"ok": False, "error": "invalid content length"})
            return

        raw_body = self.rfile.read(content_length)
        raw_text = raw_body.decode("utf-8", errors="replace")

        try:
            parsed_body = json.loads(raw_text)
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": "invalid json"})
            return

        if DEBUG:
            print(f"DEBUG raw payload: {json.dumps(parsed_body, indent=2)}", flush=True)

        try:
            records = normalize_records(parsed_body)
            for record in records:
                append_record(record)
        except Exception as exc:
            self._send_json(500, {"ok": False, "error": f"write failure: {exc}"})
            return

        self._send_json(200, {"ok": True, "records_written": len(records)})

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"listening on {LISTEN_HOST}:{LISTEN_PORT}, writing to {LOG_PATH}")
    server.serve_forever()