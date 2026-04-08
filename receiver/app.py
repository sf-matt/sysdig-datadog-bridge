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