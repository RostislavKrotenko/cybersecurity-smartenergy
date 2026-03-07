"""network-sim -- lightweight network condition simulator.

Provides HTTP endpoints for the Executor to degrade / reset network state.
Generates state-change events into data/live/events.jsonl so the Analyzer
can observe them.

Endpoints
---------
GET  /status              -> current network state JSON
POST /degrade             -> apply latency/drop_rate/disconnect
POST /reset               -> return to healthy defaults
GET  /healthz             -> 200 OK
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("network-sim")

# ── state ────────────────────────────────────────────────────────────────────

_state_lock = threading.Lock()
_state = {
    "latency_ms": 0,
    "drop_rate": 0.0,
    "disconnected": False,
    "ttl_sec": 0,
    "degraded_since": None,
}

EVENTS_PATH = os.environ.get("EVENTS_JSONL", "/work/data/live/events.jsonl")


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit_event(event: str, value: str, severity: str = "high",
                correlation_id: str = "") -> None:
    """Append a state-change event to the shared events.jsonl."""
    ev = {
        "timestamp": _now_iso(),
        "source": "network-sim",
        "component": "network",
        "event": event,
        "key": "action_result",
        "value": value,
        "severity": severity,
        "actor": "system",
        "ip": "",
        "unit": "",
        "tags": "action;state_change",
        "correlation_id": correlation_id,
    }
    try:
        os.makedirs(os.path.dirname(EVENTS_PATH), exist_ok=True)
        with open(EVENTS_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev, ensure_ascii=False, separators=(",", ":")) + "\n")
            fh.flush()
    except OSError as exc:
        log.error("Failed to write event: %s", exc)


def _apply_degrade(latency_ms: int, drop_rate: float, ttl_sec: int,
                   disconnected: bool = False, correlation_id: str = "") -> dict:
    with _state_lock:
        _state["latency_ms"] = latency_ms
        _state["drop_rate"] = drop_rate
        _state["disconnected"] = disconnected
        _state["ttl_sec"] = ttl_sec
        _state["degraded_since"] = time.monotonic()
        snap = dict(_state)
    val = (f"latency_ms={latency_ms},drop_rate={drop_rate},"
           f"disconnected={disconnected},ttl_sec={ttl_sec}")
    _emit_event("network_degraded", val, "high", correlation_id)
    log.info("DEGRADED: %s", val)
    return snap


def _apply_reset(correlation_id: str = "") -> dict:
    with _state_lock:
        _state["latency_ms"] = 0
        _state["drop_rate"] = 0.0
        _state["disconnected"] = False
        _state["ttl_sec"] = 0
        _state["degraded_since"] = None
        snap = dict(_state)
    _emit_event("network_reset_applied", "healthy", "medium", correlation_id)
    log.info("RESET: network healthy")
    return snap


def _get_status() -> dict:
    with _state_lock:
        snap = dict(_state)
    snap.pop("degraded_since", None)
    return snap


# ── TTL expiry thread ────────────────────────────────────────────────────────

def _ttl_watcher() -> None:
    """Background thread: auto-reset when TTL expires."""
    while True:
        time.sleep(1.0)
        with _state_lock:
            since = _state["degraded_since"]
            ttl = _state["ttl_sec"]
        if since is not None and ttl > 0:
            elapsed = time.monotonic() - since
            if elapsed >= ttl:
                _apply_reset()
                log.info("TTL expired after %ds, auto-reset", int(elapsed))


# ── HTTP handler ─────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def _send_json(self, data: dict, code: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw)

    def do_GET(self) -> None:
        if self.path == "/status":
            self._send_json(_get_status())
        elif self.path == "/healthz":
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        if self.path == "/degrade":
            body = self._read_body()
            result = _apply_degrade(
                latency_ms=int(body.get("latency_ms", 200)),
                drop_rate=float(body.get("drop_rate", 0.1)),
                ttl_sec=int(body.get("ttl_sec", 120)),
                disconnected=bool(body.get("disconnected", False)),
                correlation_id=body.get("correlation_id", ""),
            )
            self._send_json(result)
        elif self.path == "/reset":
            body = self._read_body()
            result = _apply_reset(
                correlation_id=body.get("correlation_id", ""),
            )
            self._send_json(result)
        else:
            self._send_json({"error": "not found"}, 404)


def main() -> None:
    port = int(os.environ.get("PORT", "8090"))
    t = threading.Thread(target=_ttl_watcher, daemon=True)
    t.start()
    server = HTTPServer(("0.0.0.0", port), Handler)
    log.info("network-sim listening on :%d", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
