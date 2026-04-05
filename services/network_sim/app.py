"""network-sim -- lightweight network condition simulator.

Provides HTTP endpoints AND action listener for network state control.
Generates state-change events into data/live/events.jsonl so the Analyzer
can observe them. Writes ACKs to data/live/actions_applied.jsonl.

Endpoints
---------
GET  /status              -> current network state JSON
POST /degrade             -> apply latency/drop_rate/disconnect
POST /reset               -> return to healthy defaults
GET  /healthz             -> 200 OK

Action Listener
---------------
Tails data/live/actions.jsonl for:
- degrade_network (target_component=network)
- reset_network (target_component=network)

Writes ACKs to data/live/actions_applied.jsonl after execution.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("network-sim")

# -- state --------------------------------------------------------------------

_state_lock = threading.Lock()
_state = {
    "latency_ms": 0,
    "drop_rate": 0.0,
    "disconnected": False,
    "ttl_sec": 0,
    "degraded_since": None,
}

EVENTS_PATH = Path(os.environ.get("EVENTS_JSONL", "/work/data/live/events.jsonl"))
ACTIONS_PATH = Path(os.environ.get("ACTIONS_PATH", "/work/data/live/actions.jsonl"))
APPLIED_PATH = Path(os.environ.get("APPLIED_PATH", "/work/data/live/actions_applied.jsonl"))


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit_event(event: str, value: str, severity: str = "high", correlation_id: str = "") -> None:
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
        EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(EVENTS_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev, ensure_ascii=False, separators=(",", ":")) + "\n")
            fh.flush()
    except OSError as exc:
        log.error("Failed to write event: %s", exc)


def _emit_ack(
    action_id: str,
    correlation_id: str,
    action: str,
    result: str,
    state_event: str = "",
    error: str = "",
) -> None:
    """Append an ACK to actions_applied.jsonl."""
    ack = {
        "action_id": action_id,
        "correlation_id": correlation_id,
        "target_component": "network",
        "action": action,
        "applied_ts_utc": _now_iso(),
        "result": result,
        "error": error,
        "state_event": state_event,
    }
    try:
        APPLIED_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(APPLIED_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(ack, ensure_ascii=False, separators=(",", ":")) + "\n")
            fh.flush()
        log.info(
            "ACK emitted: action_id=%s result=%s state_event=%s", action_id, result, state_event
        )
    except OSError as exc:
        log.error("Failed to emit ACK: %s", exc)


def _apply_degrade(
    latency_ms: int,
    drop_rate: float,
    ttl_sec: int,
    disconnected: bool = False,
    correlation_id: str = "",
    action_id: str = "",
) -> dict:
    with _state_lock:
        _state["latency_ms"] = latency_ms
        _state["drop_rate"] = drop_rate
        _state["disconnected"] = disconnected
        _state["ttl_sec"] = ttl_sec
        _state["degraded_since"] = time.monotonic()
        snap = dict(_state)
    val = (
        f"latency_ms={latency_ms},drop_rate={drop_rate},"
        f"disconnected={disconnected},ttl_sec={ttl_sec}"
    )
    _emit_event("network_degraded", val, "high", correlation_id)
    log.info("DEGRADED: %s", val)

    # Emit ACK if action_id provided (from action listener)
    if action_id:
        _emit_ack(action_id, correlation_id, "degrade_network", "success", "network_degraded")

    return snap


def _apply_reset(correlation_id: str = "", action_id: str = "") -> dict:
    with _state_lock:
        _state["latency_ms"] = 0
        _state["drop_rate"] = 0.0
        _state["disconnected"] = False
        _state["ttl_sec"] = 0
        _state["degraded_since"] = None
        snap = dict(_state)
    _emit_event("network_reset_applied", "healthy", "medium", correlation_id)
    log.info("RESET: network healthy")

    # Emit ACK if action_id provided (from action listener)
    if action_id:
        _emit_ack(action_id, correlation_id, "reset_network", "success", "network_reset_applied")

    return snap


def _get_status() -> dict:
    with _state_lock:
        snap = dict(_state)
    snap.pop("degraded_since", None)
    return snap


# -- TTL expiry thread --------------------------------------------------------


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


# -- Action listener thread ---------------------------------------------------


def _action_listener() -> None:
    """Tail actions.jsonl for degrade_network / reset_network actions."""
    offset = 0
    while True:
        try:
            if ACTIONS_PATH.exists():
                size = ACTIONS_PATH.stat().st_size
                if size > offset:
                    with open(ACTIONS_PATH, encoding="utf-8") as fh:
                        fh.seek(offset)
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                act = json.loads(line)
                                _handle_action(act)
                            except (json.JSONDecodeError, KeyError) as exc:
                                log.debug("Skip bad action: %s", exc)
                        offset = fh.tell()
        except OSError as exc:
            log.debug("Action read error: %s", exc)
        time.sleep(1.0)


def _handle_action(act: dict) -> None:
    """Process a single action from actions.jsonl."""
    action = act.get("action", "")
    action_id = act.get("action_id", "")
    cor_id = act.get("correlation_id", "")
    target = act.get("target_component", "")
    params = act.get("params", {})

    # Only handle network-targeted actions
    if target != "network":
        return

    if action == "degrade_network":
        latency_ms = int(params.get("latency_ms", 200))
        drop_rate = float(params.get("drop_rate", 0.1))
        ttl_sec = int(params.get("ttl_sec", 120))
        disconnected = bool(params.get("disconnected", False))
        _apply_degrade(
            latency_ms=latency_ms,
            drop_rate=drop_rate,
            ttl_sec=ttl_sec,
            disconnected=disconnected,
            correlation_id=cor_id,
            action_id=action_id,
        )
        log.info(
            "ACTION degrade_network applied: latency=%dms drop=%.2f ttl=%ds",
            latency_ms,
            drop_rate,
            ttl_sec,
        )

    elif action == "reset_network":
        _apply_reset(correlation_id=cor_id, action_id=action_id)
        log.info("ACTION reset_network applied")


# -- HTTP handler -------------------------------------------------------------


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

    # Start background threads
    threads = [
        threading.Thread(target=_ttl_watcher, daemon=True, name="ttl-watcher"),
        threading.Thread(target=_action_listener, daemon=True, name="action-listener"),
    ]
    for t in threads:
        t.start()
        log.info("Started thread: %s", t.name)

    # Start HTTP server
    server = HTTPServer(("0.0.0.0", port), Handler)
    log.info("network-sim listening on :%d", port)
    log.info("  events -> %s", EVENTS_PATH)
    log.info("  actions <- %s", ACTIONS_PATH)
    log.info("  ACKs -> %s", APPLIED_PATH)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
