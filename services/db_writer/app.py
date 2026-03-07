"""db-writer -- Postgres sidecar for the SmartEnergy stand.

Responsibilities
----------------
1. Periodic telemetry writer: inserts synthetic rows into the ``telemetry``
   table every N seconds so there is always something to backup.
2. Periodic backup: runs ``pg_dump`` to /backups/snapshot_<ts>.sql at a
   configurable interval.
3. Action listener: tails ``data/live/actions.jsonl`` for ``backup_db`` and
   ``restore_db`` actions and executes them for real against Postgres.
4. Corruption simulator: tails ``data/live/actions.jsonl`` -- when the
   Emulator marks the DB as corrupted (via a special internal action
   ``corrupt_db``), the sidecar truncates/corrupts the integrity_check table.
5. Event emitter: writes state-change events to ``data/live/events.jsonl``
   and ACKs to ``data/live/actions_applied.jsonl``.
"""

from __future__ import annotations

import json
import logging
import os
import random
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [db-writer] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("db-writer")

# ── config from env ──────────────────────────────────────────────────────────

PG_HOST = os.environ.get("PGHOST", "postgres")
PG_PORT = os.environ.get("PGPORT", "5432")
PG_USER = os.environ.get("PGUSER", "smartenergy")
PG_PASSWORD = os.environ.get("PGPASSWORD", "smartenergy")
PG_DB = os.environ.get("PGDATABASE", "smartenergy")

BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", "/backups"))
BACKUP_INTERVAL = int(os.environ.get("BACKUP_INTERVAL_SEC", "60"))
WRITE_INTERVAL = float(os.environ.get("WRITE_INTERVAL_SEC", "5"))

EVENTS_PATH = Path(os.environ.get("EVENTS_JSONL", "/work/data/live/events.jsonl"))
ACTIONS_PATH = Path(os.environ.get("ACTIONS_PATH", "/work/data/live/actions.jsonl"))
APPLIED_PATH = Path(os.environ.get("APPLIED_PATH", "/work/data/live/actions_applied.jsonl"))

PG_ENV = {
    **os.environ,
    "PGHOST": PG_HOST,
    "PGPORT": PG_PORT,
    "PGUSER": PG_USER,
    "PGPASSWORD": PG_PASSWORD,
    "PGDATABASE": PG_DB,
}


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _wait_for_pg() -> None:
    """Block until Postgres accepts connections."""
    for i in range(60):
        try:
            result = subprocess.run(
                ["pg_isready", "-h", PG_HOST, "-p", PG_PORT, "-U", PG_USER],
                capture_output=True, text=True, env=PG_ENV,
            )
            if result.returncode == 0:
                log.info("Postgres is ready (attempt %d)", i + 1)
                return
        except FileNotFoundError:
            pass
        time.sleep(1)
    log.error("Postgres not ready after 60s, continuing anyway")


# ── event / ACK emitters ────────────────────────────────────────────────────

def _emit_event(event: str, value: str, severity: str = "medium",
                correlation_id: str = "") -> None:
    ev = {
        "timestamp": _now_iso(),
        "source": "db-primary",
        "component": "db",
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
        log.error("Failed to emit event: %s", exc)


def _emit_ack(action_id: str, correlation_id: str, target_component: str,
              action: str, result: str, state_event: str = "",
              error: str = "") -> None:
    ack = {
        "action_id": action_id,
        "correlation_id": correlation_id,
        "target_component": target_component,
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
    except OSError as exc:
        log.error("Failed to emit ACK: %s", exc)


# ── SQL helpers ──────────────────────────────────────────────────────────────

def _psql(sql: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["psql", "-h", PG_HOST, "-p", PG_PORT, "-U", PG_USER, "-d", PG_DB,
         "-c", sql],
        capture_output=True, text=True, env=PG_ENV,
    )


def _pg_dump(output_path: str) -> bool:
    result = subprocess.run(
        ["pg_dump", "-h", PG_HOST, "-p", PG_PORT, "-U", PG_USER, "-d", PG_DB,
         "-f", output_path, "--clean", "--if-exists"],
        capture_output=True, text=True, env=PG_ENV,
    )
    if result.returncode != 0:
        log.error("pg_dump failed: %s", result.stderr)
        return False
    return True


def _pg_restore(sql_path: str) -> bool:
    result = subprocess.run(
        ["psql", "-h", PG_HOST, "-p", PG_PORT, "-U", PG_USER, "-d", PG_DB,
         "-f", sql_path],
        capture_output=True, text=True, env=PG_ENV,
    )
    if result.returncode != 0:
        log.error("psql restore failed: %s", result.stderr)
        return False
    return True


def _verify_integrity() -> bool:
    """Check that the integrity_check table has marker='healthy'."""
    r = _psql("SELECT marker FROM integrity_check LIMIT 1;")
    return "healthy" in r.stdout


# ── latest snapshot helper ───────────────────────────────────────────────────

def _list_snapshots() -> list[str]:
    """Return sorted list of snapshot filenames in BACKUP_DIR."""
    if not BACKUP_DIR.exists():
        return []
    return sorted(
        f.name for f in BACKUP_DIR.glob("snapshot_*.sql")
    )


def _resolve_snapshot(name: str) -> str | None:
    """Resolve snapshot name to full path. 'latest' picks the most recent."""
    if name == "latest" or not name:
        snaps = _list_snapshots()
        if not snaps:
            return None
        return str(BACKUP_DIR / snaps[-1])
    # Try exact name
    candidate = BACKUP_DIR / name
    if candidate.exists():
        return str(candidate)
    # Try with .sql extension
    candidate = BACKUP_DIR / f"{name}.sql"
    if candidate.exists():
        return str(candidate)
    return None


# ── telemetry writer thread ─────────────────────────────────────────────────

def _telemetry_writer() -> None:
    """Insert synthetic telemetry rows periodically."""
    sources = ["meter-17", "meter-22", "inverter-01", "inverter-02", "collector-01"]
    keys = [
        ("voltage", "V", 218.0, 242.0),
        ("power_kw", "kW", 0.0, 55.0),
        ("frequency_hz", "Hz", 49.8, 50.2),
        ("temperature_c", "C", 20.0, 65.0),
    ]
    while True:
        try:
            src = random.choice(sources)
            k, unit, lo, hi = random.choice(keys)
            val = round(random.uniform(lo, hi), 2)
            _psql(
                f"INSERT INTO telemetry (source, component, key, value, unit) "
                f"VALUES ('{src}', 'edge', '{k}', {val}, '{unit}');"
            )
        except Exception as exc:
            log.debug("Telemetry write failed: %s", exc)
        time.sleep(WRITE_INTERVAL)


# ── periodic backup thread ──────────────────────────────────────────────────

def _backup_loop() -> None:
    """Periodic pg_dump to /backups/snapshot_<timestamp>.sql."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    # Take an initial snapshot immediately
    _do_backup("snapshot_init")
    while True:
        time.sleep(BACKUP_INTERVAL)
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        _do_backup(f"snapshot_{ts}")


def _do_backup(name: str) -> bool:
    path = str(BACKUP_DIR / f"{name}.sql")
    ok = _pg_dump(path)
    if ok:
        _emit_event("db_backup_created", name, "medium")
        log.info("BACKUP: %s -> %s", name, path)
    else:
        log.error("BACKUP FAILED: %s", name)
    return ok


# ── action listener thread ─────────────────────────────────────────────────

def _action_listener() -> None:
    """Tail actions.jsonl for backup_db / restore_db / corrupt_db actions."""
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
    action = act.get("action", "")
    action_id = act.get("action_id", "")
    cor_id = act.get("correlation_id", "")
    target = act.get("target_component", "")
    params = act.get("params", {})

    if action == "backup_db" and target == "db":
        name = params.get("name", f"snapshot_{int(time.time())}")
        ok = _do_backup(name)
        _emit_ack(action_id, cor_id, "db", "backup_db",
                  "success" if ok else "failed",
                  "backup_created" if ok else "")

    elif action == "restore_db" and target == "db":
        snap_name = params.get("snapshot", "latest")
        snap_path = _resolve_snapshot(snap_name)
        if snap_path is None:
            log.error("RESTORE FAILED: snapshot '%s' not found", snap_name)
            _emit_event("restore_failed", f"snapshot={snap_name} not_found",
                        "critical", cor_id)
            _emit_ack(action_id, cor_id, "db", "restore_db", "failed",
                      error=f"snapshot {snap_name} not found")
            return

        _emit_event("restore_started", f"snapshot={snap_name}", "critical", cor_id)
        log.info("RESTORE: starting from %s", snap_path)

        ok = _pg_restore(snap_path)
        if ok and _verify_integrity():
            _emit_event("restore_completed", f"snapshot={snap_name}", "medium", cor_id)
            _emit_ack(action_id, cor_id, "db", "restore_db", "success",
                      "restore_completed")
            log.info("RESTORE COMPLETED: integrity verified")
        else:
            _emit_event("restore_failed", f"snapshot={snap_name}", "critical", cor_id)
            _emit_ack(action_id, cor_id, "db", "restore_db", "failed",
                      error="restore or integrity check failed")
            log.error("RESTORE FAILED")

    elif action == "corrupt_db" and target == "db":
        # Simulate corruption: break the integrity_check marker
        _psql("UPDATE integrity_check SET marker='CORRUPTED', updated=now();")
        # Also insert garbage into telemetry
        _psql(
            "INSERT INTO telemetry (source, component, key, value, unit, severity) "
            "VALUES ('CORRUPT', 'db', 'CORRUPTION', -999, 'ERR', 'critical');"
        )
        _emit_event("db_corruption_detected", "integrity_violation", "critical", cor_id)
        log.info("CORRUPTION SIMULATED: integrity_check marker set to CORRUPTED")


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    _wait_for_pg()

    threads = [
        threading.Thread(target=_telemetry_writer, daemon=True, name="telemetry-writer"),
        threading.Thread(target=_backup_loop, daemon=True, name="backup-loop"),
        threading.Thread(target=_action_listener, daemon=True, name="action-listener"),
    ]
    for t in threads:
        t.start()
        log.info("Started thread: %s", t.name)

    log.info(
        "db-writer running: write_interval=%.1fs backup_interval=%ds",
        WRITE_INTERVAL, BACKUP_INTERVAL,
    )

    # Keep main thread alive
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        log.info("Shutting down")


if __name__ == "__main__":
    main()
