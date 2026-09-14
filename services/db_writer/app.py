"""Сервіс db-writer — допоміжний Postgres-контейнер для стенда SmartEnergy.

Обов'язки:
1. Періодично записувати синтетичну телеметрію в таблицю ``telemetry``.
2. Періодично запускати ``pg_dump`` у /backups/snapshot_<ts>.sql.
3. Читати ``data/live/actions.jsonl`` у tail-режимі для ``backup_db`` і
   ``restore_db`` та виконувати їх у Postgres.
4. Симулювати пошкодження БД через внутрішню дію ``corrupt_db``.
5. Записувати події зміни стану в ``data/live/events.jsonl`` і ACK у
   ``data/live/actions_applied.jsonl``.
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

PG_HOST = os.environ.get("PGHOST", "postgres")
PG_PORT = os.environ.get("PGPORT", "5432")
PG_USER = os.environ.get("PGUSER", "smartenergy")
PG_PASSWORD = os.environ.get("PGPASSWORD", "smartenergy")
PG_DB = os.environ.get("PGDATABASE", "smartenergy")

BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", "/backups"))
BACKUP_INTERVAL = int(os.environ.get("BACKUP_INTERVAL_SEC", "60"))
BACKUP_RETENTION = int(os.environ.get("BACKUP_RETENTION", "5"))
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
    """Чекає, доки Postgres почне приймати підключення."""
    for i in range(60):
        try:
            result = subprocess.run(
                ["pg_isready", "-h", PG_HOST, "-p", PG_PORT, "-U", PG_USER],
                capture_output=True,
                text=True,
                env=PG_ENV,
            )
            if result.returncode == 0:
                log.info("Postgres is ready (attempt %d)", i + 1)
                return
        except FileNotFoundError:
            pass
        time.sleep(1)
    log.error("Postgres not ready after 60s, continuing anyway")


def _emit_event(event: str, value: str, severity: str = "medium", correlation_id: str = "") -> None:
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
        log.error("Не вдалося записати подію: %s", exc)


def _emit_ack(
    action_id: str,
    correlation_id: str,
    target_component: str,
    action: str,
    result: str,
    state_event: str = "",
    error: str = "",
) -> None:
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
        log.error("Не вдалося записати ACK: %s", exc)


def _psql(sql: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["psql", "-h", PG_HOST, "-p", PG_PORT, "-U", PG_USER, "-d", PG_DB, "-c", sql],
        capture_output=True,
        text=True,
        env=PG_ENV,
    )


def _pg_dump(output_path: str) -> bool:
    result = subprocess.run(
        [
            "pg_dump",
            "-h",
            PG_HOST,
            "-p",
            PG_PORT,
            "-U",
            PG_USER,
            "-d",
            PG_DB,
            "-f",
            output_path,
            "--clean",
            "--if-exists",
        ],
        capture_output=True,
        text=True,
        env=PG_ENV,
    )
    if result.returncode != 0:
        log.error("pg_dump failed: %s", result.stderr)
        return False
    return True


def _pg_restore(sql_path: str) -> bool:
    result = subprocess.run(
        ["psql", "-h", PG_HOST, "-p", PG_PORT, "-U", PG_USER, "-d", PG_DB, "-f", sql_path],
        capture_output=True,
        text=True,
        env=PG_ENV,
    )
    if result.returncode != 0:
        log.error("psql restore failed: %s", result.stderr)
        return False
    return True


def _verify_integrity() -> bool:
    """Перевіряє, що таблиця integrity_check має marker='healthy'."""
    r = _psql("SELECT marker FROM integrity_check LIMIT 1;")
    return "healthy" in r.stdout


def _list_snapshot_paths() -> list[Path]:
    """Повертає SQL backup-файли від найстарішого до найновішого."""
    if not BACKUP_DIR.exists():
        return []
    return sorted(
        BACKUP_DIR.glob("*.sql"),
        key=lambda f: (f.stat().st_mtime, f.name),
    )


def _list_snapshots() -> list[str]:
    """Повертає відсортований список назв backup-файлів у BACKUP_DIR."""
    return [f.name for f in _list_snapshot_paths()]


def _prune_old_snapshots() -> list[str]:
    """Залишає тільки найновіші BACKUP_RETENTION SQL backup-файли."""
    retention = max(1, BACKUP_RETENTION)
    snapshots = _list_snapshot_paths()
    old_snapshots = snapshots[: max(0, len(snapshots) - retention)]
    removed = []

    for snapshot in old_snapshots:
        try:
            snapshot.unlink()
            removed.append(snapshot.name)
            log.info("BACKUP RETENTION: removed old snapshot %s", snapshot.name)
        except OSError as exc:
            log.warning("BACKUP RETENTION: failed to remove %s: %s", snapshot.name, exc)

    return removed


def _resolve_snapshot(name: str) -> str | None:
    """Перетворює назву snapshot на повний шлях; latest означає найновіший."""
    if name == "latest" or not name:
        snaps = _list_snapshots()
        if not snaps:
            return None
        return str(BACKUP_DIR / snaps[-1])
    candidate = BACKUP_DIR / name
    if candidate.exists():
        return str(candidate)
    candidate = BACKUP_DIR / f"{name}.sql"
    if candidate.exists():
        return str(candidate)
    return None


def _telemetry_writer() -> None:
    """Періодично додає синтетичні рядки телеметрії."""
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
            log.debug("Не вдалося записати телеметрію: %s", exc)
        time.sleep(WRITE_INTERVAL)


def _backup_loop() -> None:
    """Періодично виконує pg_dump у /backups/snapshot_<timestamp>.sql."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    _do_backup("snapshot_init")
    while True:
        time.sleep(BACKUP_INTERVAL)
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        _do_backup(f"snapshot_{ts}")


def _do_backup(name: str) -> bool:
    path = str(BACKUP_DIR / f"{name}.sql")
    ok = _pg_dump(path)
    if ok:
        _prune_old_snapshots()
        _emit_event("db_backup_created", name, "medium")
        log.info("BACKUP: %s -> %s", name, path)
    else:
        log.error("BACKUP FAILED: %s", name)
    return ok


def _action_listener() -> None:
    """Читає actions.jsonl у tail-режимі для backup_db/restore_db/corrupt_db."""
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
                                log.debug("Пропущено невалідну дію: %s", exc)
                        offset = fh.tell()
        except OSError as exc:
            log.debug("Помилка читання дій: %s", exc)
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
        _emit_ack(
            action_id,
            cor_id,
            "db",
            "backup_db",
            "success" if ok else "failed",
            "backup_created" if ok else "",
        )

    elif action == "restore_db" and target == "db":
        snap_name = params.get("snapshot", "latest")
        snap_path = _resolve_snapshot(snap_name)
        if snap_path is None:
            log.error("RESTORE FAILED: snapshot '%s' not found", snap_name)
            _emit_event("restore_failed", f"snapshot={snap_name} not_found", "critical", cor_id)
            _emit_ack(
                action_id,
                cor_id,
                "db",
                "restore_db",
                "failed",
                error=f"snapshot {snap_name} not found",
            )
            return

        _emit_event("restore_started", f"snapshot={snap_name}", "critical", cor_id)
        log.info("RESTORE: starting from %s", snap_path)

        ok = _pg_restore(snap_path)
        if ok and _verify_integrity():
            _emit_event("restore_completed", f"snapshot={snap_name}", "medium", cor_id)
            _emit_ack(action_id, cor_id, "db", "restore_db", "success", "restore_completed")
            log.info("RESTORE COMPLETED: integrity verified")
        else:
            _emit_event("restore_failed", f"snapshot={snap_name}", "critical", cor_id)
            _emit_ack(
                action_id,
                cor_id,
                "db",
                "restore_db",
                "failed",
                error="restore or integrity check failed",
            )
            log.error("RESTORE FAILED")

    elif action == "corrupt_db" and target == "db":
        _psql("UPDATE integrity_check SET marker='CORRUPTED', updated=now();")
        _psql(
            "INSERT INTO telemetry (source, component, key, value, unit, severity) "
            "VALUES ('CORRUPT', 'db', 'CORRUPTION', -999, 'ERR', 'critical');"
        )
        _emit_event("db_corruption_detected", "integrity_violation", "critical", cor_id)
        log.info("CORRUPTION SIMULATED: integrity_check marker set to CORRUPTED")


def main() -> None:
    _wait_for_pg()

    threads = [
        threading.Thread(target=_telemetry_writer, daemon=True, name="telemetry-writer"),
        threading.Thread(target=_backup_loop, daemon=True, name="backup-loop"),
        threading.Thread(target=_action_listener, daemon=True, name="action-listener"),
    ]
    for t in threads:
        t.start()
        log.info("Запущено потік: %s", t.name)

    log.info(
        "db-writer running: write_interval=%.1fs backup_interval=%ds",
        WRITE_INTERVAL,
        BACKUP_INTERVAL,
    )

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        log.info("Зупинка сервісу")


if __name__ == "__main__":
    main()
