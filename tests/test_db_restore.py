"""Інтеграційний тест: backup -> corrupt -> restore -> перевірка.

Тест потребує запущених Postgres і db-writer з docker-compose.
Запуск: pytest tests/test_db_restore.py -v -s

Передумови:
  docker compose --profile live_direct up -d postgres db-writer
  pip install psycopg2-binary
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

# Повністю пропускається, якщо Postgres недоступний.
PG_HOST = os.environ.get("PGHOST", "localhost")
PG_PORT = os.environ.get("PGPORT", "5432")
PG_USER = os.environ.get("PGUSER", "smartenergy")
PG_PASSWORD = os.environ.get("PGPASSWORD", "smartenergy")
PG_DB = os.environ.get("PGDATABASE", "smartenergy")

BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", "./backups"))

try:
    import psycopg2

    _HAS_PG = True
except ImportError:
    _HAS_PG = False


def _pg_available() -> bool:
    """Перевіряє доступність Postgres."""
    if not _HAS_PG:
        return False
    try:
        conn = psycopg2.connect(
            host=PG_HOST,
            port=PG_PORT,
            user=PG_USER,
            password=PG_PASSWORD,
            dbname=PG_DB,
            connect_timeout=3,
        )
        conn.close()
        return True
    except Exception:
        return False


requires_pg = pytest.mark.skipif(
    not _pg_available(),
    reason="Postgres недоступний (спочатку запустіть docker compose up postgres)",
)


def _conn():
    return psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        user=PG_USER,
        password=PG_PASSWORD,
        dbname=PG_DB,
    )


def _query_one(sql: str):
    with _conn() as c, c.cursor() as cur:
        cur.execute(sql)
        return cur.fetchone()


def _execute(sql: str):
    with _conn() as c:
        c.autocommit = True
        with c.cursor() as cur:
            cur.execute(sql)


def _pg_dump(output_path: str) -> bool:
    env = {
        **os.environ,
        "PGHOST": PG_HOST,
        "PGPORT": PG_PORT,
        "PGUSER": PG_USER,
        "PGPASSWORD": PG_PASSWORD,
        "PGDATABASE": PG_DB,
    }
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
        env=env,
    )
    return result.returncode == 0


def _pg_restore(sql_path: str) -> bool:
    env = {
        **os.environ,
        "PGHOST": PG_HOST,
        "PGPORT": PG_PORT,
        "PGUSER": PG_USER,
        "PGPASSWORD": PG_PASSWORD,
        "PGDATABASE": PG_DB,
    }
    result = subprocess.run(
        ["psql", "-h", PG_HOST, "-p", PG_PORT, "-U", PG_USER, "-d", PG_DB, "-f", sql_path],
        capture_output=True,
        text=True,
        env=env,
    )
    return result.returncode == 0


@requires_pg
class TestDbBackupRestoreCycle:
    """Тестує повний цикл backup -> corrupt -> restore -> перевірка."""

    def test_integrity_check_initial(self):
        """Перевіряє, що таблиця integrity_check має marker='healthy'."""
        row = _query_one("SELECT marker FROM integrity_check LIMIT 1;")
        assert row is not None
        assert row[0] == "healthy"

    def test_telemetry_table_has_rows(self):
        """Перевіряє, що таблиця telemetry має seed-дані."""
        row = _query_one("SELECT count(*) FROM telemetry;")
        assert row is not None
        assert row[0] >= 5  # щонайменше 5 seed-рядків з init.sql

    def test_backup_corrupt_restore_verify(self, tmp_path):
        """Повний цикл: backup -> corrupt -> restore -> перевірка повернення даних."""
        snapshot_path = str(tmp_path / "test_snapshot.sql")

        # 1. BACKUP.
        ok = _pg_dump(snapshot_path)
        assert ok, "pg_dump має завершитись успішно"
        assert os.path.getsize(snapshot_path) > 0, "Snapshot не має бути порожнім"

        # 2. Фіксація поточної кількості рядків telemetry.
        row = _query_one("SELECT count(*) FROM telemetry;")
        pre_count = row[0]

        # 3. CORRUPT.
        _execute("UPDATE integrity_check SET marker='CORRUPTED';")
        _execute(
            "INSERT INTO telemetry (source, component, key, value, unit, severity) "
            "VALUES ('CORRUPT', 'db', 'CORRUPTION', -999, 'ERR', 'critical');"
        )

        # Перевірка пошкодження.
        row = _query_one("SELECT marker FROM integrity_check LIMIT 1;")
        assert row[0] == "CORRUPTED", "БД має бути пошкоджена"

        corrupt_count = _query_one("SELECT count(*) FROM telemetry;")[0]
        assert corrupt_count == pre_count + 1, "Пошкоджений рядок має бути вставлений"

        # 4. RESTORE.
        ok = _pg_restore(snapshot_path)
        assert ok, "psql restore має завершитись успішно"

        # 5. VERIFY.
        row = _query_one("SELECT marker FROM integrity_check LIMIT 1;")
        assert row[0] == "healthy", "Після restore marker має бути 'healthy'"

        post_count = _query_one("SELECT count(*) FROM telemetry;")[0]
        assert post_count == pre_count, (
            f"Після restore кількість telemetry має бути {pre_count}, отримано {post_count}"
        )


@requires_pg
class TestNetworkSimIntegration:
    """Тестує HTTP-ендпоінти network-sim, якщо контейнер запущений."""

    def _netsim_url(self) -> str:
        return os.environ.get("NETWORK_SIM_URL", "http://localhost:8090")

    def _get(self, path: str) -> dict | None:
        import urllib.request

        try:
            with urllib.request.urlopen(f"{self._netsim_url()}{path}", timeout=3) as r:
                return json.loads(r.read())
        except Exception:
            return None

    def _post(self, path: str, body: dict) -> dict | None:
        import urllib.request

        try:
            data = json.dumps(body).encode()
            req = urllib.request.Request(
                f"{self._netsim_url()}{path}",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3) as r:
                return json.loads(r.read())
        except Exception:
            return None

    def test_status_healthy_by_default(self):
        status = self._get("/status")
        if status is None:
            pytest.skip("network-sim не запущений")
        assert status["latency_ms"] == 0
        assert status["drop_rate"] == 0.0
        assert status["disconnected"] is False

    def test_degrade_and_reset(self):
        status = self._get("/healthz")
        if status is None:
            pytest.skip("network-sim не запущений")

        # Деградація.
        result = self._post(
            "/degrade",
            {
                "latency_ms": 300,
                "drop_rate": 0.2,
                "ttl_sec": 60,
            },
        )
        assert result is not None
        assert result["latency_ms"] == 300
        assert result["drop_rate"] == 0.2

        # Перевірка статусу.
        status = self._get("/status")
        assert status["latency_ms"] == 300

        # Скидання.
        result = self._post("/reset", {})
        assert result is not None
        assert result["latency_ms"] == 0

        # Перевірка healthy-стану.
        status = self._get("/status")
        assert status["latency_ms"] == 0
        assert status["disconnected"] is False
