"""Integration test: backup -> corrupt -> restore -> verify.

This test requires running Postgres and db-writer from docker-compose.
Run with: pytest tests/test_db_restore.py -v -s

Prerequisites:
  docker compose --profile live_direct up -d postgres db-writer
  pip install psycopg2-binary
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

# Skip entirely if Postgres is not available
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
    """Check if Postgres is reachable."""
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
    reason="Postgres not available (run docker compose up postgres first)",
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
    """Test the full backup -> corrupt -> restore -> verify cycle."""

    def test_integrity_check_initial(self):
        """Verify the integrity_check table has marker='healthy'."""
        row = _query_one("SELECT marker FROM integrity_check LIMIT 1;")
        assert row is not None
        assert row[0] == "healthy"

    def test_telemetry_table_has_rows(self):
        """Verify the telemetry table has seed data."""
        row = _query_one("SELECT count(*) FROM telemetry;")
        assert row is not None
        assert row[0] >= 5  # at least the 5 seed rows from init.sql

    def test_backup_corrupt_restore_verify(self, tmp_path):
        """Full cycle: backup -> corrupt -> restore -> verify data returns."""
        snapshot_path = str(tmp_path / "test_snapshot.sql")

        # 1. BACKUP
        ok = _pg_dump(snapshot_path)
        assert ok, "pg_dump should succeed"
        assert os.path.getsize(snapshot_path) > 0, "Snapshot should not be empty"

        # 2. Record the current telemetry row count
        row = _query_one("SELECT count(*) FROM telemetry;")
        pre_count = row[0]

        # 3. CORRUPT
        _execute("UPDATE integrity_check SET marker='CORRUPTED';")
        _execute(
            "INSERT INTO telemetry (source, component, key, value, unit, severity) "
            "VALUES ('CORRUPT', 'db', 'CORRUPTION', -999, 'ERR', 'critical');"
        )

        # Verify corruption
        row = _query_one("SELECT marker FROM integrity_check LIMIT 1;")
        assert row[0] == "CORRUPTED", "DB should be corrupted"

        corrupt_count = _query_one("SELECT count(*) FROM telemetry;")[0]
        assert corrupt_count == pre_count + 1, "Corrupt row should be inserted"

        # 4. RESTORE
        ok = _pg_restore(snapshot_path)
        assert ok, "psql restore should succeed"

        # 5. VERIFY
        row = _query_one("SELECT marker FROM integrity_check LIMIT 1;")
        assert row[0] == "healthy", "After restore, marker should be 'healthy'"

        post_count = _query_one("SELECT count(*) FROM telemetry;")[0]
        assert post_count == pre_count, (
            f"After restore, telemetry count should be {pre_count}, got {post_count}"
        )


@requires_pg
class TestNetworkSimIntegration:
    """Test the network-sim HTTP endpoints (if container is running)."""

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
            pytest.skip("network-sim not running")
        assert status["latency_ms"] == 0
        assert status["drop_rate"] == 0.0
        assert status["disconnected"] is False

    def test_degrade_and_reset(self):
        status = self._get("/healthz")
        if status is None:
            pytest.skip("network-sim not running")

        # Degrade
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

        # Verify status
        status = self._get("/status")
        assert status["latency_ms"] == 300

        # Reset
        result = self._post("/reset", {})
        assert result is not None
        assert result["latency_ms"] == 0

        # Verify healthy
        status = self._get("/status")
        assert status["latency_ms"] == 0
        assert status["disconnected"] is False
