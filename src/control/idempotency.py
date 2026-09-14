"""Стійке сховище ідемпотентності керувальних команд."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from src.control.models import ActionAck


@dataclass(frozen=True, slots=True)
class ClaimResult:
    """Результат спроби зарезервувати команду для виконання."""

    acquired: bool
    cached_ack: ActionAck | None = None
    in_progress: bool = False


class IdempotencyStore:
    """Зберігає результати команд і запобігає їх повторному виконанню."""

    def __init__(
        self,
        database_path: str | Path,
        lease_seconds: float = 30.0,
    ) -> None:
        """Ініціалізує SQLite-сховище та створює необхідну таблицю."""

        if lease_seconds <= 0:
            raise ValueError("lease_seconds має бути більше нуля")

        self._database_path = Path(database_path)
        self._lease_seconds = lease_seconds

        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        """Відкриває налаштоване з'єднання зі сховищем."""

        connection = sqlite3.connect(
            self._database_path,
            timeout=5.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        """Створює таблицю ідемпотентності, якщо вона ще не існує."""

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS action_idempotency (
                    action_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    lease_until REAL NOT NULL,
                    ack_json TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )

    def claim(self, action_id: str) -> ClaimResult:
        """Резервує команду або повертає її попередній результат."""

        normalized_action_id = action_id.strip()
        if not normalized_action_id:
            raise ValueError("action_id не може бути порожнім")

        now = time.time()
        lease_until = now + self._lease_seconds

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute(
                """
                SELECT state, lease_until, ack_json
                FROM action_idempotency
                WHERE action_id = ?
                """,
                (normalized_action_id,),
            ).fetchone()

            if row is None:
                connection.execute(
                    """
                    INSERT INTO action_idempotency (
                        action_id,
                        state,
                        lease_until,
                        ack_json,
                        created_at,
                        updated_at
                    )
                    VALUES (?, 'processing', ?, NULL, ?, ?)
                    """,
                    (
                        normalized_action_id,
                        lease_until,
                        now,
                        now,
                    ),
                )
                connection.execute("COMMIT")
                return ClaimResult(acquired=True)

            if row["state"] == "completed" and row["ack_json"]:
                cached_ack = ActionAck.model_validate_json(row["ack_json"])
                connection.execute("COMMIT")
                return ClaimResult(
                    acquired=False,
                    cached_ack=cached_ack,
                )

            if float(row["lease_until"]) > now:
                connection.execute("COMMIT")
                return ClaimResult(
                    acquired=False,
                    in_progress=True,
                )

            connection.execute(
                """
                UPDATE action_idempotency
                SET state = 'processing',
                    lease_until = ?,
                    ack_json = NULL,
                    updated_at = ?
                WHERE action_id = ?
                """,
                (
                    lease_until,
                    now,
                    normalized_action_id,
                ),
            )
            connection.execute("COMMIT")

        return ClaimResult(acquired=True)

    def complete(self, ack: ActionAck) -> None:
        """Зберігає остаточне підтвердження виконання команди."""

        now = time.time()
        serialized_ack = ack.model_dump_json(by_alias=True)

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO action_idempotency (
                    action_id,
                    state,
                    lease_until,
                    ack_json,
                    created_at,
                    updated_at
                )
                VALUES (?, 'completed', 0, ?, ?, ?)
                ON CONFLICT(action_id) DO UPDATE SET
                    state = 'completed',
                    lease_until = 0,
                    ack_json = excluded.ack_json,
                    updated_at = excluded.updated_at
                """,
                (
                    ack.action_id,
                    serialized_ack,
                    now,
                    now,
                ),
            )
            connection.execute("COMMIT")

    def get(self, action_id: str) -> ActionAck | None:
        """Повертає збережений результат команди, якщо він існує."""

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT ack_json
                FROM action_idempotency
                WHERE action_id = ?
                  AND state = 'completed'
                """,
                (action_id,),
            ).fetchone()

        if row is None or not row["ack_json"]:
            return None

        return ActionAck.model_validate_json(row["ack_json"])

    def prune(self, max_age_seconds: float) -> int:
        """Видаляє застарілі завершені записи та повертає їх кількість."""

        if max_age_seconds <= 0:
            raise ValueError("max_age_seconds має бути більше нуля")

        threshold = time.time() - max_age_seconds

        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM action_idempotency
                WHERE state = 'completed'
                  AND updated_at < ?
                """,
                (threshold,),
            )

        return cursor.rowcount