"""Запис подій шлюзу у канонічному форматі SmartEnergy Event v1."""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class SecurityEventEmitter:
    """Потокобезпечно додає security events у JSONL-файл."""

    def __init__(
        self,
        *,
        path: str | Path,
        source: str,
        component: str,
        force_fsync: bool = False,
    ):
        """Створює emitter для визначеного джерела та компонента."""

        if not source.strip():
            raise ValueError("Джерело подій не може бути порожнім")

        if not component.strip():
            raise ValueError("Компонент подій не може бути порожнім")

        self._path = Path(path)
        self._source = source.strip()
        self._component = component.strip()
        self._force_fsync = force_fsync
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        """Повертає шлях до JSONL-журналу."""

        return self._path

    def emit(
        self,
        *,
        event: str,
        key: str,
        value: Any,
        severity: str,
        actor: str = "",
        ip: str = "",
        unit: str = "",
        tags: str | Sequence[str] = (),
        correlation_id: str = "",
        timestamp: str = "",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Формує, перевіряє та записує одну подію безпеки."""

        normalized_severity = severity.strip().lower()
        if normalized_severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Непідтримуваний рівень критичності: {severity}"
            )

        normalized_event = event.strip()
        normalized_key = key.strip()

        if not normalized_event:
            raise ValueError("Назва події не може бути порожньою")

        if not normalized_key:
            raise ValueError("Ключ події не може бути порожнім")

        if isinstance(tags, str):
            normalized_tags = tags
        else:
            normalized_tags = ",".join(
                str(tag).strip()
                for tag in tags
                if str(tag).strip()
            )

        payload: dict[str, Any] = {
            "timestamp": timestamp.strip() or _utc_now(),
            "source": self._source,
            "component": self._component,
            "event": normalized_event,
            "key": normalized_key,
            "value": value,
            "severity": normalized_severity,
            "actor": actor.strip(),
            "ip": ip.strip(),
            "unit": unit.strip(),
            "tags": normalized_tags,
            "correlation_id": (
                correlation_id.strip()
                or f"gateway-{uuid.uuid4().hex}"
            ),
        }

        if details:
            payload["details"] = details

        serialized = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        self._path.parent.mkdir(parents=True, exist_ok=True)

        with self._lock:
            with self._path.open("a", encoding="utf-8") as stream:
                self._lock_file(stream)
                try:
                    stream.write(serialized)
                    stream.write("\n")
                    stream.flush()

                    if self._force_fsync:
                        os.fsync(stream.fileno())
                finally:
                    self._unlock_file(stream)

        return payload

    def emit_safely(self, **kwargs: Any) -> bool:
        """Записує подію без переривання основного HTTP-запиту при помилці."""

        try:
            self.emit(**kwargs)
            return True
        except Exception:
            log.exception("Не вдалося записати подію захисного шлюзу")
            return False

    @staticmethod
    def _lock_file(stream: Any) -> None:
        try:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError):
            return

    @staticmethod
    def _unlock_file(stream: Any) -> None:
        try:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        except (ImportError, OSError):
            return