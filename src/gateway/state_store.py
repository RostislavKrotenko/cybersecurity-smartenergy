"""Персистентний стан захисного шлюзу SmartEnergy.

Сховище зберігає блокування клієнтів, ручну ізоляцію upstream і поточні
параметри rate limiting. Запис виконується атомарно, щоб аварійне завершення
процесу не залишало частково записаний JSON-файл.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class BlockStatus:
    """Поточний стан блокування одного клієнта."""

    blocked: bool
    identity: str
    reason: str = ""
    action_id: str = ""
    expires_at_epoch: float | None = None
    retry_after_sec: float = 0.0


@dataclass(frozen=True, slots=True)
class IsolationStatus:
    """Поточний стан ручної ізоляції upstream."""

    enabled: bool
    reason: str
    action_id: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class RateLimitState:
    """Поточні параметри динамічного обмеження частоти."""

    enabled: bool
    rate_per_second: float
    burst_capacity: int
    action_id: str
    updated_at: str


class GatewayStateStore:
    """Зберігає керований стан одного екземпляра gateway."""

    def __init__(
        self,
        *,
        path: str | Path,
        service_id: str,
        default_rate_per_second: float,
        default_burst_capacity: int,
        wall_clock: Callable[[], float] = time.time,
    ):
        """Створює сховище та завантажує раніше збережений стан."""

        if not service_id.strip():
            raise ValueError("Ідентифікатор сервісу не може бути порожнім")

        if default_rate_per_second <= 0:
            raise ValueError("Швидкість rate limit має бути більше нуля")

        if default_burst_capacity < 1:
            raise ValueError("Місткість burst має бути не менше 1")

        self._path = Path(path)
        self._service_id = service_id.strip()
        self._wall_clock = wall_clock
        self._lock = threading.RLock()

        self._state: dict[str, Any] = self._default_state(
            rate_per_second=default_rate_per_second,
            burst_capacity=default_burst_capacity,
        )

        self._load()

    @property
    def path(self) -> Path:
        """Повертає шлях до файла стану."""
        return self._path

    def block(
        self,
        identity: str,
        *,
        ttl_sec: float,
        reason: str,
        action_id: str,
    ) -> BlockStatus:
        """Блокує клієнта на визначений час."""

        normalized_identity = identity.strip()
        if not normalized_identity:
            raise ValueError("Ідентифікатор блокування не може бути порожнім")

        if ttl_sec <= 0:
            raise ValueError("TTL блокування має бути більше нуля")

        now = self._wall_clock()
        expires_at = now + ttl_sec

        with self._lock:
            self._remove_expired_blocks_unlocked(now)

            self._state["blocked"][normalized_identity] = {
                "reason": reason.strip() or "Порушення політики доступу",
                "actionId": action_id.strip(),
                "createdAt": _utc_now(),
                "expiresAtEpoch": expires_at,
            }
            self._touch_unlocked()
            self._save_unlocked()

            return BlockStatus(
                blocked=True,
                identity=normalized_identity,
                reason=self._state["blocked"][normalized_identity]["reason"],
                action_id=self._state["blocked"][normalized_identity]["actionId"],
                expires_at_epoch=expires_at,
                retry_after_sec=ttl_sec,
            )

    def unblock(self, identity: str) -> bool:
        """Знімає блокування з указаного клієнта."""

        normalized_identity = identity.strip()
        if not normalized_identity:
            return False

        with self._lock:
            existed = normalized_identity in self._state["blocked"]
            self._state["blocked"].pop(normalized_identity, None)

            if existed:
                self._touch_unlocked()
                self._save_unlocked()

            return existed

    def is_blocked(self, identity: str) -> BlockStatus:
        """Перевіряє актуальний стан блокування клієнта."""

        normalized_identity = identity.strip()
        if not normalized_identity:
            normalized_identity = "unknown"

        now = self._wall_clock()

        with self._lock:
            record = self._state["blocked"].get(normalized_identity)
            if record is None:
                return BlockStatus(
                    blocked=False,
                    identity=normalized_identity,
                )

            expires_at = self._safe_float(
                record.get("expiresAtEpoch"),
                default=0.0,
            )

            if expires_at <= now:
                self._state["blocked"].pop(normalized_identity, None)
                self._touch_unlocked()
                self._save_unlocked()

                return BlockStatus(
                    blocked=False,
                    identity=normalized_identity,
                )

            return BlockStatus(
                blocked=True,
                identity=normalized_identity,
                reason=str(record.get("reason") or ""),
                action_id=str(record.get("actionId") or ""),
                expires_at_epoch=expires_at,
                retry_after_sec=max(0.0, expires_at - now),
            )

    def set_isolation(
        self,
        *,
        enabled: bool,
        reason: str,
        action_id: str,
    ) -> IsolationStatus:
        """Вмикає або вимикає ручну ізоляцію upstream."""

        with self._lock:
            updated_at = _utc_now()
            self._state["isolation"] = {
                "enabled": bool(enabled),
                "reason": reason.strip() if enabled else "",
                "actionId": action_id.strip(),
                "updatedAt": updated_at,
            }
            self._touch_unlocked()
            self._save_unlocked()

            return IsolationStatus(
                enabled=bool(enabled),
                reason=self._state["isolation"]["reason"],
                action_id=self._state["isolation"]["actionId"],
                updated_at=updated_at,
            )

    def get_isolation(self) -> IsolationStatus:
        """Повертає збережений стан ручної ізоляції."""

        with self._lock:
            record = self._state["isolation"]

            return IsolationStatus(
                enabled=bool(record.get("enabled", False)),
                reason=str(record.get("reason") or ""),
                action_id=str(record.get("actionId") or ""),
                updated_at=str(record.get("updatedAt") or ""),
            )

    def set_rate_limit(
        self,
        *,
        enabled: bool,
        rate_per_second: float,
        burst_capacity: int,
        action_id: str,
    ) -> RateLimitState:
        """Зберігає нові параметри rate limiting."""

        if rate_per_second <= 0:
            raise ValueError("Швидкість rate limit має бути більше нуля")

        if burst_capacity < 1:
            raise ValueError("Місткість burst має бути не менше 1")

        with self._lock:
            updated_at = _utc_now()
            self._state["rateLimit"] = {
                "enabled": bool(enabled),
                "ratePerSecond": float(rate_per_second),
                "burstCapacity": int(burst_capacity),
                "actionId": action_id.strip(),
                "updatedAt": updated_at,
            }
            self._touch_unlocked()
            self._save_unlocked()

            return RateLimitState(
                enabled=bool(enabled),
                rate_per_second=float(rate_per_second),
                burst_capacity=int(burst_capacity),
                action_id=action_id.strip(),
                updated_at=updated_at,
            )

    def get_rate_limit(self) -> RateLimitState:
        """Повертає збережені параметри rate limiting."""

        with self._lock:
            record = self._state["rateLimit"]

            return RateLimitState(
                enabled=bool(record.get("enabled", True)),
                rate_per_second=self._safe_float(
                    record.get("ratePerSecond"),
                    default=1.0,
                ),
                burst_capacity=self._safe_int(
                    record.get("burstCapacity"),
                    default=1,
                ),
                action_id=str(record.get("actionId") or ""),
                updated_at=str(record.get("updatedAt") or ""),
            )

    def snapshot(self) -> dict[str, Any]:
        """Повертає серіалізований актуальний стан gateway."""

        now = self._wall_clock()

        with self._lock:
            changed = self._remove_expired_blocks_unlocked(now)
            if changed:
                self._touch_unlocked()
                self._save_unlocked()

            blocked_items = []

            for identity, record in sorted(
                self._state["blocked"].items(),
                key=lambda item: item[0],
            ):
                expires_at = self._safe_float(
                    record.get("expiresAtEpoch"),
                    default=0.0,
                )
                blocked_items.append(
                    {
                        "identity": identity,
                        "reason": str(record.get("reason") or ""),
                        "actionId": str(record.get("actionId") or ""),
                        "createdAt": str(record.get("createdAt") or ""),
                        "expiresAtEpoch": expires_at,
                        "retryAfterSec": max(0.0, expires_at - now),
                    }
                )

            return {
                "version": int(self._state.get("version", 1)),
                "serviceId": self._service_id,
                "updatedAt": str(self._state.get("updatedAt") or ""),
                "blocked": blocked_items,
                "blockedCount": len(blocked_items),
                "isolation": dict(self._state["isolation"]),
                "rateLimit": dict(self._state["rateLimit"]),
            }

    def _default_state(
        self,
        *,
        rate_per_second: float,
        burst_capacity: int,
    ) -> dict[str, Any]:
        now = _utc_now()

        return {
            "version": 1,
            "serviceId": self._service_id,
            "updatedAt": now,
            "blocked": {},
            "isolation": {
                "enabled": False,
                "reason": "",
                "actionId": "",
                "updatedAt": now,
            },
            "rateLimit": {
                "enabled": True,
                "ratePerSecond": float(rate_per_second),
                "burstCapacity": int(burst_capacity),
                "actionId": "",
                "updatedAt": now,
            },
        }

    def _load(self) -> None:
        with self._lock:
            if not self._path.exists():
                return

            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                log.exception(
                    "Не вдалося завантажити стан gateway з %s",
                    self._path,
                )
                return

            if not isinstance(raw, dict):
                log.warning(
                    "Файл стану gateway не містить JSON-об’єкт: %s",
                    self._path,
                )
                return

            if raw.get("serviceId") not in {None, self._service_id}:
                log.warning(
                    "Файл стану належить іншому сервісу: %s",
                    raw.get("serviceId"),
                )
                return

            blocked = raw.get("blocked")
            isolation = raw.get("isolation")
            rate_limit = raw.get("rateLimit")

            if isinstance(blocked, dict):
                self._state["blocked"] = blocked

            if isinstance(isolation, dict):
                self._state["isolation"].update(isolation)

            if isinstance(rate_limit, dict):
                self._state["rateLimit"].update(rate_limit)

            self._state["updatedAt"] = str(
                raw.get("updatedAt") or self._state["updatedAt"]
            )

            changed = self._remove_expired_blocks_unlocked(self._wall_clock())
            if changed:
                self._touch_unlocked()
                self._save_unlocked()

    def _save_unlocked(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)

        temporary_path: Path | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self._path.parent,
                prefix=f".{self._path.name}.",
                suffix=".tmp",
                delete=False,
            ) as stream:
                temporary_path = Path(stream.name)
                json.dump(
                    self._state,
                    stream,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())

            os.replace(temporary_path, self._path)
            os.chmod(self._path, 0o600)
        except OSError:
            log.exception(
                "Не вдалося атомарно зберегти стан gateway у %s",
                self._path,
            )
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise

    def _remove_expired_blocks_unlocked(self, now: float) -> bool:
        expired = []

        for identity, record in self._state["blocked"].items():
            expires_at = self._safe_float(
                record.get("expiresAtEpoch"),
                default=0.0,
            )
            if expires_at <= now:
                expired.append(identity)

        for identity in expired:
            self._state["blocked"].pop(identity, None)

        return bool(expired)

    def _touch_unlocked(self) -> None:
        self._state["updatedAt"] = _utc_now()

    @staticmethod
    def _safe_float(value: Any, *, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _safe_int(value: Any, *, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default