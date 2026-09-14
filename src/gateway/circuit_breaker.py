"""Автомат станів Circuit Breaker для контрольованої деградації."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable


class CircuitMode(str, Enum):
    """Можливі автоматичні стани Circuit Breaker."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True, slots=True)
class CircuitDecision:
    """Рішення Circuit Breaker перед зверненням до upstream."""

    allowed: bool
    mode: CircuitMode
    reason: str
    retry_after_sec: float


class CircuitBreaker:
    """Зупиняє запити до нестабільного або ізольованого upstream.

    Після перевищення порога помилок автомат переходить у стан `open`.
    Після завершення recovery timeout дозволяється один пробний запит.
    Успішний пробний запит закриває circuit, а невдалий відкриває його знову.
    """

    def __init__(
        self,
        *,
        failure_threshold: int,
        recovery_timeout_sec: float,
        clock: Callable[[], float] = time.monotonic,
    ):
        """Створює Circuit Breaker з указаними порогами."""

        if failure_threshold < 1:
            raise ValueError("Поріг помилок має бути не менше 1")

        if recovery_timeout_sec <= 0:
            raise ValueError("Час відновлення має бути більше нуля")

        self._failure_threshold = failure_threshold
        self._recovery_timeout_sec = recovery_timeout_sec
        self._clock = clock

        self._mode = CircuitMode.CLOSED
        self._failure_count = 0
        self._opened_at: float | None = None
        self._probe_in_flight = False
        self._manual_isolation = False
        self._manual_reason = ""

        self._lock = threading.RLock()

    def before_request(self) -> CircuitDecision:
        """Визначає, чи дозволене нове звернення до upstream."""

        now = self._clock()

        with self._lock:
            if self._manual_isolation:
                return CircuitDecision(
                    allowed=False,
                    mode=CircuitMode.OPEN,
                    reason=self._manual_reason or "Ручна ізоляція компонента",
                    retry_after_sec=0.0,
                )

            if self._mode == CircuitMode.CLOSED:
                return CircuitDecision(
                    allowed=True,
                    mode=self._mode,
                    reason="Upstream працює у штатному режимі",
                    retry_after_sec=0.0,
                )

            if self._mode == CircuitMode.OPEN:
                retry_after = self._retry_after_unlocked(now)

                if retry_after > 0:
                    return CircuitDecision(
                        allowed=False,
                        mode=self._mode,
                        reason="Circuit відкритий після помилок upstream",
                        retry_after_sec=retry_after,
                    )

                self._mode = CircuitMode.HALF_OPEN
                self._probe_in_flight = True

                return CircuitDecision(
                    allowed=True,
                    mode=self._mode,
                    reason="Дозволено пробний запит для перевірки відновлення",
                    retry_after_sec=0.0,
                )

            if self._probe_in_flight:
                return CircuitDecision(
                    allowed=False,
                    mode=CircuitMode.HALF_OPEN,
                    reason="Пробний запит до upstream уже виконується",
                    retry_after_sec=1.0,
                )

            self._probe_in_flight = True
            return CircuitDecision(
                allowed=True,
                mode=CircuitMode.HALF_OPEN,
                reason="Дозволено пробний запит до upstream",
                retry_after_sec=0.0,
            )

    def record_success(self) -> None:
        """Фіксує успішну відповідь і повертає circuit у штатний стан."""

        with self._lock:
            if self._manual_isolation:
                self._probe_in_flight = False
                return

            self._mode = CircuitMode.CLOSED
            self._failure_count = 0
            self._opened_at = None
            self._probe_in_flight = False

    def record_failure(self) -> None:
        """Фіксує помилку upstream та за потреби відкриває circuit."""

        now = self._clock()

        with self._lock:
            self._probe_in_flight = False

            if self._manual_isolation:
                return

            self._failure_count += 1

            if (
                self._mode == CircuitMode.HALF_OPEN
                or self._failure_count >= self._failure_threshold
            ):
                self._open_unlocked(now)

    def isolate(self, reason: str) -> None:
        """Примусово ізолює upstream за рішенням dispatcher."""

        with self._lock:
            self._manual_isolation = True
            self._manual_reason = reason.strip() or "Ручна ізоляція компонента"
            self._open_unlocked(self._clock())

    def release_isolation(self) -> None:
        """Знімає ручну ізоляцію та повертає circuit у штатний стан."""

        with self._lock:
            self._manual_isolation = False
            self._manual_reason = ""
            self._mode = CircuitMode.CLOSED
            self._failure_count = 0
            self._opened_at = None
            self._probe_in_flight = False

    def snapshot(self) -> dict[str, object]:
        """Повертає поточний стан Circuit Breaker."""

        now = self._clock()

        with self._lock:
            return {
                "mode": self._mode.value,
                "failureCount": self._failure_count,
                "failureThreshold": self._failure_threshold,
                "recoveryTimeoutSec": self._recovery_timeout_sec,
                "retryAfterSec": self._retry_after_unlocked(now),
                "manualIsolation": self._manual_isolation,
                "manualReason": self._manual_reason,
                "probeInFlight": self._probe_in_flight,
            }

    def _open_unlocked(self, now: float) -> None:
        self._mode = CircuitMode.OPEN
        self._opened_at = now
        self._probe_in_flight = False

    def _retry_after_unlocked(self, now: float) -> float:
        if self._mode != CircuitMode.OPEN:
            return 0.0

        if self._manual_isolation:
            return 0.0

        if self._opened_at is None:
            return 0.0

        elapsed = max(0.0, now - self._opened_at)
        return max(0.0, self._recovery_timeout_sec - elapsed)