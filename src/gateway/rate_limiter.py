"""Потокобезпечне обмеження частоти запитів за алгоритмом Token Bucket."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    """Результат перевірки ліміту для одного клієнта."""

    allowed: bool
    remaining_tokens: float
    retry_after_sec: float


@dataclass(slots=True)
class _TokenBucket:
    tokens: float
    updated_at: float
    last_seen_at: float


class TokenBucketRateLimiter:
    """Обмежує частоту запитів окремо для кожного ідентифікатора.

    Реалізація розрахована на один worker-процес gateway. Для кількох
    worker-процесів стан необхідно винести в Redis або інше спільне сховище.
    """

    def __init__(
        self,
        *,
        rate_per_second: float,
        burst_capacity: int,
        clock: Callable[[], float] = time.monotonic,
    ):
        """Створює обмежувач із заданою швидкістю поповнення токенів."""

        if rate_per_second <= 0:
            raise ValueError("Швидкість поповнення має бути більше нуля")

        if burst_capacity < 1:
            raise ValueError("Місткість burst має бути не менше 1")

        self._rate_per_second = float(rate_per_second)
        self._burst_capacity = float(burst_capacity)
        self._clock = clock

        self._buckets: dict[str, _TokenBucket] = {}
        self._lock = threading.RLock()
        self._request_counter = 0

    @property
    def rate_per_second(self) -> float:
        """Повертає поточну швидкість поповнення токенів."""

        with self._lock:
            return self._rate_per_second

    @property
    def burst_capacity(self) -> int:
        """Повертає поточну максимальну кількість токенів."""

        with self._lock:
            return int(self._burst_capacity)

    def allow(
        self,
        identity: str,
        *,
        cost: float = 1.0,
    ) -> RateLimitResult:
        """Перевіряє, чи можна пропустити запит заданого клієнта."""

        if not identity:
            identity = "unknown"

        if cost <= 0:
            raise ValueError("Вартість запиту має бути більше нуля")

        now = self._clock()

        with self._lock:
            bucket = self._buckets.get(identity)

            if bucket is None:
                bucket = _TokenBucket(
                    tokens=self._burst_capacity,
                    updated_at=now,
                    last_seen_at=now,
                )
                self._buckets[identity] = bucket

            elapsed = max(0.0, now - bucket.updated_at)
            bucket.tokens = min(
                self._burst_capacity,
                bucket.tokens + elapsed * self._rate_per_second,
            )
            bucket.updated_at = now
            bucket.last_seen_at = now

            if bucket.tokens >= cost:
                bucket.tokens -= cost
                result = RateLimitResult(
                    allowed=True,
                    remaining_tokens=bucket.tokens,
                    retry_after_sec=0.0,
                )
            else:
                missing_tokens = cost - bucket.tokens
                result = RateLimitResult(
                    allowed=False,
                    remaining_tokens=bucket.tokens,
                    retry_after_sec=missing_tokens / self._rate_per_second,
                )

            self._request_counter += 1
            if self._request_counter % 256 == 0:
                self._remove_idle_buckets(now)

            return result

    def configure(
        self,
        *,
        rate_per_second: float,
        burst_capacity: int,
    ) -> None:
        """Атомарно змінює параметри обмеження частоти."""

        if rate_per_second <= 0:
            raise ValueError("Швидкість поповнення має бути більше нуля")

        if burst_capacity < 1:
            raise ValueError("Місткість burst має бути не менше 1")

        with self._lock:
            self._rate_per_second = float(rate_per_second)
            self._burst_capacity = float(burst_capacity)

            for bucket in self._buckets.values():
                bucket.tokens = min(
                    bucket.tokens,
                    self._burst_capacity,
                )

    def reset(self, identity: str | None = None) -> None:
        """Очищає стан одного клієнта або всіх клієнтів."""

        with self._lock:
            if identity is None:
                self._buckets.clear()
                return

            self._buckets.pop(identity, None)

    def snapshot(self) -> dict[str, object]:
        """Повертає агрегований стан обмежувача."""

        with self._lock:
            return {
                "ratePerSecond": self._rate_per_second,
                "burstCapacity": int(self._burst_capacity),
                "trackedIdentities": len(self._buckets),
            }

    def _remove_idle_buckets(self, now: float) -> None:
        idle_ttl = max(
            60.0,
            (self._burst_capacity / self._rate_per_second) * 4,
        )

        expired = [
            identity
            for identity, bucket in self._buckets.items()
            if now - bucket.last_seen_at > idle_ttl
        ]

        for identity in expired:
            self._buckets.pop(identity, None)