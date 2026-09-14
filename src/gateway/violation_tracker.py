"""Облік порушень клієнтів у ковзному часовому вікні."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable


class ViolationTracker:
    """Визначає, коли кількість порушень досягає порога блокування."""

    def __init__(
        self,
        *,
        threshold: int,
        window_sec: float,
        clock: Callable[[], float] = time.monotonic,
    ):
        """Створює облік порушень із заданим порогом і часовим вікном."""

        if threshold < 1:
            raise ValueError("Поріг порушень має бути не менше 1")

        if window_sec <= 0:
            raise ValueError("Часове вікно має бути більше нуля")

        self._threshold = threshold
        self._window_sec = window_sec
        self._clock = clock

        self._violations: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.RLock()

    def record(self, identity: str) -> tuple[int, bool]:
        """Реєструє порушення та повертає кількість і рішення про блокування."""

        if not identity:
            identity = "unknown"

        now = self._clock()

        with self._lock:
            timestamps = self._violations[identity]
            self._remove_expired(timestamps, now)
            timestamps.append(now)

            count = len(timestamps)
            return count, count >= self._threshold

    def count(self, identity: str) -> int:
        """Повертає актуальну кількість порушень клієнта."""

        now = self._clock()

        with self._lock:
            timestamps = self._violations.get(identity)
            if timestamps is None:
                return 0

            self._remove_expired(timestamps, now)

            if not timestamps:
                self._violations.pop(identity, None)
                return 0

            return len(timestamps)

    def reset(self, identity: str | None = None) -> None:
        """Очищає порушення одного клієнта або всіх клієнтів."""

        with self._lock:
            if identity is None:
                self._violations.clear()
                return

            self._violations.pop(identity, None)

    def snapshot(self) -> dict[str, object]:
        """Повертає агрегований стан обліку порушень."""

        now = self._clock()

        with self._lock:
            empty_identities: list[str] = []

            for identity, timestamps in self._violations.items():
                self._remove_expired(timestamps, now)
                if not timestamps:
                    empty_identities.append(identity)

            for identity in empty_identities:
                self._violations.pop(identity, None)

            return {
                "threshold": self._threshold,
                "windowSec": self._window_sec,
                "trackedIdentities": len(self._violations),
                "totalActiveViolations": sum(
                    len(timestamps)
                    for timestamps in self._violations.values()
                ),
            }

    def _remove_expired(
        self,
        timestamps: deque[float],
        now: float,
    ) -> None:
        cutoff = now - self._window_sec

        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()