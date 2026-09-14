"""Потокобезпечні операційні метрики захисного шлюзу."""

from __future__ import annotations

import math
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from typing import Any

VALID_OUTCOMES = {
    "success",
    "client_error",
    "upstream_error",
    "blocked",
    "rate_limited",
    "circuit_open",
    "stale_cache",
    "body_rejected",
    "internal_error",
}


class GatewayMetrics:
    """Накопичує метрики для оцінювання функціональної стійкості."""

    def __init__(
        self,
        *,
        latency_window_size: int = 5000,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ):
        """Створює накопичувач із обмеженим вікном latency."""

        if latency_window_size < 1:
            raise ValueError("Розмір вікна latency має бути не менше 1")

        self._clock = monotonic_clock
        self._started_at = self._clock()
        self._outcomes: Counter[str] = Counter()
        self._status_codes: Counter[int] = Counter()
        self._actions: Counter[str] = Counter()
        self._latencies_ms: deque[float] = deque(
            maxlen=latency_window_size
        )
        self._request_bytes = 0
        self._response_bytes = 0
        self._lock = threading.RLock()

    def record_request(
        self,
        *,
        outcome: str,
        status_code: int | None,
        latency_ms: float,
        request_bytes: int = 0,
        response_bytes: int = 0,
    ) -> None:
        """Фіксує завершення одного HTTP-запиту."""

        if outcome not in VALID_OUTCOMES:
            raise ValueError(f"Непідтримуваний результат запиту: {outcome}")

        with self._lock:
            self._outcomes[outcome] += 1

            if status_code is not None:
                self._status_codes[int(status_code)] += 1

            if latency_ms >= 0 and math.isfinite(latency_ms):
                self._latencies_ms.append(float(latency_ms))

            self._request_bytes += max(0, int(request_bytes))
            self._response_bytes += max(0, int(response_bytes))

    def record_action(self, action: str, result: str) -> None:
        """Фіксує результат виконання захисної дії."""

        normalized_action = action.strip() or "unknown"
        normalized_result = result.strip() or "unknown"

        with self._lock:
            self._actions[
                f"{normalized_action}:{normalized_result}"
            ] += 1

    def snapshot(self) -> dict[str, Any]:
        """Повертає метрики у форматі для API та дашборду."""

        with self._lock:
            outcomes = dict(self._outcomes)
            total_requests = sum(outcomes.values())

            functional_attempts = (
                outcomes.get("success", 0)
                + outcomes.get("upstream_error", 0)
                + outcomes.get("circuit_open", 0)
                + outcomes.get("stale_cache", 0)
                + outcomes.get("internal_error", 0)
            )
            functional_successes = (
                outcomes.get("success", 0)
                + outcomes.get("stale_cache", 0)
            )

            if functional_attempts:
                availability_pct = (
                    functional_successes / functional_attempts
                ) * 100
            else:
                availability_pct = 100.0

            forwarded_requests = (
                outcomes.get("success", 0)
                + outcomes.get("client_error", 0)
                + outcomes.get("upstream_error", 0)
            )
            upstream_responses = (
                outcomes.get("success", 0)
                + outcomes.get("client_error", 0)
            )

            if forwarded_requests:
                upstream_reachability_pct = (
                    upstream_responses / forwarded_requests
                ) * 100
            else:
                upstream_reachability_pct = 100.0

            latencies = sorted(self._latencies_ms)

            return {
                "uptimeSec": max(0.0, self._clock() - self._started_at),
                "totalRequests": total_requests,
                "outcomes": outcomes,
                "statusCodes": {
                    str(code): count
                    for code, count in sorted(self._status_codes.items())
                },
                "actions": dict(self._actions),
                "requestBytes": self._request_bytes,
                "responseBytes": self._response_bytes,
                "availabilityPct": round(availability_pct, 4),
                "upstreamReachabilityPct": round(
                    upstream_reachability_pct,
                    4,
                ),
                "latencyMs": {
                    "samples": len(latencies),
                    "average": self._average(latencies),
                    "p50": self._percentile(latencies, 50),
                    "p95": self._percentile(latencies, 95),
                    "p99": self._percentile(latencies, 99),
                    "maximum": (
                        round(latencies[-1], 4)
                        if latencies
                        else 0.0
                    ),
                },
            }

    @staticmethod
    def _average(values: list[float]) -> float:
        if not values:
            return 0.0

        return round(sum(values) / len(values), 4)

    @staticmethod
    def _percentile(values: list[float], percentile: int) -> float:
        if not values:
            return 0.0

        if len(values) == 1:
            return round(values[0], 4)

        position = (len(values) - 1) * (percentile / 100)
        lower_index = math.floor(position)
        upper_index = math.ceil(position)

        if lower_index == upper_index:
            return round(values[lower_index], 4)

        lower_value = values[lower_index]
        upper_value = values[upper_index]
        fraction = position - lower_index

        result = lower_value + (upper_value - lower_value) * fraction
        return round(result, 4)