"""Потокобезпечні операційні метрики захисного шлюзу."""

from __future__ import annotations

import math
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from datetime import datetime, timezone
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
        wall_clock: Callable[[], float] = time.time,
        timeline_window_sec: int = 300,
        timeline_bucket_sec: int = 5,
    ):
        """Створює накопичувач із latency та часовим рядом трафіку."""

        if latency_window_size < 1:
            raise ValueError("Розмір вікна latency має бути не менше 1")
        if timeline_window_sec < 1 or timeline_bucket_sec < 1:
            raise ValueError("Часове вікно та bucket мають бути додатними")
        if timeline_bucket_sec > timeline_window_sec:
            raise ValueError("Bucket не може бути більшим за часове вікно")

        self._clock = monotonic_clock
        self._wall_clock = wall_clock
        self._started_at = self._clock()
        self._started_wall_at = self._wall_clock()
        self._timeline_window_sec = int(timeline_window_sec)
        self._timeline_bucket_sec = int(timeline_bucket_sec)
        self._traffic_buckets: dict[int, Counter[str]] = {}
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

            bucket_timestamp = self._bucket_timestamp(self._wall_clock())
            bucket = self._traffic_buckets.setdefault(
                bucket_timestamp,
                Counter(),
            )
            bucket["requests"] += 1
            bucket[outcome] += 1
            self._prune_timeline(bucket_timestamp)

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
                "trafficTimeline": self._traffic_timeline(),
            }

    def _bucket_timestamp(self, timestamp: float) -> int:
        """Округлює Unix timestamp до початку часового bucket."""

        return (
            int(timestamp) // self._timeline_bucket_sec
        ) * self._timeline_bucket_sec

    def _prune_timeline(self, current_bucket: int) -> None:
        """Видаляє точки, що вийшли за межі часового вікна."""

        minimum_timestamp = current_bucket - self._timeline_window_sec
        for timestamp in list(self._traffic_buckets):
            if timestamp < minimum_timestamp:
                del self._traffic_buckets[timestamp]

    def _traffic_timeline(self) -> dict[str, Any]:
        """Повертає заповнений нулями часовий ряд останніх п'яти хвилин."""

        current_bucket = self._bucket_timestamp(self._wall_clock())
        self._prune_timeline(current_bucket)
        earliest_bucket = max(
            self._bucket_timestamp(self._started_wall_at),
            current_bucket - self._timeline_window_sec,
        )
        points: list[dict[str, Any]] = []

        for timestamp in range(
            earliest_bucket,
            current_bucket + 1,
            self._timeline_bucket_sec,
        ):
            bucket = self._traffic_buckets.get(timestamp, Counter())
            requests = int(bucket.get("requests", 0))
            limited = int(bucket.get("rate_limited", 0))
            blocked = int(bucket.get("blocked", 0))
            errors = int(
                bucket.get("upstream_error", 0)
                + bucket.get("circuit_open", 0)
                + bucket.get("internal_error", 0)
            )

            points.append(
                {
                    "timestamp": datetime.fromtimestamp(
                        timestamp,
                        timezone.utc,
                    ).isoformat().replace("+00:00", "Z"),
                    "requests": requests,
                    "requestsPerSecond": round(
                        requests / self._timeline_bucket_sec,
                        3,
                    ),
                    "forwarded": int(
                        bucket.get("success", 0)
                        + bucket.get("client_error", 0)
                        + bucket.get("upstream_error", 0)
                    ),
                    "limited": limited,
                    "blocked": blocked,
                    "errors": errors,
                }
            )

        return {
            "bucketSec": self._timeline_bucket_sec,
            "windowSec": self._timeline_window_sec,
            "points": points,
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
