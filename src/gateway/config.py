"""Конфігурація захисного шлюзу SmartEnergy.

Модуль читає параметри шлюзу зі змінних середовища та перевіряє їх
до запуску застосунку. Один і той самий Docker-образ можна запускати
для різних backend-сервісів, передаючи різні значення GATEWAY_*.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default

    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} має бути цілим числом") from exc


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default

    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{name} має бути числом") from exc


def _env_tuple(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = os.getenv(name)
    if value is None:
        return default

    items = tuple(item.strip() for item in value.split(",") if item.strip())
    return items or default


@dataclass(frozen=True, slots=True)
class GatewaySettings:
    """Налаштування одного екземпляра захисного шлюзу."""

    service_id: str
    component: str
    upstream_url: str

    event_log_path: Path
    state_path: Path

    rate_per_second: float
    burst_capacity: int

    command_rate_per_minute: int
    violation_threshold: int
    violation_window_sec: float
    block_ttl_sec: float

    upstream_timeout_sec: float
    max_request_body_bytes: int

    circuit_failure_threshold: int
    circuit_recovery_timeout_sec: float

    stale_cache_ttl_sec: float
    stale_cache_max_body_bytes: int

    protected_write_prefixes: tuple[str, ...]
    cacheable_get_prefixes: tuple[str, ...]

    control_token: str
    client_ip_header: str

    @classmethod
    def from_env(cls) -> "GatewaySettings":
        """Створює конфігурацію зі змінних середовища."""

        settings = cls(
            service_id=os.getenv("GATEWAY_SERVICE_ID", "iot-gateway").strip(),
            component=os.getenv("GATEWAY_COMPONENT", "gateway").strip(),
            upstream_url=os.getenv(
                "GATEWAY_UPSTREAM_URL",
                "http://backend-kravchenko:8000",
            ).strip(),
            event_log_path=Path(
                os.getenv(
                    "GATEWAY_EVENT_LOG_PATH",
                    "/work/data/integration/events.jsonl",
                )
            ),
            state_path=Path(
                os.getenv(
                    "GATEWAY_STATE_PATH",
                    "/work/data/integration/state.json",
                )
            ),
            rate_per_second=_env_float("GATEWAY_RATE_PER_SECOND", 25.0),
            burst_capacity=_env_int("GATEWAY_BURST_CAPACITY", 50),
            command_rate_per_minute=_env_int(
                "GATEWAY_COMMAND_RATE_PER_MINUTE",
                12,
            ),
            violation_threshold=_env_int(
                "GATEWAY_VIOLATION_THRESHOLD",
                8,
            ),
            violation_window_sec=_env_float(
                "GATEWAY_VIOLATION_WINDOW_SEC",
                30.0,
            ),
            block_ttl_sec=_env_float("GATEWAY_BLOCK_TTL_SEC", 120.0),
            upstream_timeout_sec=_env_float(
                "GATEWAY_UPSTREAM_TIMEOUT_SEC",
                3.0,
            ),
            max_request_body_bytes=_env_int(
                "GATEWAY_MAX_REQUEST_BODY_BYTES",
                1_048_576,
            ),
            circuit_failure_threshold=_env_int(
                "GATEWAY_CIRCUIT_FAILURE_THRESHOLD",
                5,
            ),
            circuit_recovery_timeout_sec=_env_float(
                "GATEWAY_CIRCUIT_RECOVERY_TIMEOUT_SEC",
                15.0,
            ),
            stale_cache_ttl_sec=_env_float(
                "GATEWAY_STALE_CACHE_TTL_SEC",
                30.0,
            ),
            stale_cache_max_body_bytes=_env_int(
                "GATEWAY_STALE_CACHE_MAX_BODY_BYTES",
                1_048_576,
            ),
            protected_write_prefixes=_env_tuple(
                "GATEWAY_PROTECTED_WRITE_PREFIXES",
                (
                    "/api/cmd/",
                    "/api/settings",
                    "/api/control",
                ),
            ),
            cacheable_get_prefixes=_env_tuple(
                "GATEWAY_CACHEABLE_GET_PREFIXES",
                (
                    "/api/data",
                    "/api/v1/telemetry/latest",
                    "/api/settings",
                    "/api/status",
                ),
            ),
            control_token=os.getenv("GATEWAY_CONTROL_TOKEN", "").strip(),
            client_ip_header=os.getenv(
                "GATEWAY_CLIENT_IP_HEADER",
                "",
            ).strip(),
        )
        settings.validate()
        return settings

    @property
    def normalized_upstream_url(self) -> str:
        """Повертає адресу upstream без завершального символу `/`."""

        return self.upstream_url.rstrip("/")

    def validate(self) -> None:
        """Перевіряє безпечність і коректність конфігурації."""

        if not self.service_id:
            raise ValueError("GATEWAY_SERVICE_ID не може бути порожнім")

        if not self.component:
            raise ValueError("GATEWAY_COMPONENT не може бути порожнім")

        parsed_url = urlparse(self.upstream_url)
        if parsed_url.scheme not in {"http", "https"}:
            raise ValueError(
                "GATEWAY_UPSTREAM_URL має використовувати http або https"
            )

        if not parsed_url.hostname:
            raise ValueError("GATEWAY_UPSTREAM_URL не містить hostname")

        if self.rate_per_second <= 0:
            raise ValueError("GATEWAY_RATE_PER_SECOND має бути більше нуля")

        if self.burst_capacity < 1:
            raise ValueError("GATEWAY_BURST_CAPACITY має бути не менше 1")

        if self.command_rate_per_minute < 1:
            raise ValueError(
                "GATEWAY_COMMAND_RATE_PER_MINUTE має бути не менше 1"
            )

        if self.violation_threshold < 1:
            raise ValueError(
                "GATEWAY_VIOLATION_THRESHOLD має бути не менше 1"
            )

        if self.violation_window_sec <= 0:
            raise ValueError(
                "GATEWAY_VIOLATION_WINDOW_SEC має бути більше нуля"
            )

        if self.block_ttl_sec <= 0:
            raise ValueError("GATEWAY_BLOCK_TTL_SEC має бути більше нуля")

        if self.upstream_timeout_sec <= 0:
            raise ValueError(
                "GATEWAY_UPSTREAM_TIMEOUT_SEC має бути більше нуля"
            )

        if self.max_request_body_bytes < 1:
            raise ValueError(
                "GATEWAY_MAX_REQUEST_BODY_BYTES має бути не менше 1"
            )

        if self.circuit_failure_threshold < 1:
            raise ValueError(
                "GATEWAY_CIRCUIT_FAILURE_THRESHOLD має бути не менше 1"
            )

        if self.circuit_recovery_timeout_sec <= 0:
            raise ValueError(
                "GATEWAY_CIRCUIT_RECOVERY_TIMEOUT_SEC має бути більше нуля"
            )

        if self.stale_cache_ttl_sec < 0:
            raise ValueError(
                "GATEWAY_STALE_CACHE_TTL_SEC не може бути від'ємним"
            )

        for prefix in (
            *self.protected_write_prefixes,
            *self.cacheable_get_prefixes,
        ):
            if not prefix.startswith("/"):
                raise ValueError(
                    f"Префікс маршруту має починатися з `/`: {prefix}"
                )

        if self.control_token and len(self.control_token) < 16:
            raise ValueError(
                "GATEWAY_CONTROL_TOKEN має містити щонайменше 16 символів"
            )