"""Конфігурація збирача подій SmartEnergy."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    """Читає логічне значення зі змінної середовища."""

    value = os.getenv(name)
    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _env_float(name: str, default: float) -> float:
    """Читає числове значення зі змінної середовища."""

    value = os.getenv(name)
    if value is None or not value.strip():
        return default

    try:
        return float(value)
    except ValueError as error:
        raise ValueError(
            f"{name} має містити число"
        ) from error


def _env_int(name: str, default: int) -> int:
    """Читає ціле число зі змінної середовища."""

    value = os.getenv(name)
    if value is None or not value.strip():
        return default

    try:
        return int(value)
    except ValueError as error:
        raise ValueError(
            f"{name} має містити ціле число"
        ) from error


@dataclass(frozen=True, slots=True)
class HttpTarget:
    """Опис одного HTTP-джерела подій."""

    target_id: str
    component: str
    mode: str
    url: str


@dataclass(frozen=True, slots=True)
class CollectorSettings:
    """Налаштування збирача подій кіберзахисту."""

    output_path: Path
    poll_interval_sec: float
    dedup_window_sec: float

    gateway_enabled: bool
    gateway_events_path: Path
    gateway_checkpoint_path: Path

    http_enabled: bool
    http_timeout_sec: float
    http_poll_interval_sec: float
    http_targets: tuple[HttpTarget, ...]

    mqtt_enabled: bool
    mqtt_host: str
    mqtt_port: int
    mqtt_client_id: str
    mqtt_topics: tuple[str, ...]
    mqtt_qos: int
    mqtt_username: str
    mqtt_password: str
    mqtt_tls: bool
    mqtt_queue_size: int

    @classmethod
    def from_env(cls) -> "CollectorSettings":
        """Створює конфігурацію зі змінних середовища."""

        settings = cls(
            output_path=Path(
                os.getenv(
                    "COLLECTOR_OUTPUT_PATH",
                    "/work/data/live/collected_events.jsonl",
                )
            ),
            poll_interval_sec=_env_float(
                "COLLECTOR_POLL_INTERVAL_SEC",
                1.0,
            ),
            dedup_window_sec=_env_float(
                "COLLECTOR_DEDUP_WINDOW_SEC",
                2.0,
            ),
            gateway_enabled=_env_bool(
                "COLLECTOR_GATEWAY_ENABLED",
                True,
            ),
            gateway_events_path=Path(
                os.getenv(
                    "COLLECTOR_GATEWAY_EVENTS_PATH",
                    "/work/data/live/events.jsonl",
                )
            ),
            gateway_checkpoint_path=Path(
                os.getenv(
                    "COLLECTOR_GATEWAY_CHECKPOINT_PATH",
                    "/work/data/collector/gateway-offset.json",
                )
            ),
            http_enabled=_env_bool(
                "COLLECTOR_HTTP_ENABLED",
                True,
            ),
            http_timeout_sec=_env_float(
                "COLLECTOR_HTTP_TIMEOUT_SEC",
                2.0,
            ),
            http_poll_interval_sec=_env_float(
                "COLLECTOR_HTTP_POLL_INTERVAL_SEC",
                10.0,
            ),
            http_targets=_parse_http_targets(
                os.getenv(
                    "COLLECTOR_HTTP_TARGETS",
                    (
                        "gateway-health|gateway|status|"
                        "[cybersecurity-gateway](http://cybersecurity-gateway:8080/)"
                        "_cybersecurity/healthz"
                    ),
                )
            ),
            mqtt_enabled=_env_bool(
                "COLLECTOR_MQTT_ENABLED",
                False,
            ),
            mqtt_host=os.getenv(
                "COLLECTOR_MQTT_HOST",
                "mosquitto",
            ).strip(),
            mqtt_port=_env_int(
                "COLLECTOR_MQTT_PORT",
                1883,
            ),
            mqtt_client_id=os.getenv(
                "COLLECTOR_MQTT_CLIENT_ID",
                "cybersecurity-collector",
            ).strip(),
            mqtt_topics=tuple(
                topic.strip()
                for topic in os.getenv(
                    "COLLECTOR_MQTT_TOPICS",
                    "smartenergy/#",
                ).split(",")
                if topic.strip()
            ),
            mqtt_qos=_env_int(
                "COLLECTOR_MQTT_QOS",
                1,
            ),
            mqtt_username=os.getenv(
                "COLLECTOR_MQTT_USERNAME",
                "",
            ).strip(),
            mqtt_password=os.getenv(
                "COLLECTOR_MQTT_PASSWORD",
                "",
            ),
            mqtt_tls=_env_bool(
                "COLLECTOR_MQTT_TLS",
                False,
            ),
            mqtt_queue_size=_env_int(
                "COLLECTOR_MQTT_QUEUE_SIZE",
                10_000,
            ),
        )

        settings.validate()
        return settings

    def validate(self) -> None:
        """Перевіряє коректність налаштувань Collector."""

        if self.poll_interval_sec <= 0:
            raise ValueError(
                "COLLECTOR_POLL_INTERVAL_SEC має бути більше нуля"
            )

        if self.dedup_window_sec < 0:
            raise ValueError(
                "COLLECTOR_DEDUP_WINDOW_SEC не може бути від'ємним"
            )

        if self.http_timeout_sec <= 0:
            raise ValueError(
                "COLLECTOR_HTTP_TIMEOUT_SEC має бути більше нуля"
            )

        if self.http_poll_interval_sec <= 0:
            raise ValueError(
                "COLLECTOR_HTTP_POLL_INTERVAL_SEC має бути більше нуля"
            )

        if not 1 <= self.mqtt_port <= 65_535:
            raise ValueError(
                "COLLECTOR_MQTT_PORT має бути коректним TCP-портом"
            )

        if self.mqtt_qos not in {0, 1, 2}:
            raise ValueError(
                "COLLECTOR_MQTT_QOS має дорівнювати 0, 1 або 2"
            )

        if self.mqtt_queue_size < 1:
            raise ValueError(
                "COLLECTOR_MQTT_QUEUE_SIZE має бути не менше 1"
            )

        if (
            self.gateway_enabled
            and self.gateway_events_path.resolve()
            == self.output_path.resolve()
        ):
            raise ValueError(
                "Вхідний журнал Gateway і вихід Collector "
                "не можуть бути одним файлом"
            )


def _parse_http_targets(
    raw_value: str,
) -> tuple[HttpTarget, ...]:
    """Розбирає перелік HTTP-джерел із конфігурації."""

    targets: list[HttpTarget] = []

    for raw_target in raw_value.split(";"):
        raw_target = raw_target.strip()
        if not raw_target:
            continue

        parts = raw_target.split("|", maxsplit=3)
        if len(parts) != 4:
            raise ValueError(
                "COLLECTOR_HTTP_TARGETS має формат "
                "id|component|mode|url"
            )

        target_id, component, mode, url = (
            part.strip()
            for part in parts
        )

        if mode not in {"status", "telemetry"}:
            raise ValueError(
                "Режим HTTP-джерела має бути status або telemetry"
            )

        if not url.startswith(("http://", "https://")):
            raise ValueError(
                f"Некоректний URL HTTP-джерела: {url}"
            )

        targets.append(
            HttpTarget(
                target_id=target_id,
                component=component,
                mode=mode,
                url=url,
            )
        )

    return tuple(targets)