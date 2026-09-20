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
class GatewayEventLog:
    """Опис окремого журналу подій захисного Gateway."""

    service_id: str
    events_path: Path
    checkpoint_path: Path


@dataclass(frozen=True, slots=True)
class CollectorSettings:
    """Налаштування збирача подій кіберзахисту."""

    output_path: Path
    poll_interval_sec: float
    dedup_window_sec: float

    gateway_enabled: bool
    gateway_event_logs: tuple[GatewayEventLog, ...]

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
    mqtt_quarantine_enabled: bool
    mqtt_quarantine_path: Path
    mqtt_voltage_min: float
    mqtt_voltage_max: float
    mqtt_voltage_delta: float
    mqtt_power_kw_min: float
    mqtt_power_kw_max: float
    mqtt_power_kw_delta: float
    mqtt_current_a_min: float
    mqtt_current_voltage_min: float
    mqtt_current_voltage_max: float

    @classmethod
    def from_env(cls) -> "CollectorSettings":
        """Створює конфігурацію зі змінних середовища."""

        settings = cls(
            output_path=Path(
                os.getenv(
                    "COLLECTOR_OUTPUT_PATH",
                    "/work/data/integration/collected_events.jsonl",
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
            gateway_event_logs=_parse_gateway_event_logs(
                os.getenv("COLLECTOR_GATEWAY_EVENT_LOGS", ""),
                fallback_events_path=os.getenv(
                    "COLLECTOR_GATEWAY_EVENTS_PATH",
                    "/work/data/integration/events.jsonl",
                ),
                fallback_checkpoint_path=os.getenv(
                    "COLLECTOR_GATEWAY_CHECKPOINT_PATH",
                    "/work/data/integration/gateway-offset.json",
                ),
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
                        "http://cybersecurity-gateway:8080/"
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
            mqtt_quarantine_enabled=_env_bool(
                "COLLECTOR_MQTT_QUARANTINE_ENABLED",
                True,
            ),
            mqtt_quarantine_path=Path(
                os.getenv(
                    "COLLECTOR_MQTT_QUARANTINE_PATH",
                    "/work/data/integration/quarantine/mqtt-events.jsonl",
                )
            ),
            mqtt_voltage_min=_env_float(
                "COLLECTOR_MQTT_VOLTAGE_MIN",
                180.0,
            ),
            mqtt_voltage_max=_env_float(
                "COLLECTOR_MQTT_VOLTAGE_MAX",
                280.0,
            ),
            mqtt_voltage_delta=_env_float(
                "COLLECTOR_MQTT_VOLTAGE_DELTA",
                50.0,
            ),
            mqtt_power_kw_min=_env_float(
                "COLLECTOR_MQTT_POWER_KW_MIN",
                -10.0,
            ),
            mqtt_power_kw_max=_env_float(
                "COLLECTOR_MQTT_POWER_KW_MAX",
                100.0,
            ),
            mqtt_power_kw_delta=_env_float(
                "COLLECTOR_MQTT_POWER_KW_DELTA",
                30.0,
            ),
            mqtt_current_a_min=_env_float(
                "COLLECTOR_MQTT_CURRENT_A_MIN",
                0.5,
            ),
            mqtt_current_voltage_min=_env_float(
                "COLLECTOR_MQTT_CURRENT_VOLTAGE_MIN",
                180.0,
            ),
            mqtt_current_voltage_max=_env_float(
                "COLLECTOR_MQTT_CURRENT_VOLTAGE_MAX",
                280.0,
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

        if self.gateway_enabled and not self.gateway_event_logs:
            raise ValueError(
                "Для увімкненого Gateway потрібно налаштувати хоча б один журнал"
            )

        service_ids: set[str] = set()
        checkpoint_paths: set[Path] = set()

        for gateway_log in self.gateway_event_logs:
            if gateway_log.service_id in service_ids:
                raise ValueError(
                    "COLLECTOR_GATEWAY_EVENT_LOGS містить повторний serviceId: "
                    f"{gateway_log.service_id}"
                )
            service_ids.add(gateway_log.service_id)

            if gateway_log.events_path.resolve() == self.output_path.resolve():
                raise ValueError(
                    "Вхідний журнал Gateway і вихід Collector "
                    "не можуть бути одним файлом"
                )

            normalized_checkpoint = gateway_log.checkpoint_path.resolve()
            if normalized_checkpoint in checkpoint_paths:
                raise ValueError(
                    "Кожен Gateway повинен мати окремий checkpoint"
                )
            checkpoint_paths.add(normalized_checkpoint)

        if self.mqtt_quarantine_path.resolve() == self.output_path.resolve():
            raise ValueError(
                "Карантин MQTT і вихід Collector не можуть бути одним файлом"
            )

        if self.mqtt_voltage_min >= self.mqtt_voltage_max:
            raise ValueError("Межі напруги MQTT задано некоректно")

        if self.mqtt_power_kw_min >= self.mqtt_power_kw_max:
            raise ValueError("Межі потужності MQTT задано некоректно")

        if self.mqtt_voltage_delta <= 0 or self.mqtt_power_kw_delta <= 0:
            raise ValueError("Допустимі стрибки MQTT мають бути більше нуля")

        if self.mqtt_current_a_min < 0:
            raise ValueError("Мінімальний струм MQTT не може бути від'ємним")

        if self.mqtt_current_voltage_min >= self.mqtt_current_voltage_max:
            raise ValueError("Контекстні межі напруги для струму задано некоректно")


def _parse_gateway_event_logs(
    raw_value: str,
    *,
    fallback_events_path: str,
    fallback_checkpoint_path: str,
) -> tuple[GatewayEventLog, ...]:
    """Розбирає журнали Gateway з формату serviceId|events|checkpoint."""

    if not raw_value.strip():
        return (
            GatewayEventLog(
                service_id="iot-gateway",
                events_path=Path(fallback_events_path),
                checkpoint_path=Path(fallback_checkpoint_path),
            ),
        )

    logs: list[GatewayEventLog] = []

    for raw_log in raw_value.split(";"):
        raw_log = raw_log.strip()
        if not raw_log:
            continue

        parts = [part.strip() for part in raw_log.split("|", maxsplit=2)]
        if len(parts) != 3 or not all(parts):
            raise ValueError(
                "COLLECTOR_GATEWAY_EVENT_LOGS має формат "
                "serviceId|eventsPath|checkpointPath"
            )

        service_id, events_path, checkpoint_path = parts
        logs.append(
            GatewayEventLog(
                service_id=service_id,
                events_path=Path(events_path),
                checkpoint_path=Path(checkpoint_path),
            )
        )

    return tuple(logs)


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
