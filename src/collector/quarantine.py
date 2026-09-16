"""Карантин аномальної MQTT-телеметрії перед Analyzer."""

from __future__ import annotations

import json
import logging
import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from src.contracts.event import Event

log = logging.getLogger(__name__)


def _utc_now() -> str:
    """Повертає поточний UTC-час у форматі ISO-8601."""

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class TelemetryLimit:
    """Допустимі межі та максимальний стрибок одного показника."""

    minimum: float
    maximum: float
    maximum_delta: float


class MqttTelemetryQuarantine:
    """Вилучає небезпечні MQTT-вимірювання з робочого потоку.

    Оригінальна подія записується до окремого JSONL-журналу. До Analyzer
    передається лише службове повідомлення ``telemetry_quarantined``, тому
    аномальне значення не потрапляє до звичайної телеметрії, але зберігається
    доказ для створення інциденту та подальшого аудиту.
    """

    def __init__(
        self,
        *,
        path: str | Path,
        enabled: bool,
        limits: dict[str, TelemetryLimit],
    ) -> None:
        """Створює карантин із заданими фізичними межами."""

        self._path = Path(path)
        self._enabled = enabled
        self._limits = dict(limits)
        self._last_valid_values: dict[tuple[str, str], float] = {}
        self._quarantined_count = 0

        if self._enabled:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def quarantined_count(self) -> int:
        """Повертає кількість записів, відправлених у карантин."""

        return self._quarantined_count

    def process(self, event: Event) -> Event:
        """Обробляє одну подію зі збереженням сумісності інтерфейсу."""

        return self.process_batch([event])[0]

    def process_batch(self, events: list[Event]) -> list[Event]:
        """Атомарно перевіряє пакети вимірювань з MQTT-повідомлень.

        Нормалізатор створює кілька подій з одного MQTT payload. Якщо хоча б
        один контрольований показник такого payload є аномальним, усі його
        вимірювання вилучаються з робочого потоку. Замість них повертається
        одне службове повідомлення про карантин.
        """

        if not self._enabled or not events:
            return list(events)

        groups: dict[str, list[tuple[int, Event]]] = {}
        for index, event in enumerate(events):
            if not self._is_mqtt_telemetry(event):
                continue
            groups.setdefault(
                self._message_id(event),
                [],
            ).append((index, event))

        suppressed_indexes: set[int] = set()
        replacements: dict[int, Event] = {}

        for message_id, indexed_events in groups.items():
            violations: list[tuple[Event, list[str]]] = []

            for _, event in indexed_events:
                if not self._should_inspect(event):
                    continue
                reasons, _ = self._inspect(event)
                if reasons:
                    violations.append((event, reasons))

            if violations:
                message_events = [event for _, event in indexed_events]
                first_index = indexed_events[0][0]
                primary_event, primary_reasons = violations[0]
                all_reasons = list(
                    dict.fromkeys(
                        reason
                        for _, reasons in violations
                        for reason in reasons
                    )
                )

                self._write_record(
                    message_id=message_id,
                    message_events=message_events,
                    violations=violations,
                )
                self._quarantined_count += 1
                suppressed_indexes.update(
                    index for index, _ in indexed_events
                )
                replacements[first_index] = self._quarantine_notice(
                    primary_event,
                    all_reasons or primary_reasons,
                )
                continue

            for _, event in indexed_events:
                if not self._should_inspect(event):
                    continue
                _, numeric_value = self._inspect(event)
                if math.isfinite(numeric_value):
                    self._last_valid_values[(event.source, event.key)] = (
                        numeric_value
                    )

        result: list[Event] = []
        for index, event in enumerate(events):
            replacement = replacements.get(index)
            if replacement is not None:
                result.append(replacement)
            if index not in suppressed_indexes:
                result.append(event)

        return result

    def close(self) -> None:
        """Записує підсумкову статистику карантину до журналу застосунку."""

        log.info(
            "MQTT quarantine: %d повідомлень ізольовано у %s",
            self._quarantined_count,
            self._path,
        )

    def _should_inspect(self, event: Event) -> bool:
        """Перевіряє, чи подія належить до контрольованої телеметрії."""

        return (
            self._is_mqtt_telemetry(event)
            and event.key in self._limits
        )

    @staticmethod
    def _is_mqtt_telemetry(event: Event) -> bool:
        """Перевіряє належність події до MQTT-пакета телеметрії."""

        tags = {item.strip().lower() for item in event.tags.split(",")}
        return event.event == "telemetry_read" and "mqtt" in tags

    @staticmethod
    def _message_id(event: Event) -> str:
        """Повертає спільний ідентифікатор нормалізованого MQTT payload."""

        correlation_id = event.correlation_id.strip()
        if ":" not in correlation_id:
            return correlation_id or f"{event.source}|{event.timestamp}"
        return correlation_id.rsplit(":", 1)[0]

    def _inspect(self, event: Event) -> tuple[list[str], float]:
        """Повертає причини відхилення та числове значення показника."""

        limit = self._limits[event.key]
        reasons: list[str] = []

        try:
            numeric_value = float(event.value)
        except (TypeError, ValueError):
            numeric_value = math.nan

        if not math.isfinite(numeric_value):
            reasons.append("invalid_numeric_value")
            return reasons, numeric_value

        if numeric_value < limit.minimum or numeric_value > limit.maximum:
            reasons.append("outside_physical_bounds")

        previous = self._last_valid_values.get((event.source, event.key))
        if (
            previous is not None
            and abs(numeric_value - previous) > limit.maximum_delta
        ):
            reasons.append("abrupt_value_change")

        return reasons, numeric_value

    @staticmethod
    def _quarantine_notice(event: Event, reasons: list[str]) -> Event:
        """Створює єдине безпечне повідомлення для Analyzer."""

        tags = [item.strip() for item in event.tags.split(",") if item.strip()]
        tags.extend(("quarantine", *(f"reason:{reason}" for reason in reasons)))

        return Event(
            timestamp=event.timestamp,
            source=event.source,
            component=event.component,
            event="telemetry_quarantined",
            key=event.key,
            value=event.value,
            severity="high",
            actor=event.actor,
            ip=event.ip,
            unit=event.unit,
            tags=",".join(dict.fromkeys(tags)),
            correlation_id=event.correlation_id,
        )

    def _write_record(
        self,
        *,
        message_id: str,
        message_events: list[Event],
        violations: list[tuple[Event, list[str]]],
    ) -> None:
        """Дописує повний нормалізований MQTT-пакет до JSONL."""

        primary_event, _ = violations[0]

        record = {
            "quarantinedAt": _utc_now(),
            "messageId": message_id,
            "reasons": list(
                dict.fromkeys(
                    reason
                    for _, reasons in violations
                    for reason in reasons
                )
            ),
            "event": asdict(primary_event),
            "messageEvents": [asdict(event) for event in message_events],
            "violations": [
                {
                    "key": event.key,
                    "source": event.source,
                    "value": event.value,
                    "reasons": reasons,
                }
                for event, reasons in violations
            ],
        }

        try:
            with self._path.open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        record,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                )
                stream.write("\n")
                stream.flush()
        except OSError:
            log.exception(
                "Не вдалося записати MQTT-подію до карантину %s",
                self._path,
            )
