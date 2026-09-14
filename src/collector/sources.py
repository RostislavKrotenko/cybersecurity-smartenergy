"""Джерела подій для Gateway, HTTP та MQTT."""

from __future__ import annotations

import json
import logging
import os
import queue
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from src.collector.config import HttpTarget
from src.contracts.event import Event
from src.contracts.interfaces import EventSource

log = logging.getLogger(__name__)


def _utc_now() -> str:
    """Повертає поточний час у форматі ISO-8601 UTC."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class GatewayEventSource(EventSource):
    """Читає нові канонічні події з JSONL-журналу Gateway."""

    def __init__(self, path: str | Path, checkpoint_path: str | Path) -> None:
        """Ініціалізує tail-читання з персистентним offset."""
        self._path = Path(path)
        self._checkpoint_path = Path(checkpoint_path)
        self._offset = 0
        self._inode: int | None = None
        self._load_checkpoint()

    def read_batch(self, limit: int = 10_000) -> list[Event]:
        """Зчитує пакет нових подій після збереженого offset."""
        if limit < 1 or not self._path.exists():
            return []

        try:
            stat = self._path.stat()
        except OSError:
            return []

        if self._inode is not None and self._inode != stat.st_ino:
            self._offset = 0

        if stat.st_size < self._offset:
            self._offset = 0

        self._inode = stat.st_ino
        events: list[Event] = []

        try:
            with self._path.open("r", encoding="utf-8") as stream:
                stream.seek(self._offset)

                while len(events) < limit:
                    line_start = stream.tell()
                    line = stream.readline()

                    if not line:
                        break

                    if not line.endswith("\n"):
                        stream.seek(line_start)
                        break

                    stripped = line.strip()
                    if not stripped:
                        continue

                    try:
                        payload = json.loads(stripped)
                    except json.JSONDecodeError:
                        log.warning("Collector пропустив пошкоджений JSONL-запис")
                        continue

                    if not isinstance(payload, dict):
                        log.warning("Collector пропустив JSONL без об'єкта")
                        continue

                    events.append(Event.from_dict(payload))

                self._offset = stream.tell()

        except OSError:
            log.exception("Не вдалося прочитати журнал Gateway: %s", self._path)
            return []

        self._save_checkpoint()
        return events

    def read_stream(self, poll_interval_sec: float = 1.0) -> Iterator[list[Event]]:
        """Повертає нескінченний потік пакетів подій."""
        while True:
            yield self.read_batch()
            time.sleep(poll_interval_sec)

    def get_offset(self) -> int:
        """Повертає поточну позицію читання."""
        return self._offset

    def seek(self, offset: Any) -> None:
        """Установлює нову позицію читання JSONL-журналу."""
        if not isinstance(offset, int) or offset < 0:
            raise ValueError("Offset Gateway має бути невід'ємним цілим числом")
        self._offset = offset
        self._save_checkpoint()

    def close(self) -> None:
        """Зберігає поточну позицію читання."""
        self._save_checkpoint()

    def _load_checkpoint(self) -> None:
        """Завантажує позицію попереднього читання."""
        if not self._checkpoint_path.exists():
            return

        try:
            payload = json.loads(self._checkpoint_path.read_text(encoding="utf-8"))
            self._offset = max(0, int(payload.get("offset", 0)))
            
            inode = payload.get("inode")
            self._inode = int(inode) if inode is not None else None
        except (OSError, ValueError, json.JSONDecodeError):
            log.warning("Не вдалося завантажити checkpoint Collector")
            self._offset = 0
            self._inode = None

    def _save_checkpoint(self) -> None:
        """Атомарно зберігає поточну позицію читання."""
        try:
            self._checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = self._checkpoint_path.with_suffix(
                self._checkpoint_path.suffix + ".tmp"
            )
            temporary_path.write_text(
                json.dumps({"offset": self._offset, "inode": self._inode}),
                encoding="utf-8",
            )
            os.replace(temporary_path, self._checkpoint_path)
        except OSError:
            log.exception("Не вдалося зберегти checkpoint Collector")


class HttpEventSource(EventSource):
    """Опитує read-only HTTP endpoints та створює події стану."""

    def __init__(
        self,
        targets: tuple[HttpTarget, ...],
        timeout_sec: float,
        poll_interval_sec: float,
    ) -> None:
        """Ініціалізує HTTP-джерело."""
        self._targets = targets
        self._poll_interval_sec = poll_interval_sec
        self._next_poll_at = 0.0
        self._offset = 0
        self._client = httpx.Client(timeout=timeout_sec, follow_redirects=False)

    def read_batch(self, limit: int = 10_000) -> list[Event]:
        """Опитує endpoints, якщо настав наступний інтервал."""
        now = time.monotonic()
        if now < self._next_poll_at or limit < 1:
            return []

        self._next_poll_at = now + self._poll_interval_sec
        events: list[Event] = []

        for target in self._targets:
            if len(events) >= limit:
                break
            events.extend(self._poll_target(target, limit - len(events)))

        self._offset += len(events)
        return events

    def read_stream(self, poll_interval_sec: float = 1.0) -> Iterator[list[Event]]:
        """Повертає потік результатів HTTP-опитування."""
        while True:
            yield self.read_batch()
            time.sleep(poll_interval_sec)

    def get_offset(self) -> int:
        """Повертає кількість сформованих HTTP-подій."""
        return self._offset

    def seek(self, offset: Any) -> None:
        """Перевіряє позицію непрограваного HTTP-джерела."""
        if offset != self._offset:
            raise ValueError("HTTP-джерело не підтримує повторне програвання")

    def close(self) -> None:
        """Закриває HTTP-клієнт."""
        self._client.close()

    def _poll_target(self, target: HttpTarget, limit: int) -> list[Event]:
        """Опитує один endpoint і формує події."""
        started_at = time.perf_counter()
        timestamp = _utc_now()

        try:
            response = self._client.get(
                target.url,
                headers={"Accept": "application/json"},
            )
            latency_ms = round((time.perf_counter() - started_at) * 1000, 3)
        except httpx.HTTPError:
            return [
                Event(
                    timestamp=timestamp,
                    source=target.target_id,
                    component=target.component,
                    event="service_status",
                    key="availability",
                    value="unavailable",
                    severity="high",
                    tags="collector,http,error",
                    correlation_id=f"http-{target.target_id}-{time.time_ns()}",
                )
            ]

        status_code = response.status_code
        healthy = 200 <= status_code < 300

        status_event = Event(
            timestamp=timestamp,
            source=target.target_id,
            component=target.component,
            event="service_status",
            key="http_status",
            value=str(status_code),
            severity="low" if healthy else "high" if status_code >= 500 else "medium",
            unit="HTTP",
            tags=f"collector,http,{target.mode},latency_ms={latency_ms}",
            correlation_id=f"http-{target.target_id}-{time.time_ns()}",
        )

        events = [status_event]

        if healthy and target.mode == "telemetry" and limit > 1:
            events.extend(
                self._extract_telemetry(
                    target=target,
                    response=response,
                    timestamp=timestamp,
                    limit=limit - 1,
                )
            )

        return events

    @staticmethod
    def _extract_telemetry(
        *,
        target: HttpTarget,
        response: httpx.Response,
        timestamp: str,
        limit: int,
    ) -> list[Event]:
        """Перетворює числові поля HTTP-відповіді на telemetry events."""
        try:
            payload = response.json()
        except ValueError:
            return []

        if isinstance(payload, list):
            records = payload
        elif isinstance(payload, dict):
            nested = (
                payload.get("items")
                or payload.get("data")
                or payload.get("telemetry")
            )
            records = nested if isinstance(nested, list) else [payload]
        else:
            return []

        events: list[Event] = []

        for record in records[:50]:
            if not isinstance(record, dict):
                continue

            source = str(
                record.get("source")
                or record.get("device_id")
                or record.get("deviceId")
                or record.get("id")
                or target.target_id
            )

            event_timestamp = str(
                record.get("timestamp") or record.get("ts") or timestamp
            )

            ignored_fields = {
                "id",
                "source",
                "device_id",
                "deviceId",
                "timestamp",
                "ts",
            }

            for key, value in record.items():
                if key in ignored_fields:
                    continue

                if not isinstance(value, (int, float)):
                    continue

                events.append(
                    Event(
                        timestamp=event_timestamp,
                        source=source,
                        component=target.component,
                        event="telemetry_read",
                        key=str(key),
                        value=str(value),
                        severity="low",
                        tags="collector,http,telemetry",
                        correlation_id=f"telemetry-{target.target_id}-{time.time_ns()}",
                    )
                )

                if len(events) >= limit:
                    return events

        return events


class MqttEventSource(EventSource):
    """Приймає події та телеметрію з MQTT broker."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        client_id: str,
        topics: tuple[str, ...],
        qos: int,
        queue_size: int,
        username: str = "",
        password: str = "",
        tls_enabled: bool = False,
    ) -> None:
        """Ініціалізує MQTT-клієнт і внутрішню чергу."""
        try:
            import paho.mqtt.client as mqtt
        except ImportError as error:
            raise RuntimeError("Для MQTT Collector потрібно встановити paho-mqtt") from error

        self._mqtt = mqtt
        self._host = host
        self._port = port
        self._topics = topics
        self._qos = qos
        self._events: queue.Queue[Event] = queue.Queue(maxsize=queue_size)
        self._offset = 0
        self._started = False
        self._dropped = 0

        callback_version = getattr(mqtt, "CallbackAPIVersion", None)

        if callback_version is not None:
            self._client = mqtt.Client(callback_version.VERSION2, client_id=client_id)
        else:
            self._client = mqtt.Client(client_id=client_id)

        if username:
            self._client.username_pw_set(username, password)

        if tls_enabled:
            self._client.tls_set()

        self._client.reconnect_delay_set(min_delay=1, max_delay=30)
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message

    def read_batch(self, limit: int = 10_000) -> list[Event]:
        """Повертає накопичені MQTT-події без блокування."""
        self._ensure_started()
        events: list[Event] = []

        while len(events) < limit:
            try:
                events.append(self._events.get_nowait())
            except queue.Empty:
                break

        self._offset += len(events)
        return events

    def read_stream(self, poll_interval_sec: float = 1.0) -> Iterator[list[Event]]:
        """Повертає потік пакетів MQTT-подій."""
        while True:
            yield self.read_batch()
            time.sleep(poll_interval_sec)

    def get_offset(self) -> int:
        """Повертає кількість прочитаних MQTT-повідомлень."""
        return self._offset

    def seek(self, offset: Any) -> None:
        """Перевіряє позицію непрограваного MQTT-джерела."""
        if offset != self._offset:
            raise ValueError("MQTT-джерело не підтримує довільний seek")

    def close(self) -> None:
        """Зупиняє мережевий цикл MQTT-клієнта."""
        if not self._started:
            return

        self._client.disconnect()
        self._client.loop_stop()
        self._started = False

    @property
    def dropped_messages(self) -> int:
        """Повертає кількість повідомлень, втрачених через повну чергу."""
        return self._dropped

    def _ensure_started(self) -> None:
        """Запускає MQTT-клієнт під час першого читання."""
        if self._started:
            return

        self._client.connect_async(self._host, self._port, keepalive=60)
        self._client.loop_start()
        self._started = True

    def _on_connect(
        self,
        client: Any,
        userdata: Any,
        flags: Any,
        reason_code: Any,
        properties: Any = None,
    ) -> None:
        """Підписується на теми після з'єднання або reconnect."""
        if reason_code != 0:
            log.error("MQTT broker відхилив підключення: %s", reason_code)
            return

        for topic in self._topics:
            client.subscribe(topic, qos=self._qos)

        log.info("Collector підписався на MQTT topics: %s", ", ".join(self._topics))

    def _on_message(self, client: Any, userdata: Any, message: Any) -> None:
        """Перетворює MQTT-повідомлення на канонічну подію."""
        try:
            event = self._message_to_event(
                topic=str(message.topic),
                payload=bytes(message.payload),
            )
            self._events.put_nowait(event)
        except queue.Full:
            self._dropped += 1
            log.error("Черга MQTT Collector переповнена")
        except Exception:
            log.exception("Не вдалося обробити MQTT-повідомлення")

    @staticmethod
    def _message_to_event(*, topic: str, payload: bytes) -> Event:
        """Перетворює MQTT payload на Event."""
        text = payload.decode("utf-8", errors="replace")

        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            decoded = {"value": text}

        if not isinstance(decoded, dict):
            decoded = {"value": decoded}

        raw_tags = decoded.get("tags", "collector,mqtt")
        if isinstance(raw_tags, list):
            tags = ",".join(str(item) for item in raw_tags)
        else:
            tags = str(raw_tags)

        value = decoded.get("value", decoded)
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))

        component = str(
            decoded.get("component") or MqttEventSource._component_from_topic(topic)
        )

        return Event(
            timestamp=str(decoded.get("timestamp") or decoded.get("ts") or _utc_now()),
            source=str(
                decoded.get("source")
                or decoded.get("device_id")
                or decoded.get("deviceId")
                or topic
            ),
            component=component,
            event=str(decoded.get("event") or "telemetry_read"),
            key=str(decoded.get("key") or topic),
            value=str(value),
            severity=str(decoded.get("severity") or "low").lower(),
            actor=str(decoded.get("actor") or ""),
            ip=str(decoded.get("ip") or ""),
            unit=str(decoded.get("unit") or ""),
            tags=tags,
            correlation_id=str(
                decoded.get("correlation_id")
                or decoded.get("correlationId")
                or f"mqtt-{time.time_ns()}"
            ),
        )

    @staticmethod
    def _component_from_topic(topic: str) -> str:
        """Визначає компонент за назвою MQTT topic."""
        normalized = topic.lower()

        if "inverter" in normalized:
            return "inverter"
        if "meter" in normalized or "rtu" in normalized:
            return "edge"
        if "auth" in normalized:
            return "auth"
        if "gateway" in normalized:
            return "gateway"

        return "collector"