"""Основний цикл об'єднаного Collector SmartEnergy."""

from __future__ import annotations

import hashlib
import logging
import threading
import time

from src.adapters.file_adapter import FileEventSink
from src.collector.config import CollectorSettings
from src.collector.sources import (
    GatewayEventSource,
    HttpEventSource,
    MqttEventSource,
)
from src.contracts.event import Event
from src.contracts.interfaces import EventSource

log = logging.getLogger(__name__)


class CollectorService:
    """Об'єднує події з кількох джерел в один JSONL-потік."""

    def __init__(
        self,
        *,
        sources: list[EventSource],
        output_path: str,
        poll_interval_sec: float,
        dedup_window_sec: float,
    ) -> None:
        """Створює Collector із заданими джерелами."""

        if not sources:
            raise ValueError(
                "Collector повинен мати хоча б одне джерело"
            )

        self._sources = sources
        self._sink = FileEventSink(output_path)
        self._poll_interval_sec = poll_interval_sec
        self._dedup_window_sec = dedup_window_sec
        self._seen: dict[str, float] = {}

    def collect_once(self) -> int:
        """Зчитує один пакет із кожного джерела."""

        collected: list[Event] = []

        for source in self._sources:
            try:
                events = source.read_batch()
            except Exception:
                log.exception(
                    "Помилка читання джерела %s",
                    type(source).__name__,
                )
                continue

            for event in events:
                if not self._is_duplicate(event):
                    collected.append(event)

        if collected:
            self._sink.emit_batch(collected)

        self._prune_seen()
        return len(collected)

    def run(self, stop_event: threading.Event) -> None:
        """Працює до отримання сигналу завершення."""

        log.info(
            "Collector запущено з %d джерелами",
            len(self._sources),
        )

        while not stop_event.is_set():
            count = self.collect_once()

            if count:
                log.info(
                    "Collector записав %d нових подій",
                    count,
                )

            stop_event.wait(self._poll_interval_sec)

    def close(self) -> None:
        """Закриває всі джерела та вихідний файл."""

        for source in self._sources:
            try:
                source.close()
            except Exception:
                log.exception(
                    "Помилка закриття джерела %s",
                    type(source).__name__,
                )

        self._sink.close()

    def _is_duplicate(self, event: Event) -> bool:
        """Перевіряє короткочасне дублювання події."""

        if self._dedup_window_sec == 0:
            return False

        signature = "|".join(
            (
                event.source,
                event.component,
                event.event,
                event.key,
                event.value,
                event.severity,
                event.actor,
                event.ip,
                event.correlation_id,
            )
        )
        digest = hashlib.sha256(
            signature.encode("utf-8")
        ).hexdigest()

        now = time.monotonic()
        previous = self._seen.get(digest)
        self._seen[digest] = now

        return (
            previous is not None
            and now - previous < self._dedup_window_sec
        )

    def _prune_seen(self) -> None:
        """Видаляє застарілі сигнатури дедуплікації."""

        if not self._seen:
            return

        threshold = (
            time.monotonic()
            - max(self._dedup_window_sec, 1.0) * 2
        )

        expired = [
            digest
            for digest, timestamp in self._seen.items()
            if timestamp < threshold
        ]

        for digest in expired:
            self._seen.pop(digest, None)


def create_collector(
    settings: CollectorSettings,
) -> CollectorService:
    """Створює Collector відповідно до конфігурації."""

    sources: list[EventSource] = []

    if settings.gateway_enabled:
        sources.append(
            GatewayEventSource(
                path=settings.gateway_events_path,
                checkpoint_path=(
                    settings.gateway_checkpoint_path
                ),
            )
        )

    if settings.http_enabled and settings.http_targets:
        sources.append(
            HttpEventSource(
                targets=settings.http_targets,
                timeout_sec=settings.http_timeout_sec,
                poll_interval_sec=(
                    settings.http_poll_interval_sec
                ),
            )
        )

    if settings.mqtt_enabled:
        sources.append(
            MqttEventSource(
                host=settings.mqtt_host,
                port=settings.mqtt_port,
                client_id=settings.mqtt_client_id,
                topics=settings.mqtt_topics,
                qos=settings.mqtt_qos,
                queue_size=settings.mqtt_queue_size,
                username=settings.mqtt_username,
                password=settings.mqtt_password,
                tls_enabled=settings.mqtt_tls,
            )
        )

    return CollectorService(
        sources=sources,
        output_path=str(settings.output_path),
        poll_interval_sec=settings.poll_interval_sec,
        dedup_window_sec=settings.dedup_window_sec,
    )