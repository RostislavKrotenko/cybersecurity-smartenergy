"""Фільтри після парсингу: дедуплікація та валідація."""

from __future__ import annotations

import logging

from src.contracts.event import Event

log = logging.getLogger(__name__)


def deduplicate(
    events: list[Event],
    window_sec: int = 2,
) -> list[Event]:
    """Видаляє дублікати у межах часового вікна.

    Аргументи:
        events: Відсортований список подій.
        window_sec: Вікно дедуплікації в секундах.

    Повертає:
        Список подій без дублікатів.
    """
    if not events:
        return events

    seen: dict[tuple[str, str, str, str], str] = {}
    result: list[Event] = []
    removed = 0

    for ev in events:
        fingerprint = (ev.source, ev.event, ev.key, ev.value)
        last_ts = seen.get(fingerprint)

        if last_ts is not None:
            try:
                from datetime import datetime

                dt_cur = datetime.strptime(ev.timestamp, "%Y-%m-%dT%H:%M:%SZ")
                dt_prev = datetime.strptime(last_ts, "%Y-%m-%dT%H:%M:%SZ")
                delta = abs((dt_cur - dt_prev).total_seconds())
                if delta <= window_sec:
                    removed += 1
                    continue
            except ValueError:
                pass  # якщо timestamp не парситься, залишаємо подію

        seen[fingerprint] = ev.timestamp
        result.append(ev)

    if removed:
        log.info("Дедуплікація прибрала %d дублікати подій (вікно=%ds)", removed, window_sec)

    return result


def validate_event(event: Event) -> list[str]:
    """Перевіряє подію та повертає список попереджень (порожній = валідна)."""
    warnings: list[str] = []

    valid_severities = {"low", "medium", "high", "critical"}
    if event.severity not in valid_severities:
        warnings.append(f"невідомий рівень критичності '{event.severity}'")

    valid_components = {
        "gateway",
        "edge",
        "api",
        "auth",
        "db",
        "ui",
        "collector",
        "inverter",
        "network",
        "unknown",
    }
    if event.component not in valid_components:
        warnings.append(f"невідомий компонент '{event.component}'")

    if not event.timestamp:
        warnings.append("порожній timestamp")

    return warnings
