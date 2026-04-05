"""Модель події (Event) для всіх модулів системи."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass
from typing import Any

CSV_COLUMNS: list[str] = [
    "timestamp",
    "source",
    "component",
    "event",
    "actor",
    "ip",
    "key",
    "value",
    "unit",
    "severity",
    "tags",
    "correlation_id",
]


@dataclass(slots=True)
class Event:
    """Нормалізована подія в конвеєрі SmartEnergy."""

    timestamp: str
    source: str
    component: str
    event: str
    key: str
    value: str
    severity: str
    actor: str = ""
    ip: str = ""
    unit: str = ""
    tags: str = ""
    correlation_id: str = ""

    def to_csv_row(self) -> str:
        """Повертає один рядок CSV без символу нового рядка."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([getattr(self, c) for c in CSV_COLUMNS])
        return buf.getvalue().rstrip("\r\n")

    def to_json(self) -> str:
        """Повертає компактний JSON рядок."""
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> Event:
        """Створює Event зі словника (CSV row або JSON object)."""
        return cls(
            timestamp=row.get("timestamp", ""),
            source=row.get("source", ""),
            component=row.get("component", ""),
            event=row.get("event", ""),
            key=row.get("key", ""),
            value=str(row.get("value", "")),
            severity=row.get("severity", "low"),
            actor=row.get("actor", ""),
            ip=row.get("ip", ""),
            unit=row.get("unit", ""),
            tags=row.get("tags", ""),
            correlation_id=row.get("correlation_id", ""),
        )

    @staticmethod
    def csv_header() -> str:
        return ",".join(CSV_COLUMNS)
