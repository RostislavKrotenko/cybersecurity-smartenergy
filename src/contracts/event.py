"""Модель події (Event) для всіх модулів системи."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass

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

    @staticmethod
    def csv_header() -> str:
        return ",".join(CSV_COLUMNS)
