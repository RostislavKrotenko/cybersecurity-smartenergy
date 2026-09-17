"""Модель інциденту (Incident)."""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass

INCIDENT_CSV_COLUMNS = [
    "incident_id",
    "policy",
    "threat_type",
    "severity",
    "component",
    "event_count",
    "start_ts",
    "detect_ts",
    "recover_ts",
    "mttd_sec",
    "mttr_sec",
    "impact_score",
    "description",
    "response_action",
    "source",
]


@dataclass(slots=True)
class Incident:
    """Корельований інцидент безпеки з метриками часу."""

    incident_id: str
    policy: str
    threat_type: str
    severity: str
    component: str
    event_count: int
    start_ts: str
    detect_ts: str
    recover_ts: str
    mttd_sec: float
    mttr_sec: float
    impact_score: float
    description: str
    response_action: str
    source: str = ""

    def to_csv_row(self) -> str:
        """Повертає один рядок CSV без символу нового рядка."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [getattr(self, column) for column in INCIDENT_CSV_COLUMNS]
        )
        return buf.getvalue().rstrip("\r\n")

    @staticmethod
    def csv_header() -> str:
        """Повертає заголовок CSV для збереження інцидентів."""
        return ",".join(INCIDENT_CSV_COLUMNS)
