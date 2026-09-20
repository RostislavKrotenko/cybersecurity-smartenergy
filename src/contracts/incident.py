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

    incident_id: str  # наприклад, "INC-001"
    policy: str  # застосована політика
    threat_type: str  # допустимі значення: credential_attack, availability_attack, integrity_attack, outage
    severity: str  # підвищений рівень критичності
    component: str  # уражені компоненти через крапку з комою
    event_count: int
    start_ts: str  # ISO-8601
    detect_ts: str  # ISO-8601
    recover_ts: str  # ISO-8601
    mttd_sec: float  # секунди
    mttr_sec: float  # секунди
    impact_score: float
    description: str
    response_action: str
    source: str = ""

    def to_csv_row(self) -> str:
        """Повертає один рядок CSV без символу нового рядка."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([getattr(self, c) for c in INCIDENT_CSV_COLUMNS])
        return buf.getvalue().rstrip("\r\n")

    @staticmethod
    def csv_header() -> str:
        return ",".join(INCIDENT_CSV_COLUMNS)
