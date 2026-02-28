"""Incident data-class — a correlated group of Alerts."""

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
]


@dataclass(slots=True)
class Incident:
    """A correlated security incident with timing metrics.

    Timing model
    ─────────────
      start_ts   — timestamp of the first malicious event
      detect_ts  — timestamp when the alert was raised (= start_ts + MTTD)
      recover_ts — timestamp when the incident was resolved (= detect_ts + MTTR)

    Metric formulas
    ───────────────
      MTTD = detect_ts − start_ts          (Mean-Time-To-Detect per incident)
      MTTR = recover_ts − detect_ts         (Mean-Time-To-Recover per incident)
      Downtime = recover_ts − start_ts      (total incident duration)
      impact_score ∈ [0..1] = severity_weight × confidence × impact_multiplier
    """

    incident_id: str  # e.g. "INC-001"
    policy: str  # which policy was applied
    threat_type: str  # credential_attack | availability_attack | integrity_attack | outage
    severity: str  # escalated severity
    component: str  # affected component(s), semicolon-separated
    event_count: int
    start_ts: str  # ISO-8601
    detect_ts: str  # ISO-8601
    recover_ts: str  # ISO-8601
    mttd_sec: float  # seconds
    mttr_sec: float  # seconds
    impact_score: float  # 0.0 — 1.0
    description: str
    response_action: str

    # ── serialisation ────────────────────────────────────────────────────

    def to_csv_row(self) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([getattr(self, c) for c in INCIDENT_CSV_COLUMNS])
        return buf.getvalue().rstrip("\r\n")

    @staticmethod
    def csv_header() -> str:
        return ",".join(INCIDENT_CSV_COLUMNS)
