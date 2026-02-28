"""Metrics Engine -- compute resilience metrics from Incidents.

Downtime definition
───────────────────
    Downtime is the interval from ``detect_ts`` (moment of detection) to
    ``recover_ts`` (full recovery).  It equals MTTR and does **not** include
    MTTD.  Only incidents with severity >= high are counted.  Overlapping
    intervals are merged before summing.

    ``total_downtime = SUM(recover_ts - detect_ts)``  (after merge)

    Incidents that lack a valid ``detect_ts`` or ``recover_ts`` are skipped
    in the downtime calculation (they still count towards incident totals
    and MTTD/MTTR averages).

Metrics computed per policy
───────────────────────────
  availability_pct
      Percentage of the analysis horizon with no critical/high incident active.
      Formula: ``(1 - total_downtime / horizon) * 100``

  total_downtime_hr
      Sum of merged incident durations ``(recover_ts - detect_ts)`` for
      severity >= high, converted to hours.

  mean_mttd_min
      Average MTTD across all incidents, in minutes.
      ``avg(mttd_sec) / 60``

  mean_mttr_min
      Average MTTR across all incidents, in minutes.
      ``avg(mttr_sec) / 60``

  incidents_total
      Total number of incidents.

  incidents_by_severity
      Dict mapping severity -> count.

  incidents_by_threat
      Dict mapping threat_type -> count.

Timestamps
──────────
    All timestamps in CSV/JSONL files are stored in **UTC** (ISO-8601 with
    ``Z`` or ``+00:00`` suffix).  The dashboard converts them to the
    user-selected display timezone (default ``Europe/Kyiv``) purely for
    rendering; no computation uses local time.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

from src.contracts.incident import Incident

log = logging.getLogger(__name__)


RESULTS_CSV_COLUMNS = [
    "policy",
    "availability_pct",
    "total_downtime_hr",
    "mean_mttd_min",
    "mean_mttr_min",
    "incidents_total",
    "incidents_critical",
    "incidents_high",
    "incidents_medium",
    "incidents_low",
    "by_credential_attack",
    "by_availability_attack",
    "by_integrity_attack",
    "by_outage",
]


@dataclass
class PolicyMetrics:
    """Агреговані метрики стійкості для однієї політики."""

    policy: str
    availability_pct: float = 100.0
    total_downtime_hr: float = 0.0
    mean_mttd_min: float = 0.0
    mean_mttr_min: float = 0.0
    incidents_total: int = 0
    incidents_by_severity: dict[str, int] = field(default_factory=dict)
    incidents_by_threat: dict[str, int] = field(default_factory=dict)

    def to_csv_row(self) -> str:
        """Повертає один рядок CSV для results.csv."""
        sev = self.incidents_by_severity
        thr = self.incidents_by_threat
        vals = [
            self.policy,
            f"{self.availability_pct:.2f}",
            f"{self.total_downtime_hr:.4f}",
            f"{self.mean_mttd_min:.2f}",
            f"{self.mean_mttr_min:.2f}",
            str(self.incidents_total),
            str(sev.get("critical", 0)),
            str(sev.get("high", 0)),
            str(sev.get("medium", 0)),
            str(sev.get("low", 0)),
            str(thr.get("credential_attack", 0)),
            str(thr.get("availability_attack", 0)),
            str(thr.get("integrity_attack", 0)),
            str(thr.get("outage", 0)),
        ]
        return ",".join(vals)

    @staticmethod
    def csv_header() -> str:
        return ",".join(RESULTS_CSV_COLUMNS)


def _ts(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def compute(
    incidents: list[Incident],
    policy_name: str,
    horizon_sec: float,
) -> PolicyMetrics:
    """Обчислює метрики стійкості для однієї політики.

    Args:
        incidents: Список інцидентів.
        policy_name: Назва політики.
        horizon_sec: Горизонт аналізу в секундах.

    Returns:
        PolicyMetrics з обчисленими значеннями.
    """
    m = PolicyMetrics(policy=policy_name)

    if not incidents:
        log.info("No incidents for policy '%s' — 100%% availability", policy_name)
        return m

    m.incidents_total = len(incidents)

    # Count by severity and threat_type
    for inc in incidents:
        m.incidents_by_severity[inc.severity] = m.incidents_by_severity.get(inc.severity, 0) + 1
        m.incidents_by_threat[inc.threat_type] = m.incidents_by_threat.get(inc.threat_type, 0) + 1

    # MTTD and MTTR averages
    m.mean_mttd_min = round(sum(i.mttd_sec for i in incidents) / len(incidents) / 60, 2)
    m.mean_mttr_min = round(sum(i.mttr_sec for i in incidents) / len(incidents) / 60, 2)

    # Downtime: merge overlapping intervals of severity >= high
    # Downtime = detect_ts -> recover_ts (does NOT include MTTD)
    high_sev = {"high", "critical"}
    intervals: list[tuple[datetime, datetime]] = []
    for inc in incidents:
        if inc.severity in high_sev:
            if not inc.detect_ts or not inc.recover_ts:
                log.warning(
                    "Incident %s skipped for downtime: missing detect_ts or recover_ts",
                    getattr(inc, "incident_id", "?"),
                )
                continue
            start = _ts(inc.detect_ts)
            end = _ts(inc.recover_ts)
            if end <= start:
                continue
            intervals.append((start, end))

    merged = _merge_intervals(intervals)
    total_dt_sec = sum((e - s).total_seconds() for s, e in merged)
    m.total_downtime_hr = round(total_dt_sec / 3600, 4)

    # Availability
    if horizon_sec > 0:
        m.availability_pct = round((1 - total_dt_sec / horizon_sec) * 100, 2)
    else:
        m.availability_pct = 100.0

    log.info(
        "Metrics [%s]: availability=%.2f%%, downtime=%.4fh, mttd=%.2fm, mttr=%.2fm, incidents=%d",
        policy_name,
        m.availability_pct,
        m.total_downtime_hr,
        m.mean_mttd_min,
        m.mean_mttr_min,
        m.incidents_total,
    )

    return m


def _merge_intervals(
    intervals: list[tuple[datetime, datetime]],
) -> list[tuple[datetime, datetime]]:
    """Merge overlapping time intervals."""
    if not intervals:
        return []
    sorted_iv = sorted(intervals, key=lambda x: x[0])
    merged = [sorted_iv[0]]
    for start, end in sorted_iv[1:]:
        if start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged
