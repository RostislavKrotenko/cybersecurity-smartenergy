"""Розрахунок метрик кіберстійкості на основі інцидентів.

Downtime рахується як інтервал від ``detect_ts`` до ``recover_ts``. Це дорівнює
MTTR і не включає MTTD. У downtime входять лише інциденти з severity >= high,
а перетини інтервалів об'єднуються перед підсумовуванням.

Метрики обчислюються окремо для кожної політики. У порівняльному режимі всі
політики оцінюються на спільному наборі сценаріїв, тому пропущена атака не дає
штучні 100% доступності:
- availability_pct: частка горизонту аналізу без модельного high/critical простою.
- total_downtime_hr: сумарний downtime у годинах.
- mean_mttd_min: середній MTTD у хвилинах.
- mean_mttr_min: середній MTTR у хвилинах.
- incidents_total: кількість виявлених політикою інцидентів.
- detection_rate_pct: частка виявлених сценаріїв.

Усі timestamp у CSV/JSONL зберігаються в UTC. Відображення у локальному часовому
поясі виконується тільки на dashboard-рівні.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from src.analyzer.correlator import estimate_incident_timing
from src.contracts.incident import Incident
from src.shared.time_utils import parse_iso_ts as _ts

log = logging.getLogger(__name__)


RESULTS_CSV_COLUMNS = [
    "policy",
    "availability_pct",
    "total_downtime_hr",
    "mean_mttd_min",
    "mean_mttr_min",
    "incidents_total",
    "scenarios_total",
    "incidents_missed",
    "detection_rate_pct",
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
    scenarios_total: int = 0
    incidents_missed: int = 0
    detection_rate_pct: float = 0.0
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
            str(self.scenarios_total),
            str(self.incidents_missed),
            f"{self.detection_rate_pct:.2f}",
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


def compute(
    incidents: list[Incident],
    policy_name: str,
    horizon_sec: float,
    *,
    reference_incidents: list[Incident] | None = None,
    policy_modifiers: dict[str, dict[str, float]] | None = None,
) -> PolicyMetrics:
    """Обчислює метрики стійкості для однієї політики.

    Аргументи:
        incidents: Список інцидентів.
        policy_name: Назва політики.
        horizon_sec: Горизонт аналізу в секундах.
        reference_incidents: Спільний набір сценаріїв для всіх політик.
        policy_modifiers: Множники часу реакції вибраної політики.

    Повертає:
        PolicyMetrics з обчисленими значеннями.
    """
    m = PolicyMetrics(policy=policy_name)
    comparison_mode = reference_incidents is not None
    scenarios = _canonical_scenarios(
        reference_incidents if comparison_mode else incidents
    )
    m.scenarios_total = len(scenarios)
    detected_scenarios = _count_detected_scenarios(incidents, scenarios)
    m.incidents_missed = max(0, m.scenarios_total - detected_scenarios)
    if m.scenarios_total:
        m.detection_rate_pct = round(
            detected_scenarios / m.scenarios_total * 100,
            2,
        )

    if not incidents and not comparison_mode:
        log.info("Для політики '%s' немає інцидентів — доступність 100%%", policy_name)
        return m

    m.incidents_total = len(incidents)

    for inc in incidents:
        m.incidents_by_severity[inc.severity] = m.incidents_by_severity.get(inc.severity, 0) + 1
        m.incidents_by_threat[inc.threat_type] = m.incidents_by_threat.get(inc.threat_type, 0) + 1

    if comparison_mode and scenarios:
        timings = [
            estimate_incident_timing(
                scenario.threat_type,
                policy_modifiers,
            )
            for scenario in scenarios
        ]
        m.mean_mttd_min = round(
            sum(mttd for mttd, _ in timings) / len(timings) / 60,
            2,
        )
        m.mean_mttr_min = round(
            sum(mttr for _, mttr in timings) / len(timings) / 60,
            2,
        )
    elif incidents:
        m.mean_mttd_min = round(
            sum(i.mttd_sec for i in incidents) / len(incidents) / 60,
            2,
        )
        m.mean_mttr_min = round(
            sum(i.mttr_sec for i in incidents) / len(incidents) / 60,
            2,
        )

    high_sev = {"high", "critical"}
    intervals: list[tuple[datetime, datetime]] = []
    if comparison_mode:
        for scenario in scenarios:
            if scenario.severity not in high_sev:
                continue
            mttd_sec, mttr_sec = estimate_incident_timing(
                scenario.threat_type,
                policy_modifiers,
            )
            start = _ts(scenario.start_ts) + timedelta(seconds=mttd_sec)
            intervals.append((start, start + timedelta(seconds=mttr_sec)))
    else:
        for inc in incidents:
            if inc.severity in high_sev:
                if not inc.detect_ts or not inc.recover_ts:
                    log.warning(
                        "Інцидент %s пропущено для downtime: "
                        "немає detect_ts або recover_ts",
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


def _same_scenario(
    left: Incident,
    right: Incident,
    *,
    tolerance_seconds: float = 30.0,
) -> bool:
    """Перевіряє, чи два policy-інциденти описують один сценарій."""

    if (
        left.threat_type != right.threat_type
        or left.component != right.component
        or left.source != right.source
    ):
        return False
    return abs((_ts(left.start_ts) - _ts(right.start_ts)).total_seconds()) <= (
        tolerance_seconds
    )


def _canonical_scenarios(incidents: list[Incident]) -> list[Incident]:
    """Згортає результати різних політик до спільних сценаріїв."""

    scenarios: list[Incident] = []
    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    for incident in sorted(incidents, key=lambda item: _ts(item.start_ts)):
        match_index = next(
            (
                index
                for index, scenario in enumerate(scenarios)
                if _same_scenario(scenario, incident)
            ),
            None,
        )
        if match_index is None:
            scenarios.append(incident)
            continue
        current = scenarios[match_index]
        if severity_rank.get(incident.severity, 0) > severity_rank.get(
            current.severity,
            0,
        ):
            scenarios[match_index] = incident
    return scenarios


def _count_detected_scenarios(
    incidents: list[Incident],
    scenarios: list[Incident],
) -> int:
    """Підраховує унікальні сценарії, виявлені однією політикою."""

    return sum(
        1
        for scenario in scenarios
        if any(_same_scenario(scenario, incident) for incident in incidents)
    )


def _merge_intervals(
    intervals: list[tuple[datetime, datetime]],
) -> list[tuple[datetime, datetime]]:
    """Об'єднує часові інтервали, що перетинаються."""
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
