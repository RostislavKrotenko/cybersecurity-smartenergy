"""Correlator — group Alerts into Incidents.

Grouping strategy (priority order):
  1. By ``correlation_id`` — if the emulator tagged events with COR-* IDs,
     alerts referencing the same correlation_id are grouped.
  2. By time window + component + threat_type — alerts within a configurable
     window (default 120 s) that share the same component and threat_type
     are merged into one incident.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta

from src.contracts.alert import Alert
from src.contracts.incident import Incident

log = logging.getLogger(__name__)

_DEFAULT_MERGE_WINDOW_SEC = 120
_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _ts(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def _max_sev(*sevs: str) -> str:
    return max(sevs, key=lambda s: _SEV_ORDER.get(s, 0))


def _extract_cor_ids(event_ids_str: str) -> set[str]:
    """Extract COR-* prefixed correlation IDs from semicolon-joined string."""
    return {t.strip() for t in event_ids_str.split(";") if t.strip().startswith("COR-")}


def correlate(
    alerts: list[Alert],
    policy_name: str,
    policy_modifiers: dict[str, dict[str, float]] | None = None,
    merge_window_sec: float = _DEFAULT_MERGE_WINDOW_SEC,
) -> list[Incident]:
    """Group alerts into incidents.

    Parameters
    ──────────
    alerts           — sorted list of Alerts
    policy_name      — e.g. "baseline"
    policy_modifiers — per-threat_type multipliers (mttd, mttr, impact)
    merge_window_sec — time window for grouping alerts without correlation_id

    Returns
    ───────
    Sorted list of Incidents with computed MTTD / MTTR / impact_score.
    """
    if not alerts:
        return []

    pm = policy_modifiers or {}

    # ── Phase 1: group by correlation ID ──────────────────────────────
    cor_groups: dict[str, list[Alert]] = defaultdict(list)
    no_cor: list[Alert] = []

    for a in alerts:
        cids = _extract_cor_ids(a.event_ids)
        if cids:
            # Use the first COR-* ID as group key
            cor_groups[sorted(cids)[0]].append(a)
        else:
            no_cor.append(a)

    # ── Phase 2: group remaining by time + component + threat_type ────
    time_groups: dict[str, list[Alert]] = {}
    for a in no_cor:
        placed = False
        group_key_prefix = f"{a.component}|{a.threat_type}"
        for gk, grp in time_groups.items():
            if gk.startswith(group_key_prefix):
                last_ts = max(_ts(x.timestamp) for x in grp)
                if abs((_ts(a.timestamp) - last_ts).total_seconds()) <= merge_window_sec:
                    grp.append(a)
                    placed = True
                    break
        if not placed:
            gk = f"{group_key_prefix}|{a.alert_id}"
            time_groups[gk] = [a]

    # Merge all groups
    all_groups: list[list[Alert]] = list(cor_groups.values()) + list(time_groups.values())

    # ── Phase 3: build Incidents ──────────────────────────────────────
    incidents: list[Incident] = []
    for idx, group in enumerate(all_groups, 1):
        group.sort(key=lambda a: a.timestamp)
        inc = _build_incident(group, idx, policy_name, pm)
        incidents.append(inc)

    incidents.sort(key=lambda i: i.start_ts)
    log.info("Correlator produced %d incidents from %d alerts (policy=%s)",
             len(incidents), len(alerts), policy_name)
    return incidents


# ═══════════════════════════════════════════════════════════════════════════

# Base timing constants (seconds) per threat_type — these represent
# the "baseline" detection and recovery times before policy multipliers.
_BASE_TIMING: dict[str, dict[str, float]] = {
    "credential_attack":   {"mttd": 30.0,  "mttr": 120.0},
    "availability_attack": {"mttd": 15.0,  "mttr": 180.0},
    "integrity_attack":    {"mttd": 60.0,  "mttr": 240.0},
    "outage":              {"mttd": 10.0,  "mttr": 300.0},
}

_SEV_IMPACT = {"low": 0.2, "medium": 0.4, "high": 0.7, "critical": 1.0}


def _build_incident(
    group: list[Alert],
    idx: int,
    policy: str,
    pm: dict[str, dict[str, float]],
) -> Incident:
    """Build a single Incident from a group of correlated alerts.

    Timing formulas
    ───────────────
      base_mttd / base_mttr — from _BASE_TIMING dict above
      mttd = base_mttd × mttd_multiplier      (policy-dependent)
      mttr = base_mttr × mttr_multiplier       (policy-dependent)
      detect_ts  = start_ts + mttd
      recover_ts = detect_ts + mttr
      impact_score = severity_weight × avg_confidence × impact_multiplier
    """
    threat = group[0].threat_type
    bases = _BASE_TIMING.get(threat, {"mttd": 30.0, "mttr": 120.0})
    mod = pm.get(threat, {})

    mttd = bases["mttd"] * mod.get("mttd_multiplier", 1.0)
    mttr = bases["mttr"] * mod.get("mttr_multiplier", 1.0)

    start_ts = group[0].timestamp
    start_dt = _ts(start_ts)
    detect_dt = start_dt + timedelta(seconds=mttd)
    recover_dt = detect_dt + timedelta(seconds=mttr)

    sev = group[0].severity
    for a in group[1:]:
        sev = _max_sev(sev, a.severity)

    avg_conf = sum(a.confidence for a in group) / len(group)
    impact_mult = mod.get("impact_multiplier", 1.0)
    impact_score = round(
        _SEV_IMPACT.get(sev, 0.5) * avg_conf * impact_mult, 4
    )
    impact_score = min(impact_score, 1.0)

    components = sorted({a.component for a in group})
    total_events = sum(a.event_count for a in group)

    desc_parts = sorted({a.description for a in group})
    response_parts = sorted({a.response_hint for a in group if a.response_hint})

    return Incident(
        incident_id=f"INC-{idx:03d}",
        policy=policy,
        threat_type=threat,
        severity=sev,
        component=";".join(components),
        event_count=total_events,
        start_ts=start_ts,
        detect_ts=detect_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        recover_ts=recover_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        mttd_sec=round(mttd, 2),
        mttr_sec=round(mttr, 2),
        impact_score=impact_score,
        description=" | ".join(desc_parts),
        response_action="; ".join(response_parts) if response_parts else "notify",
    )
