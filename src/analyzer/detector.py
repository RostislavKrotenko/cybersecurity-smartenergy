"""Detector — rule-based engine: Event stream → Alerts.

For each rule in rules.yaml the detector scans the event stream and
fires an Alert when the rule conditions are met.  Rules are evaluated
independently; the detector does NOT import anything from the emulator.

Supported rule types
────────────────────
  brute_force         — N auth_failure events from same IP within window
  ddos                — N rate_exceeded events within window
  telemetry_spoofing  — value out-of-bounds or delta > threshold
  unauthorized_cmd    — cmd_exec where actor ∉ allowed_roles
  outage              — service_status down/degraded or db_error events
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any

from src.contracts.alert import Alert
from src.contracts.event import Event

log = logging.getLogger(__name__)

_SEV_WEIGHT = {"low": 0.2, "medium": 0.4, "high": 0.7, "critical": 1.0}


def _ts(iso: str) -> datetime:
    """Parse ISO-8601 timestamp to datetime (UTC)."""
    s = iso.replace("Z", "+00:00")
    return datetime.fromisoformat(s)


def _diff_sec(a: str, b: str) -> float:
    return (_ts(b) - _ts(a)).total_seconds()


# ═══════════════════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════════════════


def detect(
    events: list[Event],
    rules_cfg: dict[str, Any],
    policy_modifiers: dict[str, dict[str, float]] | None = None,
) -> list[Alert]:
    """Run all enabled rules against *events* and return raised Alerts.

    Parameters
    ──────────
    events
        Sorted list of Event objects (by timestamp).
    rules_cfg
        Parsed config/rules.yaml.
    policy_modifiers
        ``policy.modifiers[threat_type]`` dict of multipliers.  Can be
        None (= baseline / all multipliers 1.0).

    Returns
    ───────
    Sorted list of Alerts.
    """
    if not events:
        log.warning("No events to analyse — detector returns empty list")
        return []

    pm = policy_modifiers or {}
    alerts: list[Alert] = []
    alert_counter = 0

    for rule in rules_cfg.get("rules", []):
        if not rule.get("enabled", True):
            continue

        rule_id = rule["id"]
        match_event = rule.get("match", {}).get("event", "")
        threat = rule.get("threat_type", "unknown")

        # Apply policy multipliers to window and threshold
        mod = pm.get(threat, {})
        window = rule.get("window_sec", 60) * mod.get("window_multiplier", 1.0)
        threshold = max(1, round(rule.get("threshold", 1) * mod.get("threshold_multiplier", 1.0)))

        matched = [e for e in events if e.event == match_event]

        if rule_id.startswith("RULE-BF"):
            new_alerts = _detect_brute_force(matched, rule, window, threshold, alert_counter)
        elif rule_id.startswith("RULE-DDOS"):
            new_alerts = _detect_ddos(matched, rule, window, threshold, events, alert_counter)
        elif rule_id.startswith("RULE-SPOOF"):
            new_alerts = _detect_telemetry_spoof(matched, rule, window, threshold, alert_counter)
        elif rule_id.startswith("RULE-UCMD"):
            new_alerts = _detect_unauthorized_cmd(matched, rule, alert_counter)
        elif rule_id.startswith("RULE-OUT"):
            new_alerts = _detect_outage(matched, rule, window, threshold, events, alert_counter)
        else:
            log.debug("Unknown rule prefix for %s — skipped", rule_id)
            continue

        alert_counter += len(new_alerts)
        alerts.extend(new_alerts)

    alerts.sort(key=lambda a: a.timestamp)
    log.info("Detector raised %d alerts from %d events", len(alerts), len(events))
    return alerts


# ═══════════════════════════════════════════════════════════════════════════
#  Rule implementations
# ═══════════════════════════════════════════════════════════════════════════


def _detect_brute_force(
    auth_failures: list[Event],
    rule: dict,
    window: float,
    threshold: int,
    counter: int,
) -> list[Alert]:
    """RULE-BF-001 — N auth_failure from same IP within window seconds."""
    alerts: list[Alert] = []
    groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in auth_failures:
        key = (e.ip or "unknown", e.source)
        groups[key].append(e)

    for (ip, source), evts in groups.items():
        evts.sort(key=lambda e: e.timestamp)
        buf: list[Event] = []
        for e in evts:
            # Slide window: remove events outside window
            buf = [b for b in buf if _diff_sec(b.timestamp, e.timestamp) <= window]
            buf.append(e)
            if len(buf) >= threshold:
                counter += 1
                alerts.append(
                    Alert(
                        alert_id=f"ALR-{counter:04d}",
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        threat_type=rule["threat_type"],
                        severity=rule.get("severity", "high"),
                        confidence=rule.get("confidence", 0.85),
                        timestamp=buf[0].timestamp,
                        component=evts[0].component,
                        source=source,
                        description=(
                            f"Brute-force: {len(buf)} auth failures from {ip} "
                            f"to {source} within {window:.0f}s"
                        ),
                        event_count=len(buf),
                        event_ids=";".join(e.correlation_id or e.timestamp for e in buf),
                        response_hint=rule.get("response_hint", ""),
                    )
                )
                buf.clear()
                break  # one alert per group

    return alerts


def _detect_ddos(
    rate_events: list[Event],
    rule: dict,
    window: float,
    threshold: int,
    all_events: list[Event],
    counter: int,
) -> list[Alert]:
    """RULE-DDOS-001 — N rate_exceeded events within window."""
    alerts: list[Alert] = []
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in rate_events:
        groups[e.source].append(e)

    for source, evts in groups.items():
        evts.sort(key=lambda e: e.timestamp)
        buf: list[Event] = []
        for e in evts:
            buf = [b for b in buf if _diff_sec(b.timestamp, e.timestamp) <= window]
            buf.append(e)
            if len(buf) >= threshold:
                # Check for service degradation within 120s (sub-rule escalation)
                sev = rule.get("severity", "critical")
                svc_impact = [
                    s
                    for s in all_events
                    if s.event == "service_status"
                    and s.source == source
                    and s.key == "status"
                    and s.value in ("degraded", "down")
                    and 0 <= _diff_sec(buf[0].timestamp, s.timestamp) <= 120
                ]
                if svc_impact:
                    sev = "critical"

                counter += 1
                alerts.append(
                    Alert(
                        alert_id=f"ALR-{counter:04d}",
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        threat_type=rule["threat_type"],
                        severity=sev,
                        confidence=0.98 if svc_impact else rule.get("confidence", 0.90),
                        timestamp=buf[0].timestamp,
                        component=evts[0].component,
                        source=source,
                        description=(
                            f"DDoS flood: {len(buf)} rate_exceeded on {source} "
                            f"within {window:.0f}s" + (" + service impact" if svc_impact else "")
                        ),
                        event_count=len(buf),
                        event_ids=";".join(e.correlation_id or e.timestamp for e in buf),
                        response_hint=rule.get("response_hint", ""),
                    )
                )
                buf.clear()
                break

    return alerts


def _detect_telemetry_spoof(
    telem_events: list[Event],
    rule: dict,
    window: float,
    threshold: int,
    counter: int,
) -> list[Alert]:
    """RULE-SPOOF-001 — telemetry value out-of-bounds or large delta."""
    alerts: list[Alert] = []
    bounds = rule.get("bounds", {})
    deltas = rule.get("delta", {})

    groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in telem_events:
        groups[(e.source, e.key)].append(e)

    for (source, key), evts in groups.items():
        evts.sort(key=lambda e: e.timestamp)
        anomalies: list[Event] = []
        prev_val: float | None = None

        for e in evts:
            try:
                val = float(e.value)
            except (ValueError, TypeError):
                continue

            is_anomaly = False

            # Static bounds check
            b = bounds.get(key)
            if b and (val < b.get("min", float("-inf")) or val > b.get("max", float("inf"))):
                is_anomaly = True

            # Delta check
            d = deltas.get(key)
            if d is not None and prev_val is not None and abs(val - prev_val) > d:
                is_anomaly = True

            prev_val = val

            if is_anomaly:
                anomalies.append(e)

        # Sliding window: group anomalies
        if len(anomalies) >= threshold:
            buf: list[Event] = []
            for a in anomalies:
                buf = [b for b in buf if _diff_sec(b.timestamp, a.timestamp) <= window]
                buf.append(a)
                if len(buf) >= threshold:
                    sev = "high" if len(buf) >= 5 else rule.get("severity", "medium")
                    counter += 1
                    alerts.append(
                        Alert(
                            alert_id=f"ALR-{counter:04d}",
                            rule_id=rule["id"],
                            rule_name=rule["name"],
                            threat_type=rule["threat_type"],
                            severity=sev,
                            confidence=0.90 if len(buf) >= 5 else rule.get("confidence", 0.75),
                            timestamp=buf[0].timestamp,
                            component=anomalies[0].component,
                            source=source,
                            description=(
                                f"Telemetry anomaly: {len(buf)} out-of-range values "
                                f"for {key} on {source} within {window:.0f}s"
                            ),
                            event_count=len(buf),
                            event_ids=";".join(e.correlation_id or e.timestamp for e in buf),
                            response_hint=rule.get("response_hint", ""),
                        )
                    )
                    buf.clear()
                    break

    return alerts


def _detect_unauthorized_cmd(
    cmd_events: list[Event],
    rule: dict,
    counter: int,
) -> list[Alert]:
    """RULE-UCMD-001 — cmd_exec where actor ∉ allowed actors."""
    alerts: list[Alert] = []
    allowed = set(rule.get("match", {}).get("actor_not_in", []))
    # "actor_not_in" in rules.yaml means these actors ARE allowed
    # An event is unauthorized if actor is not in this set

    unauth: list[Event] = []
    for e in cmd_events:
        actor = e.actor.strip().lower()
        if not actor or actor not in {a.lower() for a in allowed}:
            unauth.append(e)

    if unauth:
        sev = "critical"
        counter += 1
        alerts.append(
            Alert(
                alert_id=f"ALR-{counter:04d}",
                rule_id=rule["id"],
                rule_name=rule["name"],
                threat_type=rule["threat_type"],
                severity=sev,
                confidence=0.99 if len(unauth) >= 3 else rule.get("confidence", 0.95),
                timestamp=unauth[0].timestamp,
                component=unauth[0].component,
                source=unauth[0].source,
                description=(
                    f"Unauthorized command: {len(unauth)} cmd_exec by "
                    f"non-allowed actor(s) on {unauth[0].source}"
                ),
                event_count=len(unauth),
                event_ids=";".join(e.correlation_id or e.timestamp for e in unauth),
                response_hint=rule.get("response_hint", ""),
            )
        )

    return alerts


def _detect_outage(
    svc_events: list[Event],
    rule: dict,
    window: float,
    threshold: int,
    all_events: list[Event],
    counter: int,
) -> list[Alert]:
    """RULE-OUT-001/002 — service down/degraded or db_error events."""
    alerts: list[Alert] = []
    target_values = set(rule.get("match", {}).get("values", []))

    # Filter events matching the rule's value conditions
    if target_values:
        matched = [e for e in svc_events if e.value in target_values]
    else:
        matched = svc_events

    groups: dict[str, list[Event]] = defaultdict(list)
    for e in matched:
        groups[e.source].append(e)

    for source, evts in groups.items():
        evts.sort(key=lambda e: e.timestamp)
        buf: list[Event] = []
        for e in evts:
            buf = [b for b in buf if _diff_sec(b.timestamp, e.timestamp) <= window]
            buf.append(e)
            if len(buf) >= threshold:
                # Check for severity override
                sev = rule.get("severity", "high")
                for ov in rule.get("severity_override", []):
                    if any(b.value == ov["value"] for b in buf):
                        sev = ov["severity"]
                        break

                counter += 1
                alerts.append(
                    Alert(
                        alert_id=f"ALR-{counter:04d}",
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        threat_type=rule["threat_type"],
                        severity=sev,
                        confidence=rule.get("confidence", 0.90),
                        timestamp=buf[0].timestamp,
                        component=evts[0].component,
                        source=source,
                        description=(
                            f"Outage: {len(buf)} {evts[0].event} events on "
                            f"{source} (values: {', '.join(e.value for e in buf)})"
                        ),
                        event_count=len(buf),
                        event_ids=";".join(e.correlation_id or e.timestamp for e in buf),
                        response_hint=rule.get("response_hint", ""),
                    )
                )
                buf.clear()
                break

    return alerts
