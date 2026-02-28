"""Shared fixtures for SmartEnergy Cyber-Resilience Analyzer tests."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from src.contracts.alert import Alert
from src.contracts.event import Event
from src.contracts.incident import Incident

# ── Helper: create Event with sensible defaults ─────────────────────────


def make_event(
    *,
    timestamp: str = "2026-02-26T10:00:00Z",
    source: str = "api-gw-01",
    component: str = "api",
    event: str = "raw_log",
    key: str = "message",
    value: str = "",
    severity: str = "low",
    actor: str = "",
    ip: str = "",
    unit: str = "",
    tags: str = "",
    correlation_id: str = "",
) -> Event:
    return Event(
        timestamp=timestamp,
        source=source,
        component=component,
        event=event,
        key=key,
        value=value,
        severity=severity,
        actor=actor,
        ip=ip,
        unit=unit,
        tags=tags,
        correlation_id=correlation_id,
    )


def make_alert(
    *,
    alert_id: str = "ALR-0001",
    rule_id: str = "RULE-BF-001",
    rule_name: str = "Brute-Force Authentication",
    threat_type: str = "credential_attack",
    severity: str = "high",
    confidence: float = 0.85,
    timestamp: str = "2026-02-26T10:00:00Z",
    component: str = "api",
    source: str = "api-gw-01",
    description: str = "test alert",
    event_count: int = 5,
    event_ids: str = "COR-001",
    response_hint: str = "block_ip",
) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        rule_name=rule_name,
        threat_type=threat_type,
        severity=severity,
        confidence=confidence,
        timestamp=timestamp,
        component=component,
        source=source,
        description=description,
        event_count=event_count,
        event_ids=event_ids,
        response_hint=response_hint,
    )


def make_incident(
    *,
    incident_id: str = "INC-001",
    policy: str = "baseline",
    threat_type: str = "credential_attack",
    severity: str = "high",
    component: str = "api",
    event_count: int = 5,
    start_ts: str = "2026-02-26T10:00:00Z",
    detect_ts: str = "2026-02-26T10:00:30Z",
    recover_ts: str = "2026-02-26T10:02:30Z",
    mttd_sec: float = 30.0,
    mttr_sec: float = 120.0,
    impact_score: float = 0.6,
    description: str = "test incident",
    response_action: str = "block_ip",
) -> Incident:
    return Incident(
        incident_id=incident_id,
        policy=policy,
        threat_type=threat_type,
        severity=severity,
        component=component,
        event_count=event_count,
        start_ts=start_ts,
        detect_ts=detect_ts,
        recover_ts=recover_ts,
        mttd_sec=mttd_sec,
        mttr_sec=mttr_sec,
        impact_score=impact_score,
        description=description,
        response_action=response_action,
    )


# ── Timestamp helpers ────────────────────────────────────────────────────


def ts_offset(base: str = "2026-02-26T10:00:00Z", seconds: int = 0) -> str:
    """Return an ISO-8601 timestamp offset from *base* by *seconds*."""
    dt = datetime.fromisoformat(base.replace("Z", "+00:00"))
    dt += timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Rules config fixtures ───────────────────────────────────────────────


@pytest.fixture
def brute_force_rule() -> dict:
    """Minimal brute-force rule config matching rules.yaml RULE-BF-001."""
    return {
        "rules": [
            {
                "id": "RULE-BF-001",
                "name": "Brute-Force Authentication",
                "threat_type": "credential_attack",
                "enabled": True,
                "match": {"event": "auth_failure", "group_by": ["ip", "source"]},
                "window_sec": 60,
                "threshold": 5,
                "severity": "high",
                "confidence": 0.85,
                "response_hint": "block_ip",
            }
        ]
    }


@pytest.fixture
def ddos_rule() -> dict:
    """Minimal DDoS rule config."""
    return {
        "rules": [
            {
                "id": "RULE-DDOS-001",
                "name": "DDoS / API Rate Flood",
                "threat_type": "availability_attack",
                "enabled": True,
                "match": {"event": "rate_exceeded", "group_by": ["source"]},
                "window_sec": 30,
                "threshold": 10,
                "severity": "critical",
                "confidence": 0.90,
                "response_hint": "rate_limit_ip_range",
            }
        ]
    }


@pytest.fixture
def spoof_rule() -> dict:
    """Minimal telemetry spoof rule config."""
    return {
        "rules": [
            {
                "id": "RULE-SPOOF-001",
                "name": "Telemetry Value Anomaly",
                "threat_type": "integrity_attack",
                "enabled": True,
                "match": {"event": "telemetry_read", "group_by": ["source", "key"]},
                "bounds": {
                    "voltage": {"min": 180.0, "max": 280.0},
                    "power_kw": {"min": -10.0, "max": 100.0},
                },
                "delta": {"voltage": 50.0, "power_kw": 30.0},
                "window_sec": 60,
                "threshold": 3,
                "severity": "medium",
                "confidence": 0.75,
                "response_hint": "flag_for_review",
            }
        ]
    }


@pytest.fixture
def unauthorized_cmd_rule() -> dict:
    """Minimal unauthorized cmd rule config."""
    return {
        "rules": [
            {
                "id": "RULE-UCMD-001",
                "name": "Unauthorized Command Execution",
                "threat_type": "integrity_attack",
                "enabled": True,
                "match": {
                    "event": "cmd_exec",
                    "actor_not_in": ["operator", "admin"],
                },
                "window_sec": 120,
                "threshold": 1,
                "severity": "critical",
                "confidence": 0.95,
                "response_hint": "block_actor_and_alert",
            }
        ]
    }


@pytest.fixture
def outage_rule() -> dict:
    """Minimal outage rule config."""
    return {
        "rules": [
            {
                "id": "RULE-OUT-001",
                "name": "Service Outage Detection",
                "threat_type": "outage",
                "enabled": True,
                "match": {
                    "event": "service_status",
                    "key": "status",
                    "values": ["degraded", "down"],
                    "group_by": ["source"],
                },
                "window_sec": 60,
                "threshold": 1,
                "severity": "high",
                "confidence": 0.90,
                "severity_override": [{"value": "down", "severity": "critical"}],
                "response_hint": "notify_oncall",
            }
        ]
    }
