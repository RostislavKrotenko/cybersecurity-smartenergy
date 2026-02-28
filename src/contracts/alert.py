"""Модель оповіщення (Alert)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Alert:
    """Оповіщення, згенероване детектором при спрацюванні правила."""

    alert_id: str  # e.g. "ALR-001"
    rule_id: str  # e.g. "RULE-BF-001"
    rule_name: str
    threat_type: str  # credential_attack | availability_attack | integrity_attack | outage
    severity: str  # low | medium | high | critical
    confidence: float
    timestamp: str  # ISO-8601 — first event ts
    component: str
    source: str
    description: str
    event_count: int  # how many events matched
    event_ids: str  # semicolon-separated list of correlation_ids or timestamps
    response_hint: str = ""
