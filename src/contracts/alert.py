"""Модель оповіщення (Alert)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Alert:
    """Оповіщення, згенероване детектором при спрацюванні правила."""

    alert_id: str  # наприклад, "ALR-001"
    rule_id: str  # наприклад, "RULE-BF-001"
    rule_name: str
    threat_type: str  # допустимі значення: credential_attack, availability_attack, integrity_attack, outage
    severity: str  # допустимі значення: low, medium, high, critical
    confidence: float
    timestamp: str  # ISO-8601, час першої події
    component: str
    source: str
    description: str
    event_count: int  # кількість подій, що спрацювали за правилом
    event_ids: str  # список correlation_id або timestamp через крапку з комою
    response_hint: str = ""
