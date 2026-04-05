"""Тести валідаторів контракту інтеграції v1."""

from __future__ import annotations

from src.contracts.action import Action, ActionAck
from src.contracts.event import Event
from src.contracts.integration_contract_v1 import (
    INTEGRATION_CONTRACT_VERSION,
    validate_action_ack_v1,
    validate_action_v1,
    validate_event_v1,
)


def test_contract_version_constant():
    assert INTEGRATION_CONTRACT_VERSION == "v1.0.0"


def test_validate_event_v1_accepts_valid_payload():
    event = Event(
        timestamp="2026-03-10T10:00:00Z",
        source="api-gw-01",
        component="api",
        event="auth_failure",
        key="username",
        value="operator",
        severity="high",
        correlation_id="COR-001",
    )

    assert validate_event_v1(event) == []


def test_validate_event_v1_reports_required_and_value_errors():
    errors = validate_event_v1(
        {
            "timestamp": "bad-ts",
            "source": "",
            "component": "api",
            "event": "auth_failure",
            "key": "username",
            "value": "operator",
            "severity": "fatal",
            "correlation_id": "",
        }
    )

    assert any("Event.timestamp: некоректний формат ISO-8601" in msg for msg in errors)
    assert any("Event.source: не може бути порожнім" in msg for msg in errors)
    assert any("Event.severity: непідтримуване значення" in msg for msg in errors)
    assert any("Event.correlation_id: не може бути порожнім" in msg for msg in errors)


def test_validate_action_v1_accepts_valid_payload():
    action = Action(
        action_id="ACT-123",
        ts_utc="2026-03-10T10:00:00Z",
        action="enable_rate_limit",
        target_component="gateway",
        correlation_id="INC-001",
        params={"rps": 50},
        status="emitted",
    )

    assert validate_action_v1(action) == []


def test_validate_action_v1_reports_invalid_values():
    errors = validate_action_v1(
        {
            "action_id": "ACT-123",
            "ts_utc": "bad-ts",
            "action": "unsupported_action",
            "target_component": "gateway",
            "correlation_id": "INC-1",
            "status": "unknown",
            "params": "not-object",
        }
    )

    assert any("Action.ts_utc: некоректний формат ISO-8601" in msg for msg in errors)
    assert any("Action.action: непідтримуване значення" in msg for msg in errors)
    assert any("Action.status: непідтримуване значення" in msg for msg in errors)
    assert any("Action.params: має бути об'єктом" in msg for msg in errors)


def test_validate_action_ack_v1_accepts_valid_payload():
    ack = ActionAck(
        action_id="ACT-123",
        correlation_id="INC-001",
        target_component="gateway",
        action="enable_rate_limit",
        applied_ts_utc="2026-03-10T10:00:05Z",
        result="success",
        state_event="rate_limit_enabled",
    )

    assert validate_action_ack_v1(ack) == []


def test_validate_action_ack_v1_reports_invalid_values():
    errors = validate_action_ack_v1(
        {
            "action_id": "ACT-123",
            "correlation_id": "",
            "target_component": "gateway",
            "action": "enable_rate_limit",
            "applied_ts_utc": "not-ts",
            "result": "ok",
        }
    )

    assert any("ActionAck.correlation_id: не може бути порожнім" in msg for msg in errors)
    assert any("ActionAck.applied_ts_utc: некоректний формат ISO-8601" in msg for msg in errors)
    assert any("ActionAck.result: непідтримуване значення" in msg for msg in errors)
