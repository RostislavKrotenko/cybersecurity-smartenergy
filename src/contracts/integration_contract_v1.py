"""Контракт інтеграції v1 і допоміжні функції валідації.

Модуль визначає канонічні правила payload для зовнішньої інтеграції:
- Event (вхід)
- Action (вихід)
- ActionAck (підтвердження виконання)
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from src.contracts.action import Action, ActionAck, ActionType
from src.contracts.event import Event
from src.shared.severity import SEV_ORDER
from src.shared.time_utils import parse_iso_ts

INTEGRATION_CONTRACT_VERSION = "v1.0.0"

EVENT_REQUIRED_FIELDS: tuple[str, ...] = (
    "timestamp",
    "source",
    "component",
    "event",
    "key",
    "value",
    "severity",
    "correlation_id",
)

ACTION_REQUIRED_FIELDS: tuple[str, ...] = (
    "action_id",
    "ts_utc",
    "action",
    "target_component",
    "correlation_id",
    "status",
)

ACTION_ACK_REQUIRED_FIELDS: tuple[str, ...] = (
    "action_id",
    "correlation_id",
    "target_component",
    "action",
    "applied_ts_utc",
    "result",
)

VALID_ACTION_VALUES = {item.value for item in ActionType}
VALID_SEVERITIES = set(SEV_ORDER.keys())
VALID_ACK_RESULTS = {"success", "failed"}
VALID_ACTION_STATUS = {"pending", "emitted", "applied", "failed", "planned"}


def _as_mapping(payload: Event | Action | ActionAck | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(payload, Event):
        return {
            "timestamp": payload.timestamp,
            "source": payload.source,
            "component": payload.component,
            "event": payload.event,
            "key": payload.key,
            "value": payload.value,
            "severity": payload.severity,
            "actor": payload.actor,
            "ip": payload.ip,
            "unit": payload.unit,
            "tags": payload.tags,
            "correlation_id": payload.correlation_id,
        }

    if isinstance(payload, Action):
        return {
            "action_id": payload.action_id,
            "ts_utc": payload.ts_utc,
            "action": payload.action,
            "target_component": payload.target_component,
            "target_id": payload.target_id,
            "params": payload.params,
            "reason": payload.reason,
            "correlation_id": payload.correlation_id,
            "status": payload.status,
        }

    if isinstance(payload, ActionAck):
        return {
            "action_id": payload.action_id,
            "correlation_id": payload.correlation_id,
            "target_component": payload.target_component,
            "action": payload.action,
            "applied_ts_utc": payload.applied_ts_utc,
            "result": payload.result,
            "error": payload.error,
            "state_event": payload.state_event,
        }

    return payload


def _validate_required_fields(
    data: Mapping[str, Any],
    required_fields: tuple[str, ...],
    payload_name: str,
) -> list[str]:
    errors: list[str] = []

    for field in required_fields:
        if field not in data:
            errors.append(f"{payload_name}.{field}: відсутнє обов'язкове поле")
            continue

        value = data.get(field)
        if isinstance(value, str) and not value.strip():
            errors.append(f"{payload_name}.{field}: не може бути порожнім")

    return errors


def validate_event_v1(payload: Event | Mapping[str, Any]) -> list[str]:
    """Валідовує Event payload відповідно до контракту інтеграції v1."""
    data = _as_mapping(payload)
    errors = _validate_required_fields(data, EVENT_REQUIRED_FIELDS, "Event")

    severity = str(data.get("severity", "")).lower()
    if severity and severity not in VALID_SEVERITIES:
        errors.append(f"Event.severity: непідтримуване значення '{severity}'")

    timestamp = data.get("timestamp", "")
    if isinstance(timestamp, str) and timestamp.strip():
        try:
            parse_iso_ts(timestamp)
        except ValueError:
            errors.append("Event.timestamp: некоректний формат ISO-8601")

    return errors


def validate_action_v1(payload: Action | Mapping[str, Any]) -> list[str]:
    """Валідовує Action payload відповідно до контракту інтеграції v1."""
    data = _as_mapping(payload)
    errors = _validate_required_fields(data, ACTION_REQUIRED_FIELDS, "Action")

    action_name = str(data.get("action", ""))
    if action_name and action_name not in VALID_ACTION_VALUES:
        errors.append(f"Action.action: непідтримуване значення '{action_name}'")

    status = str(data.get("status", ""))
    if status and status not in VALID_ACTION_STATUS:
        errors.append(f"Action.status: непідтримуване значення '{status}'")

    ts_utc = data.get("ts_utc", "")
    if isinstance(ts_utc, str) and ts_utc.strip():
        try:
            parse_iso_ts(ts_utc)
        except ValueError:
            errors.append("Action.ts_utc: некоректний формат ISO-8601")

    params = data.get("params", {})
    if not isinstance(params, Mapping):
        errors.append("Action.params: має бути об'єктом")

    return errors


def validate_action_ack_v1(payload: ActionAck | Mapping[str, Any]) -> list[str]:
    """Валідовує ActionAck payload відповідно до контракту інтеграції v1."""
    data = _as_mapping(payload)
    errors = _validate_required_fields(data, ACTION_ACK_REQUIRED_FIELDS, "ActionAck")

    result = str(data.get("result", "")).lower()
    if result and result not in VALID_ACK_RESULTS:
        errors.append(f"ActionAck.result: непідтримуване значення '{result}'")

    ts_utc = data.get("applied_ts_utc", "")
    if isinstance(ts_utc, str) and ts_utc.strip():
        try:
            parse_iso_ts(ts_utc)
        except ValueError:
            errors.append("ActionAck.applied_ts_utc: некоректний формат ISO-8601")

    return errors


def assert_valid_event_v1(payload: Event | Mapping[str, Any]) -> None:
    """Підіймає ValueError, якщо Event payload невалідний для контракту v1."""
    errors = validate_event_v1(payload)
    if errors:
        raise ValueError("; ".join(errors))


def assert_valid_action_v1(payload: Action | Mapping[str, Any]) -> None:
    """Підіймає ValueError, якщо Action payload невалідний для контракту v1."""
    errors = validate_action_v1(payload)
    if errors:
        raise ValueError("; ".join(errors))


def assert_valid_action_ack_v1(payload: ActionAck | Mapping[str, Any]) -> None:
    """Підіймає ValueError, якщо ActionAck payload невалідний для контракту v1."""
    errors = validate_action_ack_v1(payload)
    if errors:
        raise ValueError("; ".join(errors))
