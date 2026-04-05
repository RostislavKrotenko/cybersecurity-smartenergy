"""Тести допоміжних компонентів надійності інтеграції."""

from __future__ import annotations

import pytest

from src.contracts.action import Action, ActionAck
from src.contracts.interfaces import ActionSink, ActionStatus
from src.shared.reliability import (
    AckDeduplicator,
    IntegrationMode,
    ReliabilityPolicy,
    RetryPolicy,
    TimeoutPolicy,
    emit_actions_with_retry,
    ensure_action_idempotency_key,
    parse_integration_mode,
)


class _FlakyActionSink(ActionSink):
    def __init__(self, failures_before_success: int = 0):
        self.failures_before_success = failures_before_success
        self.calls = 0

    def emit_batch(self, actions: list[Action]) -> list[str]:
        self.calls += 1
        if self.calls <= self.failures_before_success:
            raise RuntimeError("temporary failure")
        return [a.action_id for a in actions]

    def emit(self, action: Action) -> str:
        return action.action_id

    def get_status(self, action_id: str) -> ActionStatus:
        return ActionStatus.EMITTED

    def close(self):
        return None


def _make_action() -> Action:
    return Action(
        action_id="ACT-001",
        ts_utc="2026-03-10T10:00:00Z",
        action="enable_rate_limit",
        target_component="gateway",
        params={"rps": 50},
        correlation_id="INC-001",
    )


def test_parse_integration_mode_valid_and_invalid():
    assert parse_integration_mode("dry-run") == IntegrationMode.DRY_RUN
    assert parse_integration_mode("shadow") == IntegrationMode.SHADOW
    assert parse_integration_mode("active") == IntegrationMode.ACTIVE

    with pytest.raises(ValueError):
        parse_integration_mode("unknown")


def test_ensure_action_idempotency_key_is_stable():
    action = _make_action()

    first = ensure_action_idempotency_key(action)
    second = ensure_action_idempotency_key(action)

    assert first == "ACT-001"
    assert second == first
    assert action.params["idempotency_key"] == "ACT-001"


def test_emit_actions_with_retry_retries_then_succeeds():
    action = _make_action()
    sink = _FlakyActionSink(failures_before_success=1)
    policy = ReliabilityPolicy(
        retry=RetryPolicy(max_attempts=3, initial_backoff_sec=0.0),
        timeout=TimeoutPolicy(emit_batch_timeout_sec=3.0),
    )

    ids = emit_actions_with_retry(sink, [action], policy=policy)

    assert ids == ["ACT-001"]
    assert sink.calls == 2
    assert action.params["idempotency_key"] == "ACT-001"


def test_emit_actions_with_retry_raises_after_max_attempts():
    action = _make_action()
    sink = _FlakyActionSink(failures_before_success=5)
    policy = ReliabilityPolicy(
        retry=RetryPolicy(max_attempts=2, initial_backoff_sec=0.0),
        timeout=TimeoutPolicy(emit_batch_timeout_sec=3.0),
    )

    with pytest.raises(RuntimeError):
        emit_actions_with_retry(sink, [action], policy=policy)

    assert sink.calls == 2


def test_ack_deduplicator_filters_duplicates():
    ack = ActionAck(
        action_id="ACT-001",
        correlation_id="INC-001",
        target_component="gateway",
        action="enable_rate_limit",
        applied_ts_utc="2026-03-10T10:00:05Z",
        result="success",
        state_event="rate_limit_enabled",
    )
    ack_dup = ActionAck(
        action_id="ACT-001",
        correlation_id="INC-001",
        target_component="gateway",
        action="enable_rate_limit",
        applied_ts_utc="2026-03-10T10:00:05Z",
        result="success",
        state_event="rate_limit_enabled",
    )

    dedup = AckDeduplicator(max_entries=10)
    only_new = dedup.filter_new([ack, ack_dup])

    assert len(only_new) == 1
    assert only_new[0].action_id == "ACT-001"
