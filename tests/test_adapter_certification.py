"""Базові сертифікаційні тести адаптерів.

Будь-який майбутній адаптер має пройти той самий поведінковий контракт,
який перевіряється цим набором.
"""

from __future__ import annotations

from pathlib import Path

from src.adapters.file_adapter import (
    FileActionFeedback,
    FileActionSink,
    FileEventSource,
    SimulatedStateProvider,
)
from src.contracts.action import Action, ActionAck
from src.contracts.event import Event


def _event_json_line(correlation_id: str = "COR-001") -> str:
    return (
        '{"timestamp":"2026-03-10T10:00:00Z","source":"api-gw-01","component":"api",'
        '"event":"auth_failure","key":"username","value":"operator","severity":"high",'
        f'"correlation_id":"{correlation_id}"}}'
    )


def _make_action(action_id: str) -> Action:
    return Action(
        action_id=action_id,
        ts_utc="2026-03-10T10:00:00Z",
        action="enable_rate_limit",
        target_component="gateway",
        params={"rps": 50},
        correlation_id="INC-001",
    )


def test_event_source_certification_file_adapter(tmp_path: Path):
    events_path = tmp_path / "events.jsonl"
    events_path.write_text(_event_json_line() + "\n", encoding="utf-8")

    source = FileEventSource(str(events_path))

    batch = source.read_batch(limit=100)
    assert len(batch) == 1
    assert isinstance(batch[0], Event)

    stream = source.read_stream(poll_interval_sec=0.0)
    streamed = next(stream)
    assert len(streamed) == 1
    assert source.get_offset() > 0

    source.seek(0)
    assert source.get_offset() == 0


def test_action_sink_certification_file_adapter(tmp_path: Path):
    sink = FileActionSink(str(tmp_path / "actions.jsonl"))

    actions = [_make_action("ACT-001"), _make_action("ACT-002")]
    ids = sink.emit_batch(actions)

    assert ids == ["ACT-001", "ACT-002"]
    assert sink.get_status("ACT-001").value == "emitted"
    sink.close()


def test_action_feedback_certification_file_adapter(tmp_path: Path):
    applied_path = tmp_path / "actions_applied.jsonl"
    ack = ActionAck(
        action_id="ACT-001",
        correlation_id="INC-001",
        target_component="gateway",
        action="enable_rate_limit",
        applied_ts_utc="2026-03-10T10:00:05Z",
        result="success",
        state_event="rate_limit_enabled",
    )
    applied_path.write_text(ack.to_json() + "\n", encoding="utf-8")

    feedback = FileActionFeedback(str(applied_path))

    acks, offset = feedback.read_acks()
    assert len(acks) == 1
    assert acks[0].action_id == "ACT-001"

    # Second read with same offset must return no new ACKs.
    second, second_offset = feedback.read_acks(since=offset)
    assert second == []
    assert second_offset == offset


def test_state_provider_certification_simulated_provider():
    provider = SimulatedStateProvider()

    provider.set_component_status("gateway", "healthy")
    provider.block_actor("attacker")
    provider.isolate_component("api")

    component = provider.get_component_state("gateway")
    assert component is not None
    assert component.status == "healthy"
    assert provider.is_actor_blocked("attacker") is True
    assert provider.is_component_isolated("api") is True
