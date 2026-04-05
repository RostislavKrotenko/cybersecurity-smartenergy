"""Тести сумісності реалізацій із контрактами та hybrid-режиму."""

from __future__ import annotations

from pathlib import Path

from src.adapters.file_adapter import (
    FileActionFeedback,
    FileActionSink,
    FileActionSource,
    FileEventSink,
    FileEventSource,
    FileIncidentSource,
    FileMetricsSource,
    FileStateSource,
    SimulatedStateProvider,
)
from src.contracts.action import Action
from src.contracts.event import Event
from src.contracts.interfaces import (
    ActionExecutor,
    ActionFeedback,
    ActionResult,
    ActionSink,
    ActionSource,
    ActionStatus,
    EventSink,
    EventSource,
    IncidentSource,
    MetricsSource,
    StateProvider,
)
from src.emulator import hybrid
from src.emulator.world import WorldState


def test_file_adapters_are_contract_compatible(tmp_path: Path):
    es = FileEventSource(str(tmp_path / "events.jsonl"))
    ek = FileEventSink(str(tmp_path / "events_out.jsonl"))
    ak = FileActionSink(str(tmp_path / "actions.jsonl"))
    af = FileActionFeedback(str(tmp_path / "acks.jsonl"))

    inc = FileIncidentSource(str(tmp_path / "inc.csv"))
    act = FileActionSource(str(tmp_path / "act.csv"))
    met = FileMetricsSource(str(tmp_path / "res.csv"))
    st = FileStateSource(str(tmp_path / "state.csv"))
    sim = SimulatedStateProvider()

    assert isinstance(es, EventSource)
    assert isinstance(ek, EventSink)
    assert isinstance(ak, ActionSink)
    assert isinstance(af, ActionFeedback)

    assert isinstance(inc, IncidentSource)
    assert isinstance(act, ActionSource)
    assert isinstance(met, MetricsSource)
    assert isinstance(st, StateProvider)
    assert isinstance(sim, StateProvider)


def _make_action(action: str = "enable_rate_limit") -> Action:
    return Action(
        ts_utc="2026-03-05T10:00:00Z",
        action=action,
        target_component="gateway",
        target_id="api-gw-01",
        params={"rps": 20},
        reason="test",
        correlation_id="INC-001",
    )


class _FakeExecutor(ActionExecutor):
    def __init__(self, *, supports: bool = True, success: bool = True, with_events: bool = False):
        self._supports = supports
        self._success = success
        self._with_events = with_events
        self.executed: list[str] = []

    def execute(self, action: Action) -> ActionResult:
        self.executed.append(action.action)
        state_events = []
        if self._with_events:
            state_events = [
                Event(
                    timestamp="2026-03-05T10:00:01Z",
                    source="executor",
                    component=action.target_component,
                    event="executor_applied",
                    key="action",
                    value=action.action,
                    severity="low",
                    correlation_id=action.correlation_id,
                )
            ]
        return ActionResult(
            success=self._success,
            action_id=action.action_id,
            status=ActionStatus.APPLIED if self._success else ActionStatus.FAILED,
            state_events=state_events,
            error="boom" if not self._success else "",
        )

    def supports_action(self, action_type: str) -> bool:
        return self._supports

    def get_component_status(self, component_id: str) -> dict[str, str]:
        return {"component_id": component_id, "status": "ok"}


def test_apply_action_hybrid_simulation_only():
    state = WorldState()
    act = _make_action("enable_rate_limit")

    events = hybrid.apply_action_hybrid(state, act, executor=None)

    assert len(events) >= 1
    assert any(e.event == "rate_limit_enabled" for e in events)


def test_apply_action_hybrid_uses_real_events_when_available():
    state = WorldState()
    act = _make_action("enable_rate_limit")
    ex = _FakeExecutor(supports=True, success=True, with_events=True)

    events = hybrid.apply_action_hybrid(state, act, executor=ex)

    assert ex.executed == ["enable_rate_limit"]
    assert len(events) == 1
    assert events[0].event == "executor_applied"


def test_apply_action_hybrid_falls_back_to_simulation_on_failure_or_unsupported():
    state = WorldState()
    act = _make_action("enable_rate_limit")

    unsupported = _FakeExecutor(supports=False, success=True)
    events_unsup = hybrid.apply_action_hybrid(state, act, executor=unsupported)
    assert any(e.event == "rate_limit_enabled" for e in events_unsup)

    failed = _FakeExecutor(supports=True, success=False)
    events_failed = hybrid.apply_action_hybrid(state, act, executor=failed)
    assert any(e.event == "rate_limit_enabled" for e in events_failed)


def test_create_hybrid_executor_respects_mode_and_missing_backends(monkeypatch):
    monkeypatch.setattr(hybrid, "EXECUTION_MODE", "simulated")
    assert hybrid.create_hybrid_executor() is None

    monkeypatch.setattr(hybrid, "EXECUTION_MODE", "real")
    # Repository has no src.adapters.real_executors -> expect None.
    assert hybrid.create_hybrid_executor() is None
