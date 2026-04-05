"""Тести режимів інтеграції аналізатора (dry-run/shadow/active)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.analyzer import pipeline as analyzer_pipeline
from src.contracts.action import Action
from src.contracts.event import Event
from src.contracts.interfaces import ActionSink, ActionStatus, EventSource
from tests.conftest import make_incident


class _FakeEventSource(EventSource):
    def __init__(self, events: list[Event]):
        self._events = events
        self.closed = False

    def read_batch(self, limit: int = 10000) -> list[Event]:
        return self._events[:limit]

    def read_stream(self, poll_interval_sec: float = 1.0):
        del poll_interval_sec
        yield self._events

    def get_offset(self) -> int:
        return 0

    def seek(self, offset: Any) -> None:
        del offset

    def close(self) -> None:
        self.closed = True


class _FakeActionSink(ActionSink):
    def __init__(self):
        self.calls = 0
        self.last_actions: list[Action] = []

    def emit_batch(self, actions: list[Action]) -> list[str]:
        self.calls += 1
        self.last_actions = actions
        return [a.action_id for a in actions]

    def emit(self, action: Action):
        return action.action_id

    def get_status(self, action_id: str) -> ActionStatus:
        del action_id
        return ActionStatus.EMITTED

    def close(self) -> None:
        return None


def _patch_pipeline(monkeypatch):
    monkeypatch.setattr(analyzer_pipeline, "load_yaml", lambda *_: {"rules": []})
    monkeypatch.setattr(analyzer_pipeline, "load_policies", lambda *_: {})
    monkeypatch.setattr(analyzer_pipeline, "list_policy_names", lambda *_: ["baseline"])
    monkeypatch.setattr(analyzer_pipeline, "get_modifiers", lambda *_: {})
    monkeypatch.setattr(analyzer_pipeline, "detect", lambda *_, **__: ["alert"])
    monkeypatch.setattr(
        analyzer_pipeline,
        "correlate",
        lambda *_, **__: [make_incident(incident_id="INC-100", policy="baseline")],
    )
    monkeypatch.setattr(analyzer_pipeline, "compute", lambda *_, **__: object())
    monkeypatch.setattr(analyzer_pipeline, "rank_controls", lambda *_, **__: [])
    monkeypatch.setattr(analyzer_pipeline, "write_results_csv", lambda *_, **__: None)
    monkeypatch.setattr(analyzer_pipeline, "write_incidents_csv", lambda *_, **__: None)
    monkeypatch.setattr(analyzer_pipeline, "write_report_txt", lambda *_, **__: None)
    monkeypatch.setattr(analyzer_pipeline, "write_report_html", lambda *_, **__: None)
    monkeypatch.setattr(analyzer_pipeline, "write_plots", lambda *_, **__: None)
    monkeypatch.setattr(
        analyzer_pipeline,
        "decide",
        lambda *_, **__: [
            Action(
                action_id="ACT-777",
                ts_utc="2026-03-10T10:00:00Z",
                action="enable_rate_limit",
                target_component="gateway",
                params={"rps": 50},
                correlation_id="INC-100",
                status="emitted",
            )
        ],
    )


def _sample_events() -> list[Event]:
    return [
        Event(
            timestamp="2026-03-10T10:00:00Z",
            source="api-gw-01",
            component="api",
            event="auth_failure",
            key="username",
            value="operator",
            severity="high",
            correlation_id="COR-001",
        )
    ]


def test_run_pipeline_with_adapters_dry_run_writes_plan(monkeypatch, tmp_path: Path):
    _patch_pipeline(monkeypatch)

    source = _FakeEventSource(_sample_events())
    sink = _FakeActionSink()

    analyzer_pipeline.run_pipeline_with_adapters(
        event_source=source,
        action_sink=sink,
        out_dir=str(tmp_path),
        integration_mode="dry-run",
    )

    assert sink.calls == 0
    assert (tmp_path / "actions_dry_run.csv").exists()


def test_run_pipeline_with_adapters_shadow_writes_shadow_plan(monkeypatch, tmp_path: Path):
    _patch_pipeline(monkeypatch)

    source = _FakeEventSource(_sample_events())
    sink = _FakeActionSink()

    analyzer_pipeline.run_pipeline_with_adapters(
        event_source=source,
        action_sink=sink,
        out_dir=str(tmp_path),
        integration_mode="shadow",
    )

    assert sink.calls == 0
    assert (tmp_path / "actions_shadow.csv").exists()


def test_run_pipeline_with_adapters_active_emits_with_idempotency(monkeypatch, tmp_path: Path):
    _patch_pipeline(monkeypatch)

    source = _FakeEventSource(_sample_events())
    sink = _FakeActionSink()

    analyzer_pipeline.run_pipeline_with_adapters(
        event_source=source,
        action_sink=sink,
        out_dir=str(tmp_path),
        integration_mode="active",
    )

    assert sink.calls == 1
    assert sink.last_actions[0].params.get("idempotency_key") == "ACT-777"
