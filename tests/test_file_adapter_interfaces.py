"""Додаткові тести file-based адаптерів і їх інтерфейсних контрактів."""

from __future__ import annotations

import csv
import json
import time
from pathlib import Path

from src.adapters.file_adapter import (
    FileActionSink,
    FileActionSource,
    FileIncidentSource,
    FileMetricsSource,
    FileStateSource,
    SimulatedStateProvider,
)
from src.contracts.action import Action
from src.contracts.interfaces import ActionStatus
from src.emulator.world import WorldState


def _mk_action(action_id: str, action: str, status: str = "pending") -> Action:
    return Action(
        action_id=action_id,
        ts_utc="2026-03-01T10:00:00Z",
        action=action,
        target_component="api",
        params={"rps": 50},
        reason="test",
        correlation_id="INC-0001",
        status=status,
    )


def test_file_action_sink_tracks_status_and_writes_csv_summary(tmp_path: Path):
    out_jsonl = tmp_path / "actions.jsonl"
    out_csv = tmp_path / "actions.csv"

    sink = FileActionSink(str(out_jsonl), csv_path=str(out_csv))

    a1 = _mk_action("ACT-0001", "enable_rate_limit")
    a2 = _mk_action("ACT-0002", "isolate_component")

    emitted_ids = sink.emit_batch([a1, a2])
    assert emitted_ids == ["ACT-0001", "ACT-0002"]
    assert sink.get_status("ACT-0001") == ActionStatus.EMITTED
    assert sink.get_status("ACT-missing") == ActionStatus.PENDING

    sink.update_status("ACT-0001", ActionStatus.APPLIED)
    assert sink.get_status("ACT-0001") == ActionStatus.APPLIED

    single = _mk_action("ACT-0003", "block_actor")
    assert sink.emit(single) == "ACT-0003"
    assert len(sink.get_all_actions()) == 3

    sink.close()
    assert out_jsonl.exists()
    assert out_csv.exists()
    csv_text = out_csv.read_text(encoding="utf-8")
    assert "ACT-0001" in csv_text
    assert "ACT-0003" in csv_text


def test_simulated_state_provider_supports_world_and_manual_modes():
    world = WorldState()
    world.gateway.rate_limit_enabled = True
    world.gateway.rate_limit_rps = 120
    world.gateway.rate_limit_burst = 240
    world.api.status = "isolated"
    world.auth.blocked_actors["intruder"] = time.monotonic() + 120
    world.network.latency_ms = 250
    world.network.drop_rate = 0.2

    provider = SimulatedStateProvider(world)

    gw = provider.get_component_state("gateway")
    assert gw is not None
    assert gw.status == "rate_limited"
    assert gw.details["rps"] == 120

    net = provider.get_component_state("network")
    assert net is not None
    assert net.status == "degraded"

    assert provider.is_actor_blocked("intruder") is True
    assert provider.is_component_isolated("api") is True
    assert len(provider.get_all_components()) == 4

    manual = SimulatedStateProvider()
    manual.set_component_status("collector", "healthy")
    manual.block_actor("bot")
    manual.isolate_component("collector")

    assert manual.is_actor_blocked("bot") is True
    assert manual.is_component_isolated("collector") is True

    manual.release_isolation("collector")
    manual.unblock_actor("bot")

    assert manual.is_component_isolated("collector") is False
    assert manual.is_actor_blocked("bot") is False


def test_file_sources_read_records_and_aggregate(tmp_path: Path):
    incidents_csv = tmp_path / "incidents.csv"
    incidents_csv.write_text(
        "incident_id,policy,severity\nINC-0001,baseline,high\n",
        encoding="utf-8",
    )

    incident_source = FileIncidentSource(str(incidents_csv))
    incidents = incident_source.get_incidents()
    assert len(incidents) == 1
    assert incident_source.get_incident_count() == 1

    actions_csv = tmp_path / "actions.csv"
    with actions_csv.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["action_id", "status", "action"])
        writer.writerow(["ACT-0001", "applied", "enable_rate_limit"])
        writer.writerow(["ACT-0002", "failed", "restore_db"])

    action_source = FileActionSource(str(actions_csv))
    assert len(action_source.get_actions()) == 2
    summary = action_source.get_action_summary()
    assert summary["total"] == 2
    assert summary["applied"] == 1
    assert summary["failed"] == 1

    metrics_csv = tmp_path / "results.csv"
    with metrics_csv.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["policy", "availability", "mttd_sec", "mttr_sec", "downtime_sec"])
        writer.writerow(["baseline", 99.5, 10.0, 40.0, 12.0])
        writer.writerow(["hardening", 99.8, 8.0, 20.0, 6.0])

    metrics_source = FileMetricsSource(str(metrics_csv))
    by_policy = metrics_source.get_metrics_by_policy()
    assert len(by_policy) == 2
    overall = metrics_source.get_overall_metrics()
    assert round(overall["availability"], 2) == 99.65
    assert round(overall["mttd_sec"], 2) == 9.0

    state_csv = tmp_path / "state.csv"
    with state_csv.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["component", "status", "details", "last_updated"])
        writer.writerow(
            [
                "api",
                "isolated",
                json.dumps({"blocked_actors": ["user-bad"]}, ensure_ascii=False),
                "2026-03-01T10:00:00Z",
            ]
        )
        writer.writerow(
            [
                "gateway",
                "rate_limited",
                json.dumps({"rps": 50}, ensure_ascii=False),
                "2026-03-01T10:00:10Z",
            ]
        )

    state_source = FileStateSource(str(state_csv))
    assert state_source.get_component_state("api") is not None
    assert len(state_source.get_all_components()) == 2
    assert state_source.is_component_isolated("api") is True
    assert state_source.is_actor_blocked("user-bad") is True
