"""Додаткові unit-тести helper-частини analyzer pipeline."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from src.analyzer import pipeline
from src.analyzer.state_store import ComponentStateStore
from src.contracts.action import Action, ActionAck
from src.contracts.event import Event
from tests.conftest import make_incident


def _mk_event(ts: str = "2026-03-01T10:00:00Z") -> Event:
    return Event(
        timestamp=ts,
        source="api-gw-01",
        component="api",
        event="http_request",
        key="endpoint",
        value="/health",
        severity="low",
        actor="operator",
        ip="10.0.0.10",
        tags="access",
        correlation_id="COR-001",
    )


def test_throttle_actions_and_restore_lock(monkeypatch):
    monkeypatch.setattr("src.analyzer.pipeline.time.monotonic", lambda: 100.0)

    duplicate_a = Action(
        ts_utc="2026-03-01T10:00:00Z",
        action="enable_rate_limit",
        target_component="gateway",
        target_id="api-gw-01",
        params={"rps": 50, "burst": 100},
        correlation_id="INC-0001",
    )
    duplicate_b = Action(
        ts_utc="2026-03-01T10:00:01Z",
        action="enable_rate_limit",
        target_component="gateway",
        target_id="api-gw-01",
        params={"rps": 50, "burst": 100},
        correlation_id="INC-0001",
    )
    unique_c = Action(
        ts_utc="2026-03-01T10:00:02Z",
        action="block_actor",
        target_component="auth",
        target_id="gateway-01",
        params={"actor": "intruder"},
        correlation_id="INC-0001",
    )

    kept = pipeline._throttle_actions([duplicate_a, duplicate_b, unique_c], {})
    assert len(kept) == 2
    assert kept[0].action == "enable_rate_limit"
    assert kept[1].action == "block_actor"

    unresolved_restore = Action(
        ts_utc="2026-03-01T10:00:03Z",
        action="restore_db",
        target_component="db",
        status="emitted",
    )
    incoming = [
        Action(
            ts_utc="2026-03-01T10:00:04Z",
            action="restore_db",
            target_component="db",
            status="pending",
        ),
        Action(
            ts_utc="2026-03-01T10:00:05Z",
            action="enable_rate_limit",
            target_component="gateway",
            status="pending",
        ),
    ]

    filtered = pipeline._apply_restore_lock(incoming, [unresolved_restore])
    assert len(filtered) == 1
    assert filtered[0].action == "enable_rate_limit"


def test_apply_acks_updates_action_status_and_state_store():
    action = Action(
        action_id="ACT-0001",
        ts_utc="2026-03-01T10:00:00Z",
        action="degrade_network",
        target_component="network",
        target_id="network-sim",
        params={"latency_ms": 300, "drop_rate": 0.2, "ttl_sec": 60},
        status="emitted",
        correlation_id="INC-0009",
    )
    ack = ActionAck(
        action_id="ACT-0001",
        correlation_id="INC-0009",
        target_component="network",
        action="degrade_network",
        applied_ts_utc="2026-03-01T10:00:10Z",
        result="success",
        state_event="network_degraded",
    )

    store = ComponentStateStore()
    changed = pipeline._apply_acks([ack], {action.action_id: action}, [action], store)

    assert changed is True
    assert action.status == "applied"
    assert store.network.status == "degraded"
    assert "latency=300ms" in store.network.details


def test_run_pipeline_empty_and_selected_policy_paths(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "load_events", lambda _path: [])
    empty_result = pipeline.run_pipeline("data/missing.csv")
    assert empty_result["events"] == []

    events = [_mk_event("2026-03-01T10:00:00Z"), _mk_event("2026-03-01T10:10:00Z")]
    writes: dict[str, bool] = {}

    monkeypatch.setattr(pipeline, "load_events", lambda _path: events)
    monkeypatch.setattr(pipeline, "load_yaml", lambda _path: {"rules": []})
    monkeypatch.setattr(pipeline, "load_policies", lambda _cfg: {"policies": []})
    monkeypatch.setattr(pipeline, "list_policy_names", lambda _cfg: ["baseline"])
    monkeypatch.setattr(pipeline, "get_modifiers", lambda _cfg, _p: {})
    monkeypatch.setattr(pipeline, "detect", lambda _events, _rules, policy_modifiers=None: ["ALR"])
    monkeypatch.setattr(
        pipeline,
        "correlate",
        lambda _alerts, pname, policy_modifiers=None: [make_incident(policy=pname)],
    )

    metric = SimpleNamespace(availability_pct=99.9, total_downtime_hr=0.1)
    monkeypatch.setattr(pipeline, "compute", lambda _incs, _p, horizon_sec: metric)
    monkeypatch.setattr(
        pipeline, "rank_controls", lambda *_args, **_kwargs: [{"policy": "baseline"}]
    )
    monkeypatch.setattr(
        pipeline,
        "write_results_csv",
        lambda *_args, **_kwargs: writes.__setitem__("results", True),
    )
    monkeypatch.setattr(
        pipeline,
        "write_incidents_csv",
        lambda *_args, **_kwargs: writes.__setitem__("incidents", True),
    )
    monkeypatch.setattr(
        pipeline,
        "write_report_txt",
        lambda *_args, **_kwargs: writes.__setitem__("txt", True),
    )
    monkeypatch.setattr(
        pipeline,
        "write_report_html",
        lambda *_args, **_kwargs: writes.__setitem__("html", True),
    )
    monkeypatch.setattr(
        pipeline,
        "write_plots",
        lambda *_args, **_kwargs: writes.__setitem__("plots", True),
    )

    result = pipeline.run_pipeline(
        input_path="data/events.csv",
        out_dir=str(tmp_path),
        policy_names=["baseline", "unknown"],
        config_dir="config",
    )

    assert list(result["metrics"].keys()) == ["baseline"]
    assert result["metrics"]["baseline"] is metric
    assert all(writes.values())


def test_write_live_output_and_incremental_detect(monkeypatch, tmp_path: Path):
    writes: dict[str, int] = {"results": 0, "incidents": 0, "txt": 0}

    monkeypatch.setattr(
        pipeline,
        "compute",
        lambda incs, pname, horizon_sec: SimpleNamespace(policy=pname, incidents_total=len(incs)),
    )
    monkeypatch.setattr(
        pipeline,
        "rank_controls",
        lambda *_args, **_kwargs: [{"policy": "baseline", "effectiveness": 1.0}],
    )
    monkeypatch.setattr(
        pipeline,
        "write_results_csv",
        lambda *_args, **_kwargs: writes.__setitem__("results", writes["results"] + 1),
    )
    monkeypatch.setattr(
        pipeline,
        "write_incidents_csv",
        lambda *_args, **_kwargs: writes.__setitem__("incidents", writes["incidents"] + 1),
    )

    reported_actions = {"count": 0}

    def _fake_report(_metrics, _incidents, _ranking, _path, *, actions_count=0):
        writes["txt"] += 1
        reported_actions["count"] = actions_count

    monkeypatch.setattr(pipeline, "write_report_txt", _fake_report)

    incidents = [make_incident(policy="baseline")]
    pipeline._write_live_output(
        incidents=incidents,
        selected=["baseline"],
        policies_cfg={"policies": []},
        horizon_sec=3600.0,
        out_p=tmp_path,
        actions_count=3,
    )

    assert writes["results"] == 1
    assert writes["incidents"] == 1
    assert writes["txt"] == 1
    assert reported_actions["count"] == 3

    monkeypatch.setattr(pipeline, "get_modifiers", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        pipeline,
        "detect",
        lambda _events, _rules, policy_modifiers=None: ["ALR-001"],
    )
    monkeypatch.setattr(
        pipeline,
        "correlate",
        lambda _alerts, pname, policy_modifiers=None: [
            make_incident(policy=pname, incident_id="INC-X")
        ],
    )

    counter, new_incs = pipeline._incremental_detect(
        events=[_mk_event()],
        rules_cfg={"rules": []},
        policies_cfg={"policies": []},
        selected=["baseline"],
        inc_counter=7,
    )
    assert counter == 8
    assert len(new_incs) == 1
    assert new_incs[0].incident_id == "INC-0008"
