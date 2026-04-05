"""Додаткові тести helper-функцій емулятора для підняття покриття."""

from __future__ import annotations

import random
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.contracts.action import Action
from src.contracts.event import Event
from src.emulator.devices import Device
from src.emulator.engine import (
    _apply_attack_rate,
    _apply_demo_profile,
    _dirty_ts_iso,
    _dirty_ts_syslog,
    _format_api_line,
    _format_auth_line,
    _format_system_line,
    _generate_attack_burst,
    _generate_network_errors,
    _random_bg_event,
    _rotate_if_needed,
    _should_suppress,
    stream_demo_highrate,
)
from src.emulator.world import WorldState


class DeterministicRng:
    """Мінімальний RNG-стаб для детермінованих тестів."""

    def __init__(self, random_values: list[float] | None = None):
        self._random_values = list(random_values or [0.5])

    def random(self) -> float:
        if self._random_values:
            return self._random_values.pop(0)
        return 0.5

    def choice(self, seq):
        return seq[0]

    def randint(self, a: int, _b: int) -> int:
        return a

    def uniform(self, a: float, _b: float) -> float:
        return a


def _mk_event(**overrides) -> Event:
    data = {
        "timestamp": "2026-03-01T10:00:00Z",
        "source": "api-gw-01",
        "component": "api",
        "event": "http_request",
        "key": "endpoint",
        "value": "/health",
        "severity": "low",
        "actor": "operator",
        "ip": "10.0.0.10",
        "tags": "demo",
    }
    data.update(overrides)
    return Event(**data)


def test_apply_attack_rate_and_demo_profile_scale_counts():
    cfg = {
        "brute_force": {
            "schedule": {"start_offset_sec": [100, 120], "duration_sec": [40, 60]},
            "injection": [{"count": [2, 4]}, {"count": 3}],
        }
    }

    scaled = _apply_attack_rate(cfg, attack_rate=2.0)
    assert scaled["brute_force"]["injection"][0]["count"] == [4, 8]
    assert scaled["brute_force"]["injection"][1]["count"] == 6
    assert cfg["brute_force"]["injection"][0]["count"] == [2, 4]

    demo = _apply_demo_profile(cfg, attack_rate=1.5)
    assert demo["brute_force"]["schedule"]["start_offset_sec"] == [3, 8]
    assert demo["brute_force"]["injection"][0]["count"] == [6, 12]


def test_timestamp_and_line_format_helpers_cover_branches():
    dt = datetime(2026, 2, 28, 14, 5, 1, tzinfo=UTC)
    assert _dirty_ts_iso(dt) == "2026-02-28 14:05:01"

    syslog_ts = _dirty_ts_syslog(dt, DeterministicRng([0.0]))
    assert "Feb" in syslog_ts
    assert "14:05:01" in syslog_ts

    auth_event = _mk_event(event="auth_failure", actor="admin", ip="192.168.1.10", tags="auth")
    auth_line = _format_auth_line(auth_event, dt, DeterministicRng([0.0, 0.0]))
    assert "Failed password" in auth_line
    assert "192.168.1.10" not in auth_line  # branch with omitted 'from' part

    api_event = _mk_event(event="http_request", value="/api/v1/state", severity="high")
    api_line = _format_api_line(api_event, dt, DeterministicRng([0.9, 0.9]))
    assert "api-gw-01" in api_line
    assert "/api/v1/state" in api_line

    system_event = _mk_event(component="db", event="db_error", key="table", value="checksum")
    system_line = _format_system_line(system_event, dt, DeterministicRng([0.8]))
    assert "api-gw-01" in system_line
    assert "db error" in system_line


def test_background_and_attack_generation_helpers():
    now = datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC)
    rng = DeterministicRng([0.9, 0.9, 0.9])
    devices = {
        "gateway-01": Device("gateway-01", "10.0.0.1", "gateway", []),
        "meter-17": Device("meter-17", "10.0.0.17", "edge", []),
        "api-gw-01": Device("api-gw-01", "10.0.1.1", "api", []),
        "switch-core-01": Device("switch-core-01", "10.0.2.1", "network", []),
        "firewall-01": Device("firewall-01", "10.0.2.2", "network", []),
    }

    bg_event = _random_bg_event(rng, devices, now)
    assert isinstance(bg_event, Event)
    assert bg_event.timestamp == "2026-03-01T10:00:00Z"

    burst = _generate_attack_burst("brute_force", rng, devices, now)
    assert len(burst) == 8
    assert all(ev.event == "auth_failure" for ev in burst)
    assert len({ev.correlation_id for ev in burst}) == 1


def test_rotate_suppress_and_network_error_helpers(tmp_path: Path):
    out_path = tmp_path / "events.jsonl"
    out_path.write_text("x" * 8192, encoding="utf-8")

    rotated = _rotate_if_needed(out_path, max_mb=0.0001)
    assert rotated is True
    assert out_path.with_suffix(".jsonl.bak").exists()

    small_path = tmp_path / "small.jsonl"
    small_path.write_text("ok", encoding="utf-8")
    assert _rotate_if_needed(small_path, max_mb=10.0) is False

    world = WorldState()
    world.gateway.rate_limit_enabled = True
    assert _should_suppress(_mk_event(event="rate_exceeded"), world) is True

    world = WorldState()
    world.auth.blocked_actors["admin"] = time.monotonic() + 60
    assert _should_suppress(_mk_event(event="auth_failure", actor="admin"), world) is True

    world = WorldState()
    world.api.status = "isolated"
    assert _should_suppress(_mk_event(component="api", event="http_request"), world) is True

    world = WorldState()
    world.db.status = "restoring"
    assert _should_suppress(_mk_event(component="db", event="db_error"), world) is True

    disconnected_world = WorldState()
    disconnected_world.network.disconnected = True
    assert _should_suppress(_mk_event(component="api", event="http_request"), disconnected_world)

    errors = _generate_network_errors(
        DeterministicRng([0.5]),
        {},
        datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC),
        disconnected_world,
    )
    assert len(errors) >= 3
    assert all(ev.severity == "critical" for ev in errors)

    healthy = WorldState()
    assert _generate_network_errors(DeterministicRng(), {}, datetime.now(tz=UTC), healthy) == []


def test_stream_demo_highrate_single_tick_writes_outputs(tmp_path: Path, monkeypatch):
    jsonl_path = tmp_path / "events.jsonl"
    csv_path = tmp_path / "events.csv"
    raw_dir = tmp_path / "raw"
    actions_path = tmp_path / "actions.jsonl"
    applied_path = tmp_path / "actions_applied.jsonl"

    action = Action(
        action_id="ACT-test0001",
        ts_utc="2026-03-01T10:00:00Z",
        action="enable_rate_limit",
        target_component="gateway",
        params={"rps": 50, "burst": 100, "duration_sec": 300},
        correlation_id="INC-0001",
    )
    actions_path.write_text(action.to_json() + "\n", encoding="utf-8")

    engine = SimpleNamespace(
        rng=random.Random(1),
        devices={
            "api-gw-01": Device("api-gw-01", "10.0.1.1", "api", []),
            "gateway-01": Device("gateway-01", "10.0.0.1", "gateway", []),
            "meter-17": Device("meter-17", "10.0.0.17", "edge", []),
            "switch-core-01": Device("switch-core-01", "10.0.2.1", "network", []),
            "firewall-01": Device("firewall-01", "10.0.2.2", "network", []),
        },
    )

    def _stop_after_first_tick(_interval: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("src.emulator.engine.time.sleep", _stop_after_first_tick)

    with pytest.raises(KeyboardInterrupt):
        stream_demo_highrate(
            engine=engine,
            path=jsonl_path,
            interval_sec=0.01,
            attack_every_sec=0.01,
            bg_per_tick=1,
            max_file_mb=50.0,
            raw_log_dir=raw_dir,
            csv_out=csv_path,
            actions_path=actions_path,
            applied_path=applied_path,
        )

    assert jsonl_path.exists()
    assert jsonl_path.read_text(encoding="utf-8").strip()
    assert csv_path.exists()
    assert "timestamp,source" in csv_path.read_text(encoding="utf-8")
    assert applied_path.exists()
    assert "ACT-test0001" in applied_path.read_text(encoding="utf-8")
    assert any(raw_dir.glob("*.log"))
