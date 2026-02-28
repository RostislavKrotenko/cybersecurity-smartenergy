"""Tests for src.emulator.engine — EmulatorEngine simulation."""

from __future__ import annotations

import csv
import hashlib
import io
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from src.contracts.event import CSV_COLUMNS, Event
from src.emulator.devices import build_device_index
from src.emulator.engine import SCENARIO_REGISTRY, EmulatorEngine, write_csv, write_jsonl

ROOT = Path(__file__).resolve().parent.parent
COMPONENTS_PATH = ROOT / "config" / "components.yaml"
SCENARIOS_PATH = ROOT / "config" / "scenarios.yaml"


# ═══════════════════════════════════════════════════════════════════════════
#  build_device_index
# ═══════════════════════════════════════════════════════════════════════════


class TestBuildDeviceIndex:
    def test_basic_index(self):
        cfg = {
            "components": {
                "edge": {
                    "instances": [
                        {"id": "meter-01", "ip": "10.0.0.1", "protocols": ["modbus"]},
                        {"id": "meter-02", "ip": "10.0.0.2", "protocols": ["modbus"]},
                    ]
                },
                "api": {
                    "instances": [
                        {"id": "api-gw-01", "ip": "10.0.1.1", "protocols": ["https"]},
                    ]
                },
            }
        }
        index = build_device_index(cfg)
        assert len(index) == 3
        assert "meter-01" in index
        assert index["api-gw-01"].component == "api"
        assert index["meter-01"].ip == "10.0.0.1"

    def test_empty_config(self):
        index = build_device_index({})
        assert index == {}

    def test_default_ip(self):
        cfg = {"components": {"edge": {"instances": [{"id": "dev-01"}]}}}
        index = build_device_index(cfg)
        assert index["dev-01"].ip == "0.0.0.0"


# ═══════════════════════════════════════════════════════════════════════════
#  EmulatorEngine init
# ═══════════════════════════════════════════════════════════════════════════


class TestEmulatorEngineInit:
    @pytest.fixture
    def basic_configs(self):
        components = {
            "components": {
                "edge": {
                    "instances": [
                        {"id": "inv-01", "ip": "10.0.0.1", "protocols": ["modbus"]},
                    ]
                },
            }
        }
        scenarios = {
            "simulation": {
                "duration_sec": 60,
                "start_time": "2026-02-26T10:00:00Z",
            },
            "background": {},
            "attacks": {},
        }
        return components, scenarios

    def test_default_seed(self, basic_configs):
        comp, scen = basic_configs
        engine = EmulatorEngine(comp, scen, seed=42)
        assert engine.duration_sec == 60

    def test_days_override(self, basic_configs):
        comp, scen = basic_configs
        engine = EmulatorEngine(comp, scen, days=2)
        assert engine.duration_sec == 2 * 86400

    def test_custom_start_time(self, basic_configs):
        comp, scen = basic_configs
        custom_start = datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC)
        engine = EmulatorEngine(comp, scen, start_time=custom_start)
        assert engine.sim_start == custom_start

    def test_scenario_set_stored(self, basic_configs):
        comp, scen = basic_configs
        engine = EmulatorEngine(comp, scen, scenario_set="brute_force,ddos_abuse")
        assert engine.scenario_set == "brute_force,ddos_abuse"


# ═══════════════════════════════════════════════════════════════════════════
#  EmulatorEngine.run — minimal smoke test
# ═══════════════════════════════════════════════════════════════════════════


class TestEmulatorEngineRun:
    def test_run_no_background_no_attacks(self):
        """Engine with no bg generators and no attacks returns empty list."""
        comp = {"components": {"edge": {"instances": [{"id": "d1", "ip": "10.0.0.1"}]}}}
        scen = {
            "simulation": {"duration_sec": 5, "start_time": "2026-02-26T10:00:00Z"},
            "background": {},
            "attacks": {},
        }
        engine = EmulatorEngine(comp, scen, seed=1)
        events = engine.run()
        assert isinstance(events, list)
        # No bg generators configured → no events
        assert len(events) == 0

    def test_run_returns_sorted_events(self):
        """If there are events, they should be sorted by timestamp."""
        comp = {"components": {"edge": {"instances": [{"id": "d1", "ip": "10.0.0.1"}]}}}
        scen = {
            "simulation": {"duration_sec": 10, "start_time": "2026-02-26T10:00:00Z"},
            "background": {},
            "attacks": {},
        }
        engine = EmulatorEngine(comp, scen, seed=1)
        events = engine.run()
        for i in range(len(events) - 1):
            assert events[i].timestamp <= events[i + 1].timestamp


# ═══════════════════════════════════════════════════════════════════════════
#  SCENARIO_REGISTRY
# ═══════════════════════════════════════════════════════════════════════════


class TestScenarioRegistry:
    def test_all_expected_scenarios_registered(self):
        expected = {
            "brute_force",
            "ddos_abuse",
            "telemetry_spoofing",
            "unauthorized_command",
            "outage_db_corruption",
        }
        assert set(SCENARIO_REGISTRY.keys()) == expected

    def test_registry_values_are_classes(self):
        for name, cls in SCENARIO_REGISTRY.items():
            assert isinstance(cls, type), f"{name} is not a class"


# ═══════════════════════════════════════════════════════════════════════════
#  Writers
# ═══════════════════════════════════════════════════════════════════════════


class TestWriters:
    def test_write_csv(self, tmp_path):
        events = [
            Event(
                timestamp="2026-02-26T10:00:00Z",
                source="inv-01",
                component="edge",
                event="telemetry_read",
                key="voltage",
                value="220.5",
                severity="low",
            ),
        ]
        path = tmp_path / "events.csv"
        write_csv(events, path)

        assert path.exists()
        with open(path) as f:
            lines = f.readlines()
        assert len(lines) == 2  # header + 1 row
        assert "timestamp" in lines[0]
        assert "inv-01" in lines[1]

    def test_write_jsonl(self, tmp_path):
        events = [
            Event(
                timestamp="2026-02-26T10:00:00Z",
                source="inv-01",
                component="edge",
                event="telemetry_read",
                key="voltage",
                value="220.5",
                severity="low",
            ),
        ]
        path = tmp_path / "events.jsonl"
        write_jsonl(events, path)

        assert path.exists()
        import json

        with open(path) as f:
            data = json.loads(f.readline())
        assert data["source"] == "inv-01"
        assert data["value"] == "220.5"

    def test_write_csv_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "deep" / "nested" / "events.csv"
        write_csv([], path)
        assert path.exists()


# ═══════════════════════════════════════════════════════════════════════════
#  Seed reproducibility (full emulator run)
# ═══════════════════════════════════════════════════════════════════════════


def _load_real_configs() -> tuple[dict, dict]:
    with open(COMPONENTS_PATH) as f:
        comp = yaml.safe_load(f)
    with open(SCENARIOS_PATH) as f:
        scen = yaml.safe_load(f)
    return comp, scen


def _events_to_csv_bytes(events: list[Event]) -> bytes:
    buf = io.StringIO()
    buf.write(",".join(CSV_COLUMNS) + "\n")
    for ev in events:
        buf.write(ev.to_csv_row() + "\n")
    return buf.getvalue().encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.mark.slow
class TestSeedReproducibility:
    """Two emulator runs with seed=42 MUST produce identical output."""

    def test_same_seed_same_hash(self):
        comp, scen = _load_real_configs()
        csv1 = _events_to_csv_bytes(EmulatorEngine(comp, scen, seed=42).run())
        csv2 = _events_to_csv_bytes(EmulatorEngine(comp, scen, seed=42).run())
        assert _sha256(csv1) == _sha256(csv2), "Emulator is NOT deterministic"

    def test_event_count_4507(self):
        """Default seed=42 + 1h duration → 4507 events."""
        comp, scen = _load_real_configs()
        events = EmulatorEngine(comp, scen, seed=42).run()
        assert len(events) == 4507, f"Expected 4507 events, got {len(events)}"

    def test_different_seed_differs(self):
        comp, scen = _load_real_configs()
        h1 = _sha256(_events_to_csv_bytes(EmulatorEngine(comp, scen, seed=42).run()))
        h2 = _sha256(_events_to_csv_bytes(EmulatorEngine(comp, scen, seed=99).run()))
        assert h1 != h2

    def test_write_csv_roundtrip(self, tmp_path):
        """write_csv → read back → same number of rows."""
        comp, scen = _load_real_configs()
        events = EmulatorEngine(comp, scen, seed=42).run()
        out = tmp_path / "events.csv"
        write_csv(events, out)
        with open(out) as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == len(events)
        assert set(rows[0].keys()) == set(CSV_COLUMNS)
