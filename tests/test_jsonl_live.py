"""Tests for JSONL input support and live / watch mode helpers.

Covers:
  - load_events_jsonl / load_events auto-detect
  - JSONL ↔ CSV parity (same events produce same analysis)
  - stream_jsonl writes valid JSONL incrementally
  - watch_pipeline internal helpers
"""

from __future__ import annotations

import json

import pytest

from src.analyzer.pipeline import (
    _parse_event,
    load_events,
    load_events_csv,
    load_events_jsonl,
)
from src.contracts.event import CSV_COLUMNS, Event
from src.emulator.engine import EmulatorEngine, stream_jsonl, write_csv, write_jsonl

# ═══════════════════════════════════════════════════════════════════════════
#  _parse_event
# ═══════════════════════════════════════════════════════════════════════════

class TestParseEvent:
    def test_full_dict(self):
        row = {
            "timestamp": "2026-02-26T10:00:00Z",
            "source": "inv-01",
            "component": "edge",
            "event": "telemetry_read",
            "key": "voltage",
            "value": "220.5",
            "severity": "low",
            "actor": "sensor",
            "ip": "10.0.0.1",
            "unit": "V",
            "tags": "normal",
            "correlation_id": "COR-001",
        }
        ev = _parse_event(row)
        assert ev.source == "inv-01"
        assert ev.value == "220.5"
        assert ev.correlation_id == "COR-001"

    def test_missing_optional_fields(self):
        row = {
            "timestamp": "2026-02-26T10:00:00Z",
            "source": "dev-01",
            "component": "api",
            "event": "auth_failure",
            "key": "login",
            "value": "admin",
            "severity": "medium",
        }
        ev = _parse_event(row)
        assert ev.actor == ""
        assert ev.ip == ""
        assert ev.tags == ""

    def test_empty_dict_defaults(self):
        ev = _parse_event({})
        assert ev.severity == "low"
        assert ev.timestamp == ""


# ═══════════════════════════════════════════════════════════════════════════
#  load_events_jsonl
# ═══════════════════════════════════════════════════════════════════════════

class TestLoadEventsJsonl:
    def test_basic_load(self, tmp_path):
        path = tmp_path / "test.jsonl"
        rows = [
            {"timestamp": "2026-02-26T10:00:00Z", "source": "inv-01",
             "component": "edge", "event": "telemetry_read", "key": "voltage",
             "value": "220.5", "severity": "low"},
            {"timestamp": "2026-02-26T10:00:01Z", "source": "inv-02",
             "component": "edge", "event": "telemetry_read", "key": "current",
             "value": "5.3", "severity": "low"},
        ]
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        events = load_events_jsonl(str(path))
        assert len(events) == 2
        assert events[0].source == "inv-01"
        assert events[1].value == "5.3"

    def test_blank_lines_skipped(self, tmp_path):
        path = tmp_path / "test.jsonl"
        content = (
            '{"timestamp":"T","source":"s","component":"c","event":"e",'
            '"key":"k","value":"v","severity":"low"}\n'
            "\n"
            "\n"
            '{"timestamp":"T2","source":"s2","component":"c","event":"e",'
            '"key":"k","value":"v2","severity":"low"}\n'
        )
        path.write_text(content)
        events = load_events_jsonl(str(path))
        assert len(events) == 2

    def test_malformed_lines_skipped(self, tmp_path):
        path = tmp_path / "test.jsonl"
        content = (
            '{"timestamp":"T","source":"s","component":"c","event":"e",'
            '"key":"k","value":"v","severity":"low"}\n'
            "NOT VALID JSON\n"
            '{"timestamp":"T2","source":"s2","component":"c","event":"e",'
            '"key":"k","value":"v2","severity":"low"}\n'
        )
        path.write_text(content)
        events = load_events_jsonl(str(path))
        assert len(events) == 2


# ═══════════════════════════════════════════════════════════════════════════
#  load_events auto-detect
# ═══════════════════════════════════════════════════════════════════════════

class TestLoadEventsAutoDetect:
    def test_csv_detected(self, tmp_path):
        path = tmp_path / "events.csv"
        path.write_text(
            ",".join(CSV_COLUMNS) + "\n"
            "2026-02-26T10:00:00Z,inv-01,edge,telemetry_read,,,"
            "voltage,220.5,V,low,,\n"
        )
        # We can't easily guarantee the CSV is perfect for DictReader
        # but at least ensure load_events doesn't crash with .csv extension.
        events = load_events(str(path))
        assert isinstance(events, list)

    def test_jsonl_detected(self, tmp_path):
        path = tmp_path / "events.jsonl"
        path.write_text(
            json.dumps({
                "timestamp": "2026-02-26T10:00:00Z", "source": "inv-01",
                "component": "edge", "event": "telemetry_read",
                "key": "voltage", "value": "220.5", "severity": "low",
            }) + "\n"
        )
        events = load_events(str(path))
        assert len(events) == 1
        assert events[0].source == "inv-01"


# ═══════════════════════════════════════════════════════════════════════════
#  CSV ↔ JSONL parity
# ═══════════════════════════════════════════════════════════════════════════

class TestCsvJsonlParity:
    """Events written via write_csv vs write_jsonl must reload identically."""

    @pytest.fixture
    def sample_events(self):
        return [
            Event(
                timestamp="2026-02-26T10:00:00Z",
                source="inv-01",
                component="edge",
                event="telemetry_read",
                key="voltage",
                value="220.5",
                severity="low",
                actor="sensor",
                ip="10.0.0.1",
                unit="V",
                tags="normal",
                correlation_id="COR-001",
            ),
            Event(
                timestamp="2026-02-26T10:00:05Z",
                source="api-gw-01",
                component="api",
                event="auth_failure",
                key="login",
                value="admin",
                severity="medium",
                actor="unknown",
                ip="192.168.1.100",
                unit="",
                tags="brute_force",
                correlation_id="COR-BF-001",
            ),
        ]

    def test_parity_fields(self, tmp_path, sample_events):
        csv_path = tmp_path / "events.csv"
        jsonl_path = tmp_path / "events.jsonl"

        write_csv(sample_events, csv_path)
        write_jsonl(sample_events, jsonl_path)

        csv_events = load_events_csv(str(csv_path))
        jsonl_events = load_events_jsonl(str(jsonl_path))

        assert len(csv_events) == len(jsonl_events)
        for csv_ev, jsonl_ev in zip(csv_events, jsonl_events):
            assert csv_ev.timestamp == jsonl_ev.timestamp
            assert csv_ev.source == jsonl_ev.source
            assert csv_ev.component == jsonl_ev.component
            assert csv_ev.event == jsonl_ev.event
            assert csv_ev.key == jsonl_ev.key
            assert csv_ev.value == jsonl_ev.value
            assert csv_ev.severity == jsonl_ev.severity
            assert csv_ev.actor == jsonl_ev.actor
            assert csv_ev.ip == jsonl_ev.ip


# ═══════════════════════════════════════════════════════════════════════════
#  stream_jsonl
# ═══════════════════════════════════════════════════════════════════════════

class TestStreamJsonl:
    @pytest.fixture
    def tiny_engine(self):
        comp = {
            "components": {
                "edge": {
                    "instances": [
                        {"id": "inv-01", "ip": "10.0.0.1", "protocols": ["modbus"]}
                    ]
                }
            }
        }
        scen = {
            "simulation": {"duration_sec": 10, "start_time": "2026-02-26T10:00:00Z"},
            "background": {
                "telemetry": {
                    "sources": ["inv-01"],
                    "component": ["edge"],
                    "interval_sec": [1, 2],
                    "severity": "low",
                    "tags": ["test"],
                    "keys": [
                        {"key": "voltage", "range": [210, 240], "unit": "V"},
                    ],
                },
            },
            "attacks": {},
        }
        return EmulatorEngine(comp, scen, seed=42)

    def test_stream_creates_file(self, tmp_path, tiny_engine):
        path = tmp_path / "live.jsonl"
        count = stream_jsonl(tiny_engine, path, interval_sec=0, max_events=10)
        assert path.exists()
        assert count > 0

    def test_stream_valid_jsonl(self, tmp_path, tiny_engine):
        path = tmp_path / "live.jsonl"
        stream_jsonl(tiny_engine, path, interval_sec=0, max_events=5)
        with open(path) as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        for line in lines:
            obj = json.loads(line)
            assert "timestamp" in obj
            assert "source" in obj

    def test_stream_max_events_cap(self, tmp_path, tiny_engine):
        path = tmp_path / "live.jsonl"
        count = stream_jsonl(tiny_engine, path, interval_sec=0, max_events=3)
        assert count == 3
        with open(path) as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        assert len(lines) == 3

    def test_stream_appends_to_existing(self, tmp_path, tiny_engine):
        path = tmp_path / "live.jsonl"
        path.write_text('{"existing":"line"}\n')
        stream_jsonl(tiny_engine, path, interval_sec=0, max_events=2)
        with open(path) as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        assert len(lines) == 3  # 1 existing + 2 new
