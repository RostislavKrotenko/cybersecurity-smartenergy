"""Tests for src.contracts — Event, Alert, Incident data classes."""

from __future__ import annotations

import csv
import io
import json

import pytest

from src.contracts.alert import Alert
from src.contracts.enums import Component, EventType, Severity
from src.contracts.event import CSV_COLUMNS, Event
from src.contracts.incident import INCIDENT_CSV_COLUMNS, Incident

# ═══════════════════════════════════════════════════════════════════════════
#  Event
# ═══════════════════════════════════════════════════════════════════════════


class TestEvent:
    @pytest.fixture
    def sample_event(self):
        return Event(
            timestamp="2026-02-26T10:00:00Z",
            source="inv-01",
            component="edge",
            event="telemetry_read",
            key="voltage",
            value="220.5",
            severity="low",
            actor="system",
            ip="10.0.0.1",
            unit="V",
            tags="telemetry",
            correlation_id="COR-001",
        )

    def test_csv_header_matches_columns(self):
        header = Event.csv_header()
        assert header == ",".join(CSV_COLUMNS)

    def test_to_csv_row(self, sample_event):
        row = sample_event.to_csv_row()
        reader = csv.reader(io.StringIO(row))
        values = next(reader)
        assert len(values) == len(CSV_COLUMNS)
        assert values[0] == "2026-02-26T10:00:00Z"  # timestamp
        assert values[1] == "inv-01"  # source
        assert values[7] == "220.5"  # value (index 7 per CSV_COLUMNS)

    def test_to_json(self, sample_event):
        j = sample_event.to_json()
        data = json.loads(j)
        assert data["timestamp"] == "2026-02-26T10:00:00Z"
        assert data["source"] == "inv-01"
        assert data["correlation_id"] == "COR-001"

    def test_default_optional_fields(self):
        ev = Event(
            timestamp="2026-02-26T10:00:00Z",
            source="s",
            component="api",
            event="raw_log",
            key="msg",
            value="hello",
            severity="low",
        )
        assert ev.actor == ""
        assert ev.ip == ""
        assert ev.unit == ""
        assert ev.tags == ""
        assert ev.correlation_id == ""

    def test_csv_roundtrip(self, sample_event):
        """CSV header + row can be re-read by csv.DictReader."""
        text = Event.csv_header() + "\n" + sample_event.to_csv_row() + "\n"
        reader = csv.DictReader(io.StringIO(text))
        row = next(reader)
        assert row["timestamp"] == "2026-02-26T10:00:00Z"
        assert row["source"] == "inv-01"


# ═══════════════════════════════════════════════════════════════════════════
#  Alert
# ═══════════════════════════════════════════════════════════════════════════


class TestAlert:
    def test_alert_fields(self):
        a = Alert(
            alert_id="ALR-0001",
            rule_id="RULE-BF-001",
            rule_name="Brute-Force",
            threat_type="credential_attack",
            severity="high",
            confidence=0.85,
            timestamp="2026-02-26T10:00:00Z",
            component="api",
            source="api-gw-01",
            description="5 auth failures",
            event_count=5,
            event_ids="COR-001;COR-002",
        )
        assert a.alert_id == "ALR-0001"
        assert a.confidence == 0.85
        assert a.response_hint == ""  # default

    def test_alert_response_hint(self):
        a = Alert(
            alert_id="ALR-0001",
            rule_id="RULE-BF-001",
            rule_name="test",
            threat_type="credential_attack",
            severity="high",
            confidence=0.85,
            timestamp="2026-02-26T10:00:00Z",
            component="api",
            source="api-gw-01",
            description="test",
            event_count=1,
            event_ids="x",
            response_hint="block_ip",
        )
        assert a.response_hint == "block_ip"


# ═══════════════════════════════════════════════════════════════════════════
#  Incident
# ═══════════════════════════════════════════════════════════════════════════


class TestIncident:
    @pytest.fixture
    def sample_incident(self):
        return Incident(
            incident_id="INC-001",
            policy="baseline",
            threat_type="credential_attack",
            severity="high",
            component="api",
            event_count=5,
            start_ts="2026-02-26T10:00:00Z",
            detect_ts="2026-02-26T10:00:30Z",
            recover_ts="2026-02-26T10:02:30Z",
            mttd_sec=30.0,
            mttr_sec=120.0,
            impact_score=0.595,
            description="Brute-force detected",
            response_action="block_ip",
        )

    def test_csv_header(self):
        assert Incident.csv_header() == ",".join(INCIDENT_CSV_COLUMNS)

    def test_to_csv_row(self, sample_incident):
        row = sample_incident.to_csv_row()
        reader = csv.reader(io.StringIO(row))
        values = next(reader)
        assert values[0] == "INC-001"
        assert values[1] == "baseline"
        assert float(values[9]) == 30.0

    def test_csv_roundtrip(self, sample_incident):
        text = Incident.csv_header() + "\n" + sample_incident.to_csv_row() + "\n"
        reader = csv.DictReader(io.StringIO(text))
        row = next(reader)
        assert row["incident_id"] == "INC-001"
        assert row["policy"] == "baseline"


# ═══════════════════════════════════════════════════════════════════════════
#  Enums
# ═══════════════════════════════════════════════════════════════════════════


class TestEnums:
    def test_severity_values(self):
        assert Severity.LOW == "low"
        assert Severity.CRITICAL == "critical"

    def test_component_values(self):
        assert Component.EDGE == "edge"
        assert Component.API == "api"

    def test_event_type_values(self):
        assert EventType.AUTH_FAILURE == "auth_failure"
        assert EventType.TELEMETRY_READ == "telemetry_read"
        assert EventType.CMD_EXEC == "cmd_exec"
