"""Tests for src.analyzer.detector — rule-based detection engine."""

from __future__ import annotations

import itertools

import pytest

from src.analyzer.detector import (
    _detect_brute_force,
    _detect_ddos,
    _detect_outage,
    _detect_telemetry_spoof,
    _detect_unauthorized_cmd,
    _diff_sec,
    _ts,
    detect,
)
from tests.conftest import make_event, ts_offset

# ═══════════════════════════════════════════════════════════════════════════
#  Utility function tests
# ═══════════════════════════════════════════════════════════════════════════

class TestTimestampUtils:
    def test_ts_parses_iso_with_z(self):
        dt = _ts("2026-02-26T10:00:00Z")
        assert dt.year == 2026
        assert dt.month == 2
        assert dt.hour == 10

    def test_ts_parses_iso_with_offset(self):
        dt = _ts("2026-02-26T12:00:00+02:00")
        assert dt.hour == 12

    def test_diff_sec_positive(self):
        a = "2026-02-26T10:00:00Z"
        b = "2026-02-26T10:01:00Z"
        assert _diff_sec(a, b) == 60.0

    def test_diff_sec_zero(self):
        t = "2026-02-26T10:00:00Z"
        assert _diff_sec(t, t) == 0.0

    def test_diff_sec_negative(self):
        a = "2026-02-26T10:01:00Z"
        b = "2026-02-26T10:00:00Z"
        assert _diff_sec(a, b) == -60.0


# ═══════════════════════════════════════════════════════════════════════════
#  detect() — top-level dispatcher
# ═══════════════════════════════════════════════════════════════════════════

class TestDetect:
    def test_empty_events_returns_empty(self, brute_force_rule):
        result = detect([], brute_force_rule)
        assert result == []

    def test_disabled_rule_skipped(self):
        cfg = {
            "rules": [
                {
                    "id": "RULE-BF-001",
                    "name": "disabled",
                    "threat_type": "credential_attack",
                    "enabled": False,
                    "match": {"event": "auth_failure"},
                    "window_sec": 60,
                    "threshold": 1,
                }
            ]
        }
        events = [make_event(event="auth_failure")]
        assert detect(events, cfg) == []

    def test_unknown_rule_prefix_skipped(self):
        cfg = {
            "rules": [
                {
                    "id": "RULE-UNKNOWN-001",
                    "name": "unknown",
                    "threat_type": "???",
                    "match": {"event": "something"},
                    "window_sec": 60,
                    "threshold": 1,
                }
            ]
        }
        events = [make_event(event="something")]
        assert detect(events, cfg) == []

    def test_alerts_sorted_by_timestamp(self, brute_force_rule):
        events = [
            make_event(
                event="auth_failure",
                timestamp=ts_offset(seconds=i),
                ip="10.0.0.1",
                source="api-gw-01",
                correlation_id=f"COR-{i}",
            )
            for i in range(6)
        ]
        alerts = detect(events, brute_force_rule)
        if len(alerts) >= 2:
            for a, b in itertools.pairwise(alerts):
                assert a.timestamp <= b.timestamp

    def test_policy_modifiers_adjust_threshold(self, brute_force_rule):
        """With threshold_multiplier=2.0, need 10 events instead of 5."""
        events = [
            make_event(
                event="auth_failure",
                timestamp=ts_offset(seconds=i),
                ip="10.0.0.1",
                source="api-gw-01",
                correlation_id=f"COR-{i}",
            )
            for i in range(7)  # 7 events — enough for threshold=5,  not for threshold=10
        ]
        modifiers = {"credential_attack": {"threshold_multiplier": 2.0}}
        alerts = detect(events, brute_force_rule, policy_modifiers=modifiers)
        assert len(alerts) == 0  # threshold is now 10

    def test_policy_modifiers_adjust_window(self, brute_force_rule):
        """With window_multiplier=0.1, the 60s window shrinks to 6s."""
        events = [
            make_event(
                event="auth_failure",
                timestamp=ts_offset(seconds=i * 10),  # 10s apart
                ip="10.0.0.1",
                source="api-gw-01",
                correlation_id=f"COR-{i}",
            )
            for i in range(10)
        ]
        modifiers = {"credential_attack": {"window_multiplier": 0.1}}
        alerts = detect(events, brute_force_rule, policy_modifiers=modifiers)
        # window is 6s but events are 10s apart — never accumulate 5 in window
        assert len(alerts) == 0


# ═══════════════════════════════════════════════════════════════════════════
#  Brute-force detection
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectBruteForce:
    @pytest.fixture
    def rule(self):
        return {
            "id": "RULE-BF-001",
            "name": "Brute-Force Authentication",
            "threat_type": "credential_attack",
            "severity": "high",
            "confidence": 0.85,
            "response_hint": "block_ip",
        }

    def test_fires_when_threshold_reached(self, rule):
        events = [
            make_event(
                event="auth_failure",
                timestamp=ts_offset(seconds=i * 5),
                ip="10.0.0.1",
                source="api-gw-01",
                correlation_id=f"COR-{i}",
            )
            for i in range(5)
        ]
        alerts = _detect_brute_force(events, rule, window=60, threshold=5, counter=0)
        assert len(alerts) == 1
        assert alerts[0].rule_id == "RULE-BF-001"
        assert alerts[0].severity == "high"
        assert alerts[0].event_count == 5

    def test_no_alert_below_threshold(self, rule):
        events = [
            make_event(
                event="auth_failure",
                timestamp=ts_offset(seconds=i),
                ip="10.0.0.1",
                source="api-gw-01",
            )
            for i in range(4)
        ]
        alerts = _detect_brute_force(events, rule, window=60, threshold=5, counter=0)
        assert alerts == []

    def test_groups_by_ip_and_source(self, rule):
        # 3 events from IP-A, 3 from IP-B — neither hits threshold=5
        events = []
        for i in range(3):
            events.append(make_event(
                event="auth_failure",
                timestamp=ts_offset(seconds=i),
                ip="10.0.0.1",
                source="api-gw-01",
            ))
            events.append(make_event(
                event="auth_failure",
                timestamp=ts_offset(seconds=i),
                ip="10.0.0.2",
                source="api-gw-01",
            ))
        alerts = _detect_brute_force(events, rule, window=60, threshold=5, counter=0)
        assert len(alerts) == 0

    def test_events_outside_window_evicted(self, rule):
        """Events spread over 120s w/ 30s window — never accumulate 5."""
        events = [
            make_event(
                event="auth_failure",
                timestamp=ts_offset(seconds=i * 30),
                ip="10.0.0.1",
                source="api-gw-01",
            )
            for i in range(5)
        ]
        alerts = _detect_brute_force(events, rule, window=30, threshold=5, counter=0)
        assert len(alerts) == 0

    def test_alert_id_uses_counter(self, rule):
        events = [
            make_event(
                event="auth_failure",
                timestamp=ts_offset(seconds=i),
                ip="10.0.0.1",
                source="api-gw-01",
                correlation_id=f"COR-{i}",
            )
            for i in range(5)
        ]
        alerts = _detect_brute_force(events, rule, window=60, threshold=5, counter=10)
        assert alerts[0].alert_id == "ALR-0011"

    def test_description_contains_ip(self, rule):
        events = [
            make_event(
                event="auth_failure",
                timestamp=ts_offset(seconds=i),
                ip="192.168.1.100",
                source="api-gw-01",
            )
            for i in range(5)
        ]
        alerts = _detect_brute_force(events, rule, window=60, threshold=5, counter=0)
        assert "192.168.1.100" in alerts[0].description


# ═══════════════════════════════════════════════════════════════════════════
#  DDoS detection
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectDDoS:
    @pytest.fixture
    def rule(self):
        return {
            "id": "RULE-DDOS-001",
            "name": "DDoS Flood",
            "threat_type": "availability_attack",
            "severity": "critical",
            "confidence": 0.90,
            "response_hint": "rate_limit_ip_range",
        }

    def test_fires_on_rate_exceeded_burst(self, rule):
        events = [
            make_event(
                event="rate_exceeded",
                timestamp=ts_offset(seconds=i),
                source="api-gw-01",
                component="api",
                correlation_id=f"COR-{i}",
            )
            for i in range(12)
        ]
        alerts = _detect_ddos(events, rule, window=30, threshold=10,
                              all_events=events, counter=0)
        assert len(alerts) == 1
        assert alerts[0].event_count >= 10

    def test_no_alert_below_threshold(self, rule):
        events = [
            make_event(
                event="rate_exceeded",
                timestamp=ts_offset(seconds=i),
                source="api-gw-01",
            )
            for i in range(5)
        ]
        alerts = _detect_ddos(events, rule, window=30, threshold=10,
                              all_events=events, counter=0)
        assert alerts == []

    def test_escalates_on_service_impact(self, rule):
        rate_events = [
            make_event(
                event="rate_exceeded",
                timestamp=ts_offset(seconds=i),
                source="api-gw-01",
                component="api",
                correlation_id=f"COR-{i}",
            )
            for i in range(15)
        ]
        status_event = make_event(
            event="service_status",
            timestamp=ts_offset(seconds=60),
            source="api-gw-01",
            key="status",
            value="degraded",
        )
        all_events = [*rate_events, status_event]
        alerts = _detect_ddos(rate_events, rule, window=30, threshold=10,
                              all_events=all_events, counter=0)
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"
        assert alerts[0].confidence == 0.98
        assert "service impact" in alerts[0].description


# ═══════════════════════════════════════════════════════════════════════════
#  Telemetry spoof detection
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectTelemetrySpoof:
    @pytest.fixture
    def rule(self):
        return {
            "id": "RULE-SPOOF-001",
            "name": "Telemetry Value Anomaly",
            "threat_type": "integrity_attack",
            "severity": "medium",
            "confidence": 0.75,
            "bounds": {
                "voltage": {"min": 180.0, "max": 280.0},
            },
            "delta": {
                "voltage": 50.0,
            },
            "response_hint": "flag_for_review",
        }

    def test_fires_on_out_of_bounds_values(self, rule):
        """3 voltage readings above 280V should trigger."""
        events = [
            make_event(
                event="telemetry_read",
                timestamp=ts_offset(seconds=i * 10),
                source="inv-01",
                key="voltage",
                value=str(300 + i * 10),
                correlation_id=f"COR-{i}",
            )
            for i in range(4)
        ]
        alerts = _detect_telemetry_spoof(events, rule, window=60, threshold=3, counter=0)
        assert len(alerts) == 1
        assert "out-of-range" in alerts[0].description

    def test_no_alert_within_bounds(self, rule):
        events = [
            make_event(
                event="telemetry_read",
                timestamp=ts_offset(seconds=i),
                source="inv-01",
                key="voltage",
                value=str(220 + i),
            )
            for i in range(10)
        ]
        alerts = _detect_telemetry_spoof(events, rule, window=60, threshold=3, counter=0)
        assert alerts == []

    def test_fires_on_large_delta(self, rule):
        """Delta > 50V between consecutive readings."""
        events = [
            make_event(
                event="telemetry_read",
                timestamp=ts_offset(seconds=0),
                source="inv-01",
                key="voltage",
                value="220",
            ),
            # Sudden jump to 220 → 280 = delta 60 > 50
            make_event(
                event="telemetry_read",
                timestamp=ts_offset(seconds=5),
                source="inv-01",
                key="voltage",
                value="280",
                correlation_id="COR-1",
            ),
            make_event(
                event="telemetry_read",
                timestamp=ts_offset(seconds=10),
                source="inv-01",
                key="voltage",
                value="220",
                correlation_id="COR-2",
            ),
            make_event(
                event="telemetry_read",
                timestamp=ts_offset(seconds=15),
                source="inv-01",
                key="voltage",
                value="280",
                correlation_id="COR-3",
            ),
        ]
        alerts = _detect_telemetry_spoof(events, rule, window=60, threshold=3, counter=0)
        assert len(alerts) == 1

    def test_non_numeric_values_skipped(self, rule):
        events = [
            make_event(
                event="telemetry_read",
                timestamp=ts_offset(seconds=i),
                source="inv-01",
                key="voltage",
                value="N/A",
            )
            for i in range(5)
        ]
        alerts = _detect_telemetry_spoof(events, rule, window=60, threshold=3, counter=0)
        assert alerts == []

    def test_severity_escalates_for_5_plus_anomalies(self, rule):
        """>=5 anomalies in window bumps severity to 'high'."""
        events = [
            make_event(
                event="telemetry_read",
                timestamp=ts_offset(seconds=i * 5),
                source="inv-01",
                key="voltage",
                value=str(300 + i),  # all out of bounds
                correlation_id=f"COR-{i}",
            )
            for i in range(8)
        ]
        # threshold=5 so alert fires when buf reaches 5 → severity escalates to "high"
        alerts = _detect_telemetry_spoof(events, rule, window=60, threshold=5, counter=0)
        assert len(alerts) == 1
        assert alerts[0].severity == "high"
        assert alerts[0].confidence == 0.90


# ═══════════════════════════════════════════════════════════════════════════
#  Unauthorized command detection
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectUnauthorizedCmd:
    @pytest.fixture
    def rule(self):
        return {
            "id": "RULE-UCMD-001",
            "name": "Unauthorized Command Execution",
            "threat_type": "integrity_attack",
            "severity": "critical",
            "confidence": 0.95,
            "match": {"event": "cmd_exec", "actor_not_in": ["operator", "admin"]},
            "response_hint": "block_actor_and_alert",
        }

    def test_fires_on_unknown_actor(self, rule):
        events = [
            make_event(event="cmd_exec", actor="guest", source="inv-01", component="edge"),
        ]
        alerts = _detect_unauthorized_cmd(events, rule, counter=0)
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"

    def test_no_alert_for_allowed_actor(self, rule):
        events = [
            make_event(event="cmd_exec", actor="operator", source="inv-01"),
        ]
        alerts = _detect_unauthorized_cmd(events, rule, counter=0)
        assert len(alerts) == 0

    def test_admin_allowed(self, rule):
        events = [
            make_event(event="cmd_exec", actor="Admin", source="inv-01"),
        ]
        alerts = _detect_unauthorized_cmd(events, rule, counter=0)
        assert len(alerts) == 0

    def test_empty_actor_triggers(self, rule):
        events = [
            make_event(event="cmd_exec", actor="", source="inv-01"),
        ]
        alerts = _detect_unauthorized_cmd(events, rule, counter=0)
        assert len(alerts) == 1

    def test_confidence_escalation_on_multiple(self, rule):
        """>=3 unauthorized commands → confidence 0.99."""
        events = [
            make_event(event="cmd_exec", actor="hacker", timestamp=ts_offset(seconds=i),
                       source="inv-01", component="edge", correlation_id=f"COR-{i}")
            for i in range(4)
        ]
        alerts = _detect_unauthorized_cmd(events, rule, counter=0)
        assert alerts[0].confidence == 0.99
        assert alerts[0].event_count == 4


# ═══════════════════════════════════════════════════════════════════════════
#  Outage detection
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectOutage:
    @pytest.fixture
    def rule(self):
        return {
            "id": "RULE-OUT-001",
            "name": "Service Outage",
            "threat_type": "outage",
            "severity": "high",
            "confidence": 0.90,
            "match": {
                "event": "service_status",
                "key": "status",
                "values": ["degraded", "down"],
            },
            "severity_override": [{"value": "down", "severity": "critical"}],
            "response_hint": "notify_oncall",
        }

    def test_fires_on_degraded_status(self, rule):
        events = [
            make_event(event="service_status", key="status", value="degraded",
                       source="db-01", component="db", correlation_id="COR-1"),
        ]
        alerts = _detect_outage(events, rule, window=60, threshold=1,
                                all_events=events, counter=0)
        assert len(alerts) == 1
        assert alerts[0].severity == "high"  # no severity_override for "degraded"

    def test_severity_override_for_down(self, rule):
        events = [
            make_event(event="service_status", key="status", value="down",
                       source="db-01", component="db", correlation_id="COR-1"),
        ]
        alerts = _detect_outage(events, rule, window=60, threshold=1,
                                all_events=events, counter=0)
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"

    def test_no_alert_for_healthy_status(self, rule):
        events = [
            make_event(event="service_status", key="status", value="ok",
                       source="db-01", component="db"),
        ]
        alerts = _detect_outage(events, rule, window=60, threshold=1,
                                all_events=events, counter=0)
        assert len(alerts) == 0

    def test_groups_by_source(self, rule):
        events = [
            make_event(event="service_status", key="status", value="down",
                       source="db-01", component="db",
                       timestamp=ts_offset(seconds=0), correlation_id="COR-A"),
            make_event(event="service_status", key="status", value="degraded",
                       source="db-02", component="db",
                       timestamp=ts_offset(seconds=5), correlation_id="COR-B"),
        ]
        alerts = _detect_outage(events, rule, window=60, threshold=1,
                                all_events=events, counter=0)
        assert len(alerts) == 2
        sources = {a.source for a in alerts}
        assert sources == {"db-01", "db-02"}
