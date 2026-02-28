"""End-to-end integration tests: events → detector → correlator → metrics."""

from __future__ import annotations

import pytest

from src.analyzer.correlator import correlate
from src.analyzer.detector import detect
from src.analyzer.metrics import compute
from tests.conftest import make_event, ts_offset


class TestDetectorToCorrelatorToMetrics:
    """Full pipeline: generate events → detect alerts → correlate → compute metrics."""

    @pytest.fixture
    def brute_force_events(self):
        """10 auth_failure events from same IP in 30 seconds."""
        return [
            make_event(
                event="auth_failure",
                timestamp=ts_offset(seconds=i * 3),
                ip="10.0.0.99",
                source="api-gw-01",
                component="api",
                severity="medium",
                correlation_id=f"COR-BF-{i:03d}",
            )
            for i in range(10)
        ]

    @pytest.fixture
    def full_rules_cfg(self):
        return {
            "rules": [
                {
                    "id": "RULE-BF-001",
                    "name": "Brute-Force Authentication",
                    "threat_type": "credential_attack",
                    "enabled": True,
                    "match": {"event": "auth_failure"},
                    "window_sec": 60,
                    "threshold": 5,
                    "severity": "high",
                    "confidence": 0.85,
                    "response_hint": "block_ip",
                },
                {
                    "id": "RULE-DDOS-001",
                    "name": "DDoS Flood",
                    "threat_type": "availability_attack",
                    "enabled": True,
                    "match": {"event": "rate_exceeded"},
                    "window_sec": 30,
                    "threshold": 10,
                    "severity": "critical",
                    "confidence": 0.90,
                    "response_hint": "rate_limit_ip_range",
                },
                {
                    "id": "RULE-SPOOF-001",
                    "name": "Telemetry Anomaly",
                    "threat_type": "integrity_attack",
                    "enabled": True,
                    "match": {"event": "telemetry_read"},
                    "bounds": {"voltage": {"min": 180, "max": 280}},
                    "delta": {"voltage": 50},
                    "window_sec": 60,
                    "threshold": 3,
                    "severity": "medium",
                    "confidence": 0.75,
                    "response_hint": "flag_for_review",
                },
            ]
        }

    def test_brute_force_e2e(self, brute_force_events, full_rules_cfg):
        # Step 1: Detect
        alerts = detect(brute_force_events, full_rules_cfg)
        assert len(alerts) >= 1
        assert alerts[0].threat_type == "credential_attack"

        # Step 2: Correlate
        incidents = correlate(alerts, "baseline")
        assert len(incidents) >= 1
        inc = incidents[0]
        assert inc.threat_type == "credential_attack"
        assert inc.mttd_sec > 0
        assert inc.mttr_sec > 0

        # Step 3: Metrics
        metrics = compute(incidents, "baseline", horizon_sec=3600)
        assert metrics.incidents_total >= 1
        assert metrics.incidents_by_threat.get("credential_attack", 0) >= 1
        assert metrics.mean_mttd_min > 0
        assert metrics.mean_mttr_min > 0

    def test_mixed_attacks_e2e(self, full_rules_cfg):
        events = []
        # Brute force: 6 auth failures
        for i in range(6):
            events.append(make_event(
                event="auth_failure",
                timestamp=ts_offset(seconds=i * 5),
                ip="10.0.0.1", source="api-gw-01", component="api",
                correlation_id=f"COR-BF-{i}",
            ))
        # DDoS: 12 rate_exceeded
        for i in range(12):
            events.append(make_event(
                event="rate_exceeded",
                timestamp=ts_offset(seconds=100 + i * 2),
                source="api-gw-01", component="api",
                correlation_id=f"COR-DD-{i}",
            ))
        # Spoof: 4 out-of-range voltage readings
        for i in range(4):
            events.append(make_event(
                event="telemetry_read",
                timestamp=ts_offset(seconds=200 + i * 10),
                source="inv-01", component="edge", key="voltage",
                value=str(350 + i * 10),
                correlation_id=f"COR-SP-{i}",
            ))

        events.sort(key=lambda e: e.timestamp)

        # Detect
        alerts = detect(events, full_rules_cfg)
        assert len(alerts) >= 3  # at least one per threat type

        # Correlate
        incidents = correlate(alerts, "baseline")
        assert len(incidents) >= 1  # groups may merge some

        # Metrics
        metrics = compute(incidents, "baseline", horizon_sec=3600)
        assert metrics.incidents_total >= 1
        assert metrics.availability_pct <= 100.0

    def test_policy_comparison_e2e(self, brute_force_events, full_rules_cfg):
        """Standard policy should yield better metrics than minimal."""
        # Minimal — higher multipliers = slower detection
        minimal_mods = {"credential_attack": {
            "mttd_multiplier": 1.5, "mttr_multiplier": 1.5,
            "threshold_multiplier": 1.0, "impact_multiplier": 1.2,
        }}
        # Standard — lower multipliers = faster detection
        standard_mods = {"credential_attack": {
            "mttd_multiplier": 0.5, "mttr_multiplier": 0.5,
            "threshold_multiplier": 1.0, "impact_multiplier": 0.6,
        }}

        alerts_min = detect(brute_force_events, full_rules_cfg, policy_modifiers=minimal_mods)
        alerts_std = detect(brute_force_events, full_rules_cfg, policy_modifiers=standard_mods)

        incidents_min = correlate(alerts_min, "minimal", policy_modifiers=minimal_mods)
        incidents_std = correlate(alerts_std, "standard", policy_modifiers=standard_mods)

        metrics_min = compute(incidents_min, "minimal", horizon_sec=3600)
        metrics_std = compute(incidents_std, "standard", horizon_sec=3600)

        # Standard should have lower MTTD (faster detection)
        if incidents_min and incidents_std:
            assert metrics_std.mean_mttd_min <= metrics_min.mean_mttd_min

    def test_no_events_produces_clean_metrics(self, full_rules_cfg):
        alerts = detect([], full_rules_cfg)
        assert alerts == []
        incidents = correlate(alerts, "baseline")
        assert incidents == []
        metrics = compute(incidents, "baseline", horizon_sec=3600)
        assert metrics.availability_pct == 100.0
        assert metrics.incidents_total == 0
