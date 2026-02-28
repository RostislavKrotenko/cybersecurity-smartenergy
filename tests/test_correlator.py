"""Tests for src.analyzer.correlator — alert-to-incident grouping."""

from __future__ import annotations

import pytest

from src.analyzer.correlator import (
    _build_incident,
    _extract_cor_ids,
    _max_sev,
    correlate,
)
from tests.conftest import make_alert, ts_offset

# ═══════════════════════════════════════════════════════════════════════════
#  Helper functions
# ═══════════════════════════════════════════════════════════════════════════

class TestHelpers:
    def test_extract_cor_ids_single(self):
        ids = _extract_cor_ids("COR-001")
        assert ids == {"COR-001"}

    def test_extract_cor_ids_multiple(self):
        ids = _extract_cor_ids("COR-001;COR-002;2026-02-26T10:00:00Z")
        assert ids == {"COR-001", "COR-002"}

    def test_extract_cor_ids_none(self):
        ids = _extract_cor_ids("2026-02-26T10:00:00Z;2026-02-26T10:01:00Z")
        assert ids == set()

    def test_extract_cor_ids_empty(self):
        ids = _extract_cor_ids("")
        assert ids == set()

    def test_max_sev_critical_wins(self):
        assert _max_sev("low", "critical") == "critical"

    def test_max_sev_high_over_medium(self):
        assert _max_sev("medium", "high") == "high"

    def test_max_sev_same(self):
        assert _max_sev("low", "low") == "low"


# ═══════════════════════════════════════════════════════════════════════════
#  correlate() — grouping logic
# ═══════════════════════════════════════════════════════════════════════════

class TestCorrelate:
    def test_empty_alerts_returns_empty(self):
        assert correlate([], "baseline") == []

    def test_single_alert_one_incident(self):
        alerts = [make_alert(event_ids="COR-001")]
        incidents = correlate(alerts, "baseline")
        assert len(incidents) == 1
        assert incidents[0].policy == "baseline"
        assert incidents[0].threat_type == "credential_attack"

    def test_alerts_same_cor_id_grouped(self):
        alerts = [
            make_alert(alert_id="ALR-0001", event_ids="COR-001", timestamp=ts_offset(seconds=0)),
            make_alert(alert_id="ALR-0002", event_ids="COR-001", timestamp=ts_offset(seconds=30)),
        ]
        incidents = correlate(alerts, "baseline")
        assert len(incidents) == 1
        assert incidents[0].event_count == 10  # 5+5

    def test_different_cor_ids_separate_incidents(self):
        alerts = [
            make_alert(alert_id="ALR-0001", event_ids="COR-001", timestamp=ts_offset(seconds=0)),
            make_alert(alert_id="ALR-0002", event_ids="COR-002", timestamp=ts_offset(seconds=30)),
        ]
        incidents = correlate(alerts, "baseline")
        assert len(incidents) == 2

    def test_no_cor_id_grouped_by_time_component_threat(self):
        alerts = [
            make_alert(
                alert_id="ALR-0001",
                event_ids="2026-02-26T10:00:00Z",
                timestamp=ts_offset(seconds=0),
                component="api",
                threat_type="credential_attack",
            ),
            make_alert(
                alert_id="ALR-0002",
                event_ids="2026-02-26T10:01:00Z",
                timestamp=ts_offset(seconds=60),
                component="api",
                threat_type="credential_attack",
            ),
        ]
        incidents = correlate(alerts, "baseline", merge_window_sec=120)
        # Same component + threat_type within 120s → merged
        assert len(incidents) == 1

    def test_no_cor_id_different_components_separate(self):
        alerts = [
            make_alert(
                alert_id="ALR-0001",
                event_ids="ts1",
                timestamp=ts_offset(seconds=0),
                component="api",
                threat_type="credential_attack",
            ),
            make_alert(
                alert_id="ALR-0002",
                event_ids="ts2",
                timestamp=ts_offset(seconds=10),
                component="db",
                threat_type="credential_attack",
            ),
        ]
        incidents = correlate(alerts, "baseline", merge_window_sec=120)
        assert len(incidents) == 2

    def test_no_cor_id_outside_merge_window_separate(self):
        alerts = [
            make_alert(
                alert_id="ALR-0001",
                event_ids="ts1",
                timestamp=ts_offset(seconds=0),
                component="api",
                threat_type="credential_attack",
            ),
            make_alert(
                alert_id="ALR-0002",
                event_ids="ts2",
                timestamp=ts_offset(seconds=300),
                component="api",
                threat_type="credential_attack",
            ),
        ]
        incidents = correlate(alerts, "baseline", merge_window_sec=120)
        assert len(incidents) == 2

    def test_incidents_sorted_by_start_ts(self):
        alerts = [
            make_alert(alert_id="ALR-0002", event_ids="COR-002", timestamp=ts_offset(seconds=60)),
            make_alert(alert_id="ALR-0001", event_ids="COR-001", timestamp=ts_offset(seconds=0)),
        ]
        incidents = correlate(alerts, "baseline")
        assert incidents[0].start_ts <= incidents[1].start_ts

    def test_policy_modifiers_affect_timing(self):
        alerts = [make_alert(event_ids="COR-001", threat_type="credential_attack")]
        # Baseline: mttd=30, mttr=120
        inc_baseline = correlate(alerts, "baseline")[0]

        # With halved mttd
        mods = {"credential_attack": {"mttd_multiplier": 0.5, "mttr_multiplier": 0.5}}
        inc_fast = correlate(alerts, "standard", policy_modifiers=mods)[0]

        assert inc_fast.mttd_sec < inc_baseline.mttd_sec
        assert inc_fast.mttr_sec < inc_baseline.mttr_sec


# ═══════════════════════════════════════════════════════════════════════════
#  _build_incident
# ═══════════════════════════════════════════════════════════════════════════

class TestBuildIncident:
    def test_basic_incident_fields(self):
        group = [make_alert(
            alert_id="ALR-0001",
            threat_type="credential_attack",
            severity="high",
            confidence=0.85,
            timestamp="2026-02-26T10:00:00Z",
            component="api",
            event_count=5,
            description="test brute force",
            response_hint="block_ip",
        )]
        inc = _build_incident(group, idx=1, policy="baseline", pm={})
        assert inc.incident_id == "INC-001"
        assert inc.policy == "baseline"
        assert inc.threat_type == "credential_attack"
        assert inc.severity == "high"
        assert inc.start_ts == "2026-02-26T10:00:00Z"
        assert inc.mttd_sec == 30.0  # _BASE_TIMING default
        assert inc.mttr_sec == 120.0

    def test_severity_escalated_to_max(self):
        group = [
            make_alert(severity="medium", confidence=0.8, timestamp=ts_offset(seconds=0)),
            make_alert(severity="critical", confidence=0.9, timestamp=ts_offset(seconds=10)),
        ]
        inc = _build_incident(group, idx=1, policy="test", pm={})
        assert inc.severity == "critical"

    def test_impact_score_formula(self):
        group = [make_alert(
            severity="critical",
            confidence=0.90,
            threat_type="credential_attack",
        )]
        # impact = SEV_IMPACT["critical"] * avg_confidence * impact_multiplier
        # = 1.0 * 0.90 * 1.0 = 0.90
        inc = _build_incident(group, idx=1, policy="test", pm={})
        assert inc.impact_score == pytest.approx(0.90, abs=0.01)

    def test_impact_score_with_policy_modifier(self):
        group = [make_alert(
            severity="high",
            confidence=0.80,
            threat_type="credential_attack",
        )]
        pm = {"credential_attack": {"impact_multiplier": 0.5}}
        # impact = 0.7 * 0.80 * 0.5 = 0.28
        inc = _build_incident(group, idx=1, policy="test", pm=pm)
        assert inc.impact_score == pytest.approx(0.28, abs=0.01)

    def test_impact_score_capped_at_one(self):
        group = [make_alert(
            severity="critical",
            confidence=1.0,
            threat_type="credential_attack",
        )]
        pm = {"credential_attack": {"impact_multiplier": 5.0}}
        inc = _build_incident(group, idx=1, policy="test", pm=pm)
        assert inc.impact_score <= 1.0

    def test_mttd_mttr_with_modifiers(self):
        group = [make_alert(threat_type="availability_attack")]
        # Base: mttd=15, mttr=180
        pm = {"availability_attack": {"mttd_multiplier": 2.0, "mttr_multiplier": 0.5}}
        inc = _build_incident(group, idx=1, policy="test", pm=pm)
        assert inc.mttd_sec == 30.0   # 15 * 2
        assert inc.mttr_sec == 90.0   # 180 * 0.5

    def test_detect_and_recover_timestamps(self):
        group = [make_alert(
            timestamp="2026-02-26T10:00:00Z",
            threat_type="credential_attack",
        )]
        # mttd=30, mttr=120
        inc = _build_incident(group, idx=1, policy="test", pm={})
        assert inc.detect_ts == "2026-02-26T10:00:30Z"
        assert inc.recover_ts == "2026-02-26T10:02:30Z"

    def test_components_joined(self):
        group = [
            make_alert(component="api", timestamp=ts_offset(seconds=0)),
            make_alert(component="db", timestamp=ts_offset(seconds=5)),
            make_alert(component="api", timestamp=ts_offset(seconds=10)),
        ]
        inc = _build_incident(group, idx=1, policy="test", pm={})
        assert "api" in inc.component
        assert "db" in inc.component

    def test_unknown_threat_type_uses_defaults(self):
        group = [make_alert(threat_type="unknown_threat")]
        inc = _build_incident(group, idx=1, policy="test", pm={})
        # Fallback: mttd=30, mttr=120
        assert inc.mttd_sec == 30.0
        assert inc.mttr_sec == 120.0
