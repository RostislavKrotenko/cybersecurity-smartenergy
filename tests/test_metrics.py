"""Tests for src.analyzer.metrics — resilience metric computation."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src.analyzer.metrics import (
    RESULTS_CSV_COLUMNS,
    PolicyMetrics,
    _merge_intervals,
    compute,
)
from tests.conftest import make_incident

# ═══════════════════════════════════════════════════════════════════════════
#  _merge_intervals
# ═══════════════════════════════════════════════════════════════════════════

class TestMergeIntervals:
    def _dt(self, minutes: int) -> datetime:
        return datetime(2026, 2, 26, 10, minutes, 0, tzinfo=UTC)

    def test_empty_list(self):
        assert _merge_intervals([]) == []

    def test_single_interval(self):
        iv = [(self._dt(0), self._dt(10))]
        merged = _merge_intervals(iv)
        assert len(merged) == 1
        assert merged[0] == iv[0]

    def test_non_overlapping(self):
        iv = [
            (self._dt(0), self._dt(5)),
            (self._dt(10), self._dt(15)),
        ]
        merged = _merge_intervals(iv)
        assert len(merged) == 2

    def test_overlapping_merged(self):
        iv = [
            (self._dt(0), self._dt(10)),
            (self._dt(5), self._dt(15)),
        ]
        merged = _merge_intervals(iv)
        assert len(merged) == 1
        assert merged[0] == (self._dt(0), self._dt(15))

    def test_adjacent_intervals_merged(self):
        """Intervals that touch exactly at boundary are merged."""
        iv = [
            (self._dt(0), self._dt(10)),
            (self._dt(10), self._dt(20)),
        ]
        merged = _merge_intervals(iv)
        assert len(merged) == 1
        assert merged[0] == (self._dt(0), self._dt(20))

    def test_nested_interval(self):
        iv = [
            (self._dt(0), self._dt(30)),
            (self._dt(5), self._dt(10)),
        ]
        merged = _merge_intervals(iv)
        assert len(merged) == 1
        assert merged[0] == (self._dt(0), self._dt(30))

    def test_unsorted_input(self):
        iv = [
            (self._dt(10), self._dt(20)),
            (self._dt(0), self._dt(5)),
        ]
        merged = _merge_intervals(iv)
        assert len(merged) == 2
        assert merged[0][0] < merged[1][0]

    def test_multiple_overlapping_chains(self):
        iv = [
            (self._dt(0), self._dt(10)),
            (self._dt(5), self._dt(15)),
            (self._dt(14), self._dt(25)),
            (self._dt(30), self._dt(40)),
        ]
        merged = _merge_intervals(iv)
        assert len(merged) == 2
        assert merged[0] == (self._dt(0), self._dt(25))
        assert merged[1] == (self._dt(30), self._dt(40))


# ═══════════════════════════════════════════════════════════════════════════
#  compute()
# ═══════════════════════════════════════════════════════════════════════════

class TestCompute:
    def test_no_incidents_100_percent_availability(self):
        m = compute([], "baseline", horizon_sec=3600)
        assert m.policy == "baseline"
        assert m.availability_pct == 100.0
        assert m.total_downtime_hr == 0.0
        assert m.incidents_total == 0

    def test_single_high_incident(self):
        inc = make_incident(
            severity="high",
            start_ts="2026-02-26T10:00:00Z",
            detect_ts="2026-02-26T10:00:30Z",
            recover_ts="2026-02-26T10:02:30Z",
            mttd_sec=30.0,
            mttr_sec=120.0,
        )
        m = compute([inc], "baseline", horizon_sec=3600)
        assert m.incidents_total == 1
        assert m.incidents_by_severity["high"] == 1
        assert m.mean_mttd_min == round(30.0 / 60, 2)
        assert m.mean_mttr_min == round(120.0 / 60, 2)
        # Downtime = recover - start = 150s = 0.0417h
        assert m.total_downtime_hr == pytest.approx(150 / 3600, abs=0.001)
        assert m.availability_pct < 100.0

    def test_critical_incident_counts_as_downtime(self):
        inc = make_incident(
            severity="critical",
            start_ts="2026-02-26T10:00:00Z",
            detect_ts="2026-02-26T10:01:00Z",
            recover_ts="2026-02-26T10:31:00Z",
            mttd_sec=60.0,
            mttr_sec=1800.0,
        )
        m = compute([inc], "minimal", horizon_sec=7200)
        # Downtime = 31 minutes = 1860 seconds
        expected_dt_hr = 1860 / 3600
        assert m.total_downtime_hr == pytest.approx(expected_dt_hr, abs=0.001)
        expected_avail = (1 - 1860 / 7200) * 100
        assert m.availability_pct == pytest.approx(expected_avail, abs=0.1)

    def test_low_severity_no_downtime(self):
        inc = make_incident(
            severity="low",
            start_ts="2026-02-26T10:00:00Z",
            detect_ts="2026-02-26T10:10:00Z",
            recover_ts="2026-02-26T10:20:00Z",
            mttd_sec=600.0,
            mttr_sec=600.0,
        )
        m = compute([inc], "baseline", horizon_sec=3600)
        # low severity → not in {"high", "critical"} → no downtime
        assert m.total_downtime_hr == 0.0
        assert m.availability_pct == 100.0
        assert m.incidents_total == 1

    def test_medium_severity_no_downtime(self):
        inc = make_incident(
            severity="medium",
            mttd_sec=60.0,
            mttr_sec=120.0,
        )
        m = compute([inc], "baseline", horizon_sec=3600)
        assert m.total_downtime_hr == 0.0

    def test_overlapping_high_incidents_merged(self):
        inc1 = make_incident(
            severity="high",
            start_ts="2026-02-26T10:00:00Z",
            detect_ts="2026-02-26T10:00:30Z",
            recover_ts="2026-02-26T10:10:00Z",
            mttd_sec=30.0,
            mttr_sec=570.0,
        )
        inc2 = make_incident(
            severity="high",
            start_ts="2026-02-26T10:05:00Z",
            detect_ts="2026-02-26T10:05:30Z",
            recover_ts="2026-02-26T10:15:00Z",
            mttd_sec=30.0,
            mttr_sec=570.0,
        )
        m = compute([inc1, inc2], "baseline", horizon_sec=7200)
        # Merged interval: 10:00 → 10:15 = 900s = 0.25h
        assert m.total_downtime_hr == pytest.approx(900 / 3600, abs=0.001)
        assert m.incidents_total == 2

    def test_zero_horizon_gives_100_pct(self):
        inc = make_incident(severity="high")
        m = compute([inc], "baseline", horizon_sec=0)
        assert m.availability_pct == 100.0

    def test_incidents_by_threat_counted(self):
        inc1 = make_incident(threat_type="credential_attack", severity="low", mttd_sec=10, mttr_sec=10)
        inc2 = make_incident(threat_type="credential_attack", severity="low", mttd_sec=20, mttr_sec=20)
        inc3 = make_incident(threat_type="outage", severity="low", mttd_sec=30, mttr_sec=30)
        m = compute([inc1, inc2, inc3], "baseline", horizon_sec=3600)
        assert m.incidents_by_threat["credential_attack"] == 2
        assert m.incidents_by_threat["outage"] == 1

    def test_mttd_mttr_averages(self):
        inc1 = make_incident(severity="low", mttd_sec=60.0, mttr_sec=120.0)
        inc2 = make_incident(severity="low", mttd_sec=120.0, mttr_sec=240.0)
        m = compute([inc1, inc2], "baseline", horizon_sec=3600)
        assert m.mean_mttd_min == round((60 + 120) / 2 / 60, 2)  # 1.5
        assert m.mean_mttr_min == round((120 + 240) / 2 / 60, 2)  # 3.0


# ═══════════════════════════════════════════════════════════════════════════
#  PolicyMetrics serialisation
# ═══════════════════════════════════════════════════════════════════════════

class TestPolicyMetricsSerialization:
    def test_csv_header_matches_columns(self):
        header = PolicyMetrics.csv_header()
        assert header == ",".join(RESULTS_CSV_COLUMNS)

    def test_to_csv_row_default_values(self):
        m = PolicyMetrics(policy="test")
        row = m.to_csv_row()
        parts = row.split(",")
        assert parts[0] == "test"
        assert parts[1] == "100.00"  # availability_pct
        assert int(parts[5]) == 0  # incidents_total

    def test_to_csv_row_with_data(self):
        m = PolicyMetrics(
            policy="standard",
            availability_pct=95.50,
            total_downtime_hr=0.1234,
            mean_mttd_min=2.50,
            mean_mttr_min=10.00,
            incidents_total=3,
            incidents_by_severity={"critical": 1, "high": 2},
            incidents_by_threat={"credential_attack": 2, "outage": 1},
        )
        row = m.to_csv_row()
        parts = row.split(",")
        assert parts[0] == "standard"
        assert parts[1] == "95.50"
        assert parts[6] == "1"   # critical
        assert parts[7] == "2"   # high
        assert parts[10] == "2"  # credential_attack (index 10 per RESULTS_CSV_COLUMNS)
