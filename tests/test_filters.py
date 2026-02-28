"""Тести фільтрів: дедуплікація та валідація."""

from __future__ import annotations

from src.normalizer.filters import deduplicate, validate_event
from tests.conftest import make_event, ts_offset


class TestDeduplicate:
    def test_empty_list(self):
        assert deduplicate([]) == []

    def test_no_duplicates_unchanged(self):
        events = [
            make_event(timestamp=ts_offset(seconds=0), source="a", event="e1", key="k", value="v1"),
            make_event(timestamp=ts_offset(seconds=5), source="b", event="e2", key="k", value="v2"),
        ]
        result = deduplicate(events, window_sec=2)
        assert len(result) == 2

    def test_exact_duplicate_within_window_removed(self):
        events = [
            make_event(timestamp=ts_offset(seconds=0), source="a", event="e", key="k", value="v"),
            make_event(timestamp=ts_offset(seconds=1), source="a", event="e", key="k", value="v"),
        ]
        result = deduplicate(events, window_sec=2)
        assert len(result) == 1  # second removed

    def test_duplicate_outside_window_kept(self):
        events = [
            make_event(timestamp=ts_offset(seconds=0), source="a", event="e", key="k", value="v"),
            make_event(timestamp=ts_offset(seconds=5), source="a", event="e", key="k", value="v"),
        ]
        result = deduplicate(events, window_sec=2)
        assert len(result) == 2

    def test_different_source_not_duplicate(self):
        events = [
            make_event(timestamp=ts_offset(seconds=0), source="a", event="e", key="k", value="v"),
            make_event(timestamp=ts_offset(seconds=1), source="b", event="e", key="k", value="v"),
        ]
        result = deduplicate(events, window_sec=2)
        assert len(result) == 2

    def test_different_event_not_duplicate(self):
        events = [
            make_event(timestamp=ts_offset(seconds=0), source="a", event="e1", key="k", value="v"),
            make_event(timestamp=ts_offset(seconds=1), source="a", event="e2", key="k", value="v"),
        ]
        result = deduplicate(events, window_sec=2)
        assert len(result) == 2

    def test_different_key_not_duplicate(self):
        events = [
            make_event(timestamp=ts_offset(seconds=0), source="a", event="e", key="k1", value="v"),
            make_event(timestamp=ts_offset(seconds=1), source="a", event="e", key="k2", value="v"),
        ]
        result = deduplicate(events, window_sec=2)
        assert len(result) == 2

    def test_different_value_not_duplicate(self):
        events = [
            make_event(timestamp=ts_offset(seconds=0), source="a", event="e", key="k", value="v1"),
            make_event(timestamp=ts_offset(seconds=1), source="a", event="e", key="k", value="v2"),
        ]
        result = deduplicate(events, window_sec=2)
        assert len(result) == 2

    def test_window_zero_removes_exact_same_ts(self):
        events = [
            make_event(timestamp=ts_offset(seconds=0), source="a", event="e", key="k", value="v"),
            make_event(timestamp=ts_offset(seconds=0), source="a", event="e", key="k", value="v"),
        ]
        result = deduplicate(events, window_sec=0)
        assert len(result) == 1

    def test_chain_of_duplicates(self):
        """Кілька дублікатів поспіль — лише перший залишається."""
        events = [
            make_event(timestamp=ts_offset(seconds=i), source="a", event="e", key="k", value="v")
            for i in range(5)
        ]
        result = deduplicate(events, window_sec=10)
        assert len(result) == 1

    def test_duplicate_after_gap_creates_new_chain(self):
        """Після проміжку > window дублікат зберігається."""
        events = [
            make_event(timestamp=ts_offset(seconds=0), source="a", event="e", key="k", value="v"),
            make_event(timestamp=ts_offset(seconds=1), source="a", event="e", key="k", value="v"),
            make_event(timestamp=ts_offset(seconds=10), source="a", event="e", key="k", value="v"),
            make_event(timestamp=ts_offset(seconds=11), source="a", event="e", key="k", value="v"),
        ]
        result = deduplicate(events, window_sec=2)
        assert len(result) == 2  # ts=0 and ts=10


class TestValidateEvent:
    def test_valid_event_no_warnings(self):
        ev = make_event(severity="high", component="api", timestamp="2026-02-26T10:00:00Z")
        warnings = validate_event(ev)
        assert warnings == []

    def test_unknown_severity(self):
        ev = make_event(severity="extreme")
        warnings = validate_event(ev)
        assert any("severity" in w for w in warnings)

    def test_unknown_component(self):
        ev = make_event(component="firewall")
        warnings = validate_event(ev)
        assert any("component" in w for w in warnings)

    def test_empty_timestamp(self):
        ev = make_event(timestamp="")
        warnings = validate_event(ev)
        assert any("timestamp" in w for w in warnings)

    def test_multiple_warnings(self):
        ev = make_event(severity="extreme", component="firewall", timestamp="")
        warnings = validate_event(ev)
        assert len(warnings) == 3

    def test_all_valid_severities(self):
        for sev in ("low", "medium", "high", "critical"):
            ev = make_event(severity=sev, component="api")
            assert validate_event(ev) == []

    def test_all_valid_components(self):
        for comp in ("edge", "api", "db", "ui", "collector", "inverter", "network", "unknown"):
            ev = make_event(component=comp, severity="low")
            assert validate_event(ev) == []
