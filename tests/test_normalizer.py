"""Test 5 — Normalizer: parsing + quarantine."""

from __future__ import annotations

from datetime import UTC
from pathlib import Path

import pytest
import yaml

from src.contracts.event import Event
from src.normalizer.filters import deduplicate, validate_event
from src.normalizer.parser import build_profiles, parse_line, select_profile

ROOT = Path(__file__).resolve().parent.parent
MAPPING_PATH = ROOT / "config" / "mapping.yaml"


@pytest.fixture(scope="module")
def profiles():
    with open(MAPPING_PATH) as f:
        mapping = yaml.safe_load(f)
    return build_profiles(mapping)


@pytest.fixture()
def api_profile(profiles):
    p = select_profile(profiles, "sample_api.log")
    assert p is not None, "No profile matched 'sample_api.log'"
    return p


@pytest.fixture()
def auth_profile(profiles):
    p = select_profile(profiles, "sample_auth.log")
    assert p is not None, "No profile matched 'sample_auth.log'"
    return p


# ═════════════════════════════════════════════════════════════════════════════
#  Parsing: successful lines
# ═════════════════════════════════════════════════════════════════════════════


class TestParserSuccess:
    """Raw log lines that should parse into Events."""

    def test_api_info_line(self, api_profile):
        line = "2026-09-10 12:31:02 INFO api-gw-01 GET /api/v1/telemetry 200"
        result = parse_line(line, api_profile, UTC)
        assert isinstance(result, Event)
        assert result.source == "api-gw-01"
        assert result.component == "api"
        assert result.timestamp.endswith("Z")

    def test_api_error_line(self, api_profile):
        line = "2026-09-10 12:32:00 ERROR api-gw-01 auth failure for user admin from 10.0.5.99"
        result = parse_line(line, api_profile, UTC)
        assert isinstance(result, Event)
        # ERROR level should map to a higher severity
        assert result.severity in ("high", "critical", "medium")

    def test_auth_syslog_line(self, auth_profile):
        line = "Feb 26 10:05:01 auth-server sshd[1234]: Failed password for admin from 10.0.5.55 port 22"
        result = parse_line(line, auth_profile, UTC)
        assert isinstance(result, Event)
        assert "auth" in result.component or result.source == "auth-server"


# ═════════════════════════════════════════════════════════════════════════════
#  Parsing: quarantine (unparseable lines)
# ═════════════════════════════════════════════════════════════════════════════


class TestParserQuarantine:
    """Lines that should fail parsing and go to quarantine."""

    def test_empty_line(self, api_profile):
        result = parse_line("", api_profile, UTC)
        assert isinstance(result, tuple)
        assert result[1] == "empty_line"

    def test_garbage_line(self, api_profile):
        result = parse_line("this is not a log line at all", api_profile, UTC)
        assert isinstance(result, tuple)
        assert result[1] == "parse_error"

    def test_whitespace_only(self, api_profile):
        result = parse_line("    \t  ", api_profile, UTC)
        assert isinstance(result, tuple)
        assert result[1] == "empty_line"


# ═════════════════════════════════════════════════════════════════════════════
#  Filters: dedup + validate
# ═════════════════════════════════════════════════════════════════════════════


class TestDedup:
    def test_removes_within_window(self):
        from tests.conftest import make_event, ts_offset

        base = "2026-02-26T10:00:00Z"
        e1 = make_event(timestamp=base, source="m1", event="x", key="k", value="v")
        e2 = make_event(timestamp=ts_offset(base, 1), source="m1", event="x", key="k", value="v")
        result = deduplicate([e1, e2], window_sec=2)
        assert len(result) == 1

    def test_keeps_beyond_window(self):
        from tests.conftest import make_event, ts_offset

        base = "2026-02-26T10:00:00Z"
        e1 = make_event(timestamp=base, source="m1", event="x", key="k", value="v")
        e2 = make_event(timestamp=ts_offset(base, 5), source="m1", event="x", key="k", value="v")
        result = deduplicate([e1, e2], window_sec=2)
        assert len(result) == 2

    def test_different_fingerprint_kept(self):
        from tests.conftest import make_event

        e1 = make_event(source="m1", event="a", key="k", value="v")
        e2 = make_event(source="m2", event="a", key="k", value="v")
        result = deduplicate([e1, e2], window_sec=2)
        assert len(result) == 2


class TestValidateEvent:
    def test_valid_event(self):
        from tests.conftest import make_event

        ev = make_event(severity="low", component="edge")
        assert validate_event(ev) == []

    def test_unknown_severity(self):
        from tests.conftest import make_event

        ev = make_event(severity="unknown_sev")
        warnings = validate_event(ev)
        assert any("severity" in w for w in warnings)

    def test_unknown_component(self):
        from tests.conftest import make_event

        ev = make_event(component="satellite")
        warnings = validate_event(ev)
        assert any("component" in w for w in warnings)

    def test_empty_timestamp(self):
        from tests.conftest import make_event

        ev = make_event(timestamp="")
        warnings = validate_event(ev)
        assert any("timestamp" in w for w in warnings)
