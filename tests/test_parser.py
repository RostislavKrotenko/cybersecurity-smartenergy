"""Tests for src.normalizer.parser — raw log line parsing."""

from __future__ import annotations

import re
from datetime import UTC

import pytest

from src.contracts.event import Event
from src.normalizer.parser import (
    Profile,
    _detect_component,
    _detect_event,
    _detect_severity,
    _extract_actor,
    _extract_ip,
    _extract_kv,
    build_profiles,
    parse_line,
    select_profile,
)

# ═══════════════════════════════════════════════════════════════════════════
#  Fixtures — minimal API-like profile
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture
def api_profile() -> Profile:
    """A minimal profile matching API gateway logs."""
    return Profile(
        name="api",
        file_pattern=re.compile(r"api", re.IGNORECASE),
        line_regex=re.compile(
            r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
            r"(?P<level>\w+)\s+(?P<host>\S+)\s+(?P<msg>.+)$"
        ),
        timestamp_format="iso_space",
        year_default=None,
        source_field="host",
        level_field="level",
        message_field="msg",
        severity_map={
            "debug": "low",
            "info": "low",
            "warn": "medium",
            "warning": "medium",
            "error": "high",
            "critical": "critical",
        },
        severity_from_message={
            "critical": ["fatal", "panic"],
            "high": ["denied", "refused"],
        },
        event_rules=[
            (re.compile(r"(?:GET|POST|PUT|DELETE)\s+/"), "http_request", "api,http"),
            (re.compile(r"(?i)rate.?limit|throttl"), "rate_exceeded", "api,rate"),
            (re.compile(r"(?i)auth.*fail|login.*fail"), "auth_failure", "auth"),
            (re.compile(r"(?i)auth.*success|login.*success"), "auth_success", "auth"),
        ],
        component_rules=[
            (re.compile(r"api", re.IGNORECASE), "api"),
            (re.compile(r"db", re.IGNORECASE), "db"),
        ],
        ip_regex=re.compile(r"(?:from |src[= ]|client[= ])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
        actor_regex=re.compile(r"user[= ](\S+)"),
        kv_regex=re.compile(r"(\w+)[= ]([^\s,]+)"),
        defaults={
            "source": "unknown",
            "component": "unknown",
            "event": "raw_log",
            "severity": "low",
        },
    )


@pytest.fixture
def syslog_profile() -> Profile:
    """A minimal syslog-style profile."""
    return Profile(
        name="syslog",
        file_pattern=re.compile(r"syslog|messages", re.IGNORECASE),
        line_regex=re.compile(
            r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
            r"(?P<host>\S+)\s+(?P<msg>.+)$"
        ),
        timestamp_format="syslog",
        year_default=2026,
        source_field="host",
        level_field=None,
        message_field="msg",
        severity_map={},
        severity_from_message={
            "critical": ["kernel panic"],
            "high": ["error", "failure"],
            "medium": ["warning"],
        },
        event_rules=[
            (re.compile(r"error|failure", re.IGNORECASE), "system_error", "system"),
        ],
        component_rules=[
            (re.compile(r"switch", re.IGNORECASE), "network"),
        ],
        ip_regex=None,
        actor_regex=None,
        kv_regex=None,
        defaults={
            "source": "unknown",
            "component": "unknown",
            "event": "raw_log",
            "severity": "low",
        },
    )


# ═══════════════════════════════════════════════════════════════════════════
#  build_profiles / select_profile
# ═══════════════════════════════════════════════════════════════════════════


class TestBuildAndSelectProfile:
    def test_build_profiles_from_config(self):
        cfg = {
            "defaults": {"severity": "low"},
            "profiles": {
                "test_api": {
                    "file_pattern": "api",
                    "line_regex": r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<level>\w+)\s+(?P<host>\S+)\s+(?P<msg>.+)$",
                    "timestamp_format": "iso_space",
                    "source_field": "host",
                    "level_field": "level",
                    "message_field": "msg",
                    "severity_map": {"info": "low", "error": "high"},
                    "event_rules": [],
                    "component_rules": [],
                },
            },
        }
        profiles = build_profiles(cfg)
        assert len(profiles) == 1
        assert profiles[0].name == "test_api"

    def test_select_profile_matches_filename(self, api_profile, syslog_profile):
        profiles = [api_profile, syslog_profile]
        p = select_profile(profiles, "api_gateway_logs.csv")
        assert p is not None
        assert p.name == "api"

    def test_select_profile_no_match(self, api_profile):
        p = select_profile([api_profile], "firewall_logs.txt")
        assert p is None


# ═══════════════════════════════════════════════════════════════════════════
#  parse_line
# ═══════════════════════════════════════════════════════════════════════════


class TestParseLine:
    def test_successful_api_line(self, api_profile):
        line = "2026-02-26 10:00:00 INFO api-gw-01 GET /api/v1/telemetry 200"
        result = parse_line(line, api_profile, UTC)
        assert isinstance(result, Event)
        assert result.timestamp == "2026-02-26T10:00:00Z"
        assert result.source == "api-gw-01"
        assert result.component == "api"
        assert result.event == "http_request"
        assert result.severity == "low"

    def test_empty_line_quarantined(self, api_profile):
        result = parse_line("", api_profile, UTC)
        assert isinstance(result, tuple)
        assert result[1] == "empty_line"

    def test_whitespace_only_quarantined(self, api_profile):
        result = parse_line("   \n", api_profile, UTC)
        assert isinstance(result, tuple)
        assert result[1] == "empty_line"

    def test_unparseable_line_quarantined(self, api_profile):
        result = parse_line("GARBAGE LINE NO MATCH", api_profile, UTC)
        assert isinstance(result, tuple)
        assert result[1] == "parse_error"

    def test_severity_from_level_field(self, api_profile):
        line = "2026-02-26 10:00:00 ERROR api-gw-01 Something went wrong"
        result = parse_line(line, api_profile, UTC)
        assert isinstance(result, Event)
        assert result.severity == "high"

    def test_ip_extraction(self, api_profile):
        line = "2026-02-26 10:00:00 WARN api-gw-01 auth failed from 192.168.1.100"
        result = parse_line(line, api_profile, UTC)
        assert isinstance(result, Event)
        assert result.ip == "192.168.1.100"

    def test_actor_extraction(self, api_profile):
        line = "2026-02-26 10:00:00 INFO api-gw-01 login success user=john_doe"
        result = parse_line(line, api_profile, UTC)
        assert isinstance(result, Event)
        assert result.actor == "john_doe"

    def test_event_type_detection_auth_failure(self, api_profile):
        line = "2026-02-26 10:00:00 WARN api-gw-01 auth failed from 10.0.0.1"
        result = parse_line(line, api_profile, UTC)
        assert isinstance(result, Event)
        assert result.event == "auth_failure"

    def test_event_type_detection_rate_limit(self, api_profile):
        line = "2026-02-26 10:00:00 WARN api-gw-01 rate-limit exceeded"
        result = parse_line(line, api_profile, UTC)
        assert isinstance(result, Event)
        assert result.event == "rate_exceeded"

    def test_syslog_format_parsing(self, syslog_profile):
        line = "Feb 26 10:05:30 switch-01 port Gi0/1 error link down"
        result = parse_line(line, syslog_profile, UTC)
        assert isinstance(result, Event)
        assert result.source == "switch-01"
        assert result.component == "network"
        assert result.event == "system_error"
        assert "2026" in result.timestamp

    def test_strips_trailing_newline(self, api_profile):
        line = "2026-02-26 10:00:00 INFO api-gw-01 GET /health 200\n"
        result = parse_line(line, api_profile, UTC)
        assert isinstance(result, Event)


# ═══════════════════════════════════════════════════════════════════════════
#  Field extraction helpers
# ═══════════════════════════════════════════════════════════════════════════


class TestDetectSeverity:
    def test_from_level_field(self, api_profile):
        groups = {"level": "error"}
        sev = _detect_severity(groups, "some msg", api_profile)
        assert sev == "high"

    def test_from_message_fallback(self, api_profile):
        # Use a level NOT in severity_map so it falls through to message check
        groups = {"level": "notice"}
        sev = _detect_severity(groups, "connection denied by firewall", api_profile)
        assert sev == "high"

    def test_defaults_to_low(self, api_profile):
        groups = {}
        sev = _detect_severity(groups, "routine check ok", api_profile)
        assert sev == "low"

    def test_none_level_field_uses_message(self, syslog_profile):
        groups = {}
        sev = _detect_severity(groups, "kernel panic at address 0xDEAD", syslog_profile)
        assert sev == "critical"


class TestDetectComponent:
    def test_api_component(self, api_profile):
        assert _detect_component("api-gw-01", api_profile) == "api"

    def test_db_component(self, api_profile):
        assert _detect_component("db-primary", api_profile) == "db"

    def test_unknown_component(self, api_profile):
        assert _detect_component("firewall-01", api_profile) == "unknown"


class TestDetectEvent:
    def test_http_request(self, api_profile):
        event, tags = _detect_event("GET /api/v1/data 200", api_profile)
        assert event == "http_request"
        assert "api" in tags

    def test_rate_exceeded(self, api_profile):
        event, _ = _detect_event("rate-limit exceeded for client", api_profile)
        assert event == "rate_exceeded"

    def test_default_event(self, api_profile):
        event, tags = _detect_event("random log message", api_profile)
        assert event == "raw_log"
        assert tags == ""


class TestExtractIp:
    def test_from_prefix(self, api_profile):
        assert _extract_ip("request from 10.0.0.1 to api", api_profile) == "10.0.0.1"

    def test_no_ip(self, api_profile):
        assert _extract_ip("no ip here", api_profile) == ""

    def test_none_regex(self, syslog_profile):
        assert _extract_ip("from 1.2.3.4", syslog_profile) == ""


class TestExtractActor:
    def test_user_equals(self, api_profile):
        assert _extract_actor("login user=admin attempt", api_profile) == "admin"

    def test_no_actor(self, api_profile):
        assert _extract_actor("system restart", api_profile) == ""


class TestExtractKv:
    def test_kv_found(self, api_profile):
        key, val, unit = _extract_kv("voltage=231.4V measured", api_profile)
        assert key == "voltage"
        assert val == "231.4"
        assert unit == "V"

    def test_kv_no_unit(self, api_profile):
        key, val, _unit = _extract_kv("count=42", api_profile)
        assert key == "count"
        assert val == "42"

    def test_fallback_to_message(self, syslog_profile):
        key, _val, unit = _extract_kv("plain text message", syslog_profile)
        assert key == "message"
        assert unit == ""
