"""Line parser: raw log line → Event using regex profiles from mapping.yaml.

Each profile defines:
  - a line regex with named groups
  - timestamp format (iso_space / iso_t / syslog)
  - field extractions (source, severity, event type, component, ip, actor, kv)

The parser compiles all regexes once and reuses them for every line.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timezone
from typing import Any

from src.contracts.event import Event

log = logging.getLogger(__name__)

# ── Timestamp strptime patterns ──────────────────────────────────────────────
_TS_PATTERNS: dict[str, str] = {
    "iso_space": "%Y-%m-%d %H:%M:%S",
    "iso_t": "%Y-%m-%dT%H:%M:%SZ",
    "syslog": "%b %d %H:%M:%S",
}


# ── Compiled profile ─────────────────────────────────────────────────────────


@dataclass(slots=True)
class Profile:
    """Compiled parsing profile (one per log-source type)."""

    name: str
    file_pattern: re.Pattern[str]
    line_regex: re.Pattern[str]
    timestamp_format: str
    year_default: int | None
    source_field: str
    level_field: str | None
    message_field: str
    severity_map: dict[str, str]
    severity_from_message: dict[str, list[str]]
    event_rules: list[tuple[re.Pattern[str], str, str]]
    component_rules: list[tuple[re.Pattern[str], str]]
    ip_regex: re.Pattern[str] | None
    actor_regex: re.Pattern[str] | None
    kv_regex: re.Pattern[str] | None
    defaults: dict[str, str]


# ── Build helpers ────────────────────────────────────────────────────────────


def build_profiles(mapping: dict[str, Any]) -> list[Profile]:
    """Compile all profiles from the mapping config dict."""
    defaults = mapping.get("defaults", {})
    result: list[Profile] = []

    for name, cfg in mapping.get("profiles", {}).items():
        ip_rx = re.compile(cfg["ip_regex"]) if cfg.get("ip_regex") else None
        actor_rx = re.compile(cfg["actor_regex"]) if cfg.get("actor_regex") else None
        kv_rx = re.compile(cfg["kv_regex"]) if cfg.get("kv_regex") else None

        sev_map: dict[str, str] = {k.lower(): v for k, v in cfg.get("severity_map", {}).items()}
        sev_msg: dict[str, list[str]] = {}
        for sev, patterns in cfg.get("severity_from_message", {}).items():
            sev_msg[sev] = [p.lower() for p in patterns]

        event_rules: list[tuple[re.Pattern[str], str, str]] = []
        for r in cfg.get("event_rules", []):
            event_rules.append(
                (
                    re.compile(r["pattern"]),
                    r["event"],
                    r.get("tags", ""),
                )
            )

        comp_rules: list[tuple[re.Pattern[str], str]] = []
        for r in cfg.get("component_rules", []):
            comp_rules.append(
                (
                    re.compile(r["pattern"], re.IGNORECASE),
                    r["component"],
                )
            )

        level_field = cfg.get("level_field")
        # YAML null → Python None — keep it None
        if level_field is None or str(level_field).lower() == "null":
            level_field = None

        result.append(
            Profile(
                name=name,
                file_pattern=re.compile(cfg["file_pattern"], re.IGNORECASE),
                line_regex=re.compile(cfg["line_regex"]),
                timestamp_format=cfg.get("timestamp_format", "iso_space"),
                year_default=cfg.get("year_default"),
                source_field=cfg.get("source_field", "host"),
                level_field=level_field,
                message_field=cfg.get("message_field", "msg"),
                severity_map=sev_map,
                severity_from_message=sev_msg,
                event_rules=event_rules,
                component_rules=comp_rules,
                ip_regex=ip_rx,
                actor_regex=actor_rx,
                kv_regex=kv_rx,
                defaults=defaults,
            )
        )
        log.debug("Compiled profile '%s' (regex groups: %s)", name, cfg.get("line_regex", "")[:60])

    return result


def select_profile(profiles: list[Profile], filename: str) -> Profile | None:
    """Select the first profile whose file_pattern matches *filename*."""
    for p in profiles:
        if p.file_pattern.search(filename):
            return p
    return None


# ── Timestamp parsing ────────────────────────────────────────────────────────


def _parse_timestamp(
    groups: dict[str, str],
    profile: Profile,
    tz: timezone | Any,
) -> str | None:
    """Parse timestamp from regex named groups. Returns ISO-8601 UTC or None."""
    fmt = profile.timestamp_format
    try:
        if fmt == "syslog":
            month = groups.get("month", "")
            day = groups.get("day", "")
            time_str = groups.get("time", "")
            if not (month and day and time_str):
                return None
            year = profile.year_default or datetime.now().year
            ts_str = f"{month} {day} {time_str}"
            dt = datetime.strptime(ts_str, _TS_PATTERNS["syslog"])
            dt = dt.replace(year=year, tzinfo=tz)
        else:
            ts_str = groups.get("ts", "")
            if not ts_str:
                return None
            pattern = _TS_PATTERNS.get(fmt, fmt)
            dt = datetime.strptime(ts_str, pattern)
            dt = dt.replace(tzinfo=tz)

        # Convert to UTC
        dt_utc = dt.astimezone(UTC)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, KeyError, OverflowError) as exc:
        log.debug("Timestamp parse error: %s", exc)
        return None


# ── Field extraction helpers ─────────────────────────────────────────────────


def _detect_severity(
    groups: dict[str, str],
    message: str,
    profile: Profile,
) -> str:
    """Determine severity from log level field or message content."""
    # 1) From explicit level field
    if profile.level_field:
        level = groups.get(profile.level_field, "").lower()
        if level in profile.severity_map:
            return profile.severity_map[level]

    # 2) From message substrings (check from most severe to least)
    if profile.severity_from_message:
        msg_lower = message.lower()
        for sev in ("critical", "high", "medium", "low"):
            patterns = profile.severity_from_message.get(sev, [])
            for pat in patterns:
                if pat in msg_lower:
                    return sev

    # 3) Fallback
    return profile.defaults.get("severity", "low")


def _detect_component(source: str, profile: Profile) -> str:
    """Determine component from source/host name."""
    for pattern, component in profile.component_rules:
        if pattern.search(source):
            return component
    return profile.defaults.get("component", "unknown")


def _detect_event(message: str, profile: Profile) -> tuple[str, str]:
    """Determine event type and tags from message content. First match wins."""
    for pattern, event, tags in profile.event_rules:
        if pattern.search(message):
            return event, tags
    return profile.defaults.get("event", "raw_log"), ""


def _extract_ip(message: str, profile: Profile) -> str:
    """Extract first IP address from message."""
    if profile.ip_regex:
        m = profile.ip_regex.search(message)
        if m:
            return m.group(1)
    return ""


def _extract_actor(message: str, profile: Profile) -> str:
    """Extract actor/user from message."""
    if profile.actor_regex:
        m = profile.actor_regex.search(message)
        if m:
            return m.group(1)
    return ""


def _extract_kv(message: str, profile: Profile) -> tuple[str, str, str]:
    """Extract key, value, unit from message.

    If kv_regex is defined and matches, uses the first (key, raw_value) pair
    and tries to separate a numeric value from its unit suffix.
    Otherwise returns ("message", <truncated message>, "").
    """
    if profile.kv_regex:
        matches = profile.kv_regex.findall(message)
        if matches:
            key, raw_value = matches[0]
            # Separate numeric part from unit: "231.4V" → ("231.4", "V")
            m = re.match(r"^([+-]?\d+\.?\d*)\s*([a-zA-Z/%]*)$", raw_value)
            if m:
                return key, m.group(1), m.group(2)
            return key, raw_value, ""
    return "message", message[:512], ""


# ── Main parse function ──────────────────────────────────────────────────────


def parse_line(
    line: str,
    profile: Profile,
    tz: timezone | Any,
) -> Event | tuple[str, str]:
    """Parse a single raw log line.

    Returns:
        Event — on success
        (raw_line, reason) — on failure (for quarantine)
    """
    line = line.rstrip("\n\r")

    # Empty / whitespace-only
    if not line.strip():
        return (line, "empty_line")

    # Regex match
    m = profile.line_regex.match(line)
    if not m:
        return (line, "parse_error")

    groups = m.groupdict()

    # ── Timestamp ──
    ts = _parse_timestamp(groups, profile, tz)
    if ts is None:
        return (line, "no_timestamp")

    # ── Source ──
    source = groups.get(profile.source_field, profile.defaults.get("source", "unknown"))

    # ── Message ──
    message = groups.get(profile.message_field, "")

    # ── Component ──
    component = _detect_component(source, profile)

    # ── Severity ──
    severity = _detect_severity(groups, message, profile)

    # ── Event type + tags ──
    event_type, tags = _detect_event(message, profile)

    # ── IP ──
    ip = _extract_ip(message, profile)

    # ── Actor ──
    actor = _extract_actor(message, profile)

    # ── Key / Value / Unit ──
    key, value, unit = _extract_kv(message, profile)

    return Event(
        timestamp=ts,
        source=source,
        component=component,
        event=event_type,
        key=key,
        value=value,
        severity=severity,
        actor=actor,
        ip=ip,
        unit=unit,
        tags=tags,
        correlation_id="",
    )
