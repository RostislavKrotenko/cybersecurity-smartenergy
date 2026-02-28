"""Post-parse filters: deduplication and validation.

These run *after* raw lines have been parsed into Events but *before*
writing the final CSV output.
"""

from __future__ import annotations

import logging

from src.contracts.event import Event

log = logging.getLogger(__name__)


def deduplicate(
    events: list[Event],
    window_sec: int = 2,
) -> list[Event]:
    """Remove near-duplicate events within a sliding time window.

    Two events are considered duplicates when they share the same
    (source, event, key, value) and their timestamps differ by at most
    *window_sec* seconds.

    The list must be **sorted by timestamp** before calling.

    Returns a new list with duplicates removed.
    """
    if not events:
        return events

    seen: dict[tuple[str, str, str, str], str] = {}
    result: list[Event] = []
    removed = 0

    for ev in events:
        fingerprint = (ev.source, ev.event, ev.key, ev.value)
        last_ts = seen.get(fingerprint)

        if last_ts is not None:
            # Both timestamps are ISO-8601 strings — lexicographic compare works
            # Convert to seconds for window check
            try:
                from datetime import datetime
                dt_cur = datetime.strptime(ev.timestamp, "%Y-%m-%dT%H:%M:%SZ")
                dt_prev = datetime.strptime(last_ts, "%Y-%m-%dT%H:%M:%SZ")
                delta = abs((dt_cur - dt_prev).total_seconds())
                if delta <= window_sec:
                    removed += 1
                    continue
            except ValueError:
                pass  # on parse error, keep the event

        seen[fingerprint] = ev.timestamp
        result.append(ev)

    if removed:
        log.info("Dedup removed %d duplicate events (window=%ds)", removed, window_sec)

    return result


def validate_event(event: Event) -> list[str]:
    """Return a list of validation warnings (empty = valid).

    Currently checks:
      - severity is one of the known values
      - component is one of the known values
      - timestamp is non-empty
    """
    warnings: list[str] = []

    valid_severities = {"low", "medium", "high", "critical"}
    if event.severity not in valid_severities:
        warnings.append(f"unknown severity '{event.severity}'")

    valid_components = {"edge", "api", "db", "ui", "collector", "inverter", "network", "unknown"}
    if event.component not in valid_components:
        warnings.append(f"unknown component '{event.component}'")

    if not event.timestamp:
        warnings.append("empty timestamp")

    return warnings
