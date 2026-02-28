"""Canonical Event data-class — the single source of truth for all modules."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass

# CSV column order — matches EVENT_CONTRACT.md §2
CSV_COLUMNS: list[str] = [
    "timestamp",
    "source",
    "component",
    "event",
    "actor",
    "ip",
    "key",
    "value",
    "unit",
    "severity",
    "tags",
    "correlation_id",
]


@dataclass(slots=True)
class Event:
    """One normalised event in the SmartEnergy pipeline."""

    # ── mandatory ──
    timestamp: str          # ISO-8601 UTC  e.g. "2026-02-26T10:00:00Z"
    source: str             # device / service id
    component: str          # edge | api | db | ui | collector | inverter | network
    event: str              # event type (auth_failure, telemetry_read …)
    key: str                # metric / parameter name
    value: str              # always string
    severity: str           # low | medium | high | critical

    # ── optional ──
    actor: str = ""
    ip: str = ""
    unit: str = ""
    tags: str = ""
    correlation_id: str = ""

    # ── serialisation ─────────────────────────────────────────────────────

    def to_csv_row(self) -> str:
        """Return a single CSV line (no trailing newline)."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([getattr(self, c) for c in CSV_COLUMNS])
        return buf.getvalue().rstrip("\r\n")

    def to_json(self) -> str:
        """Return compact JSON string."""
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def csv_header() -> str:
        return ",".join(CSV_COLUMNS)
