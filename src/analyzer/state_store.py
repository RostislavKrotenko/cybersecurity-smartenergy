"""Component state store for the Analyzer.

Tracks the live status of infrastructure components by observing
state-change events emitted by the Emulator (e.g. ``rate_limit_enabled``,
``isolation_enabled``, ``actor_blocked``, ``restore_started``).

The store is updated each watch-pipeline cycle and written to
``out/state.csv`` atomically so the Dashboard can display a
"Component Status" panel.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.analyzer.reporter import _atomic_write
from src.contracts.event import Event

log = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
#  Row model
# ═══════════════════════════════════════════════════════════════════════════

STATE_CSV_COLUMNS = [
    "timestamp_utc",
    "component",
    "status",
    "details",
    "ttl_sec",
    "expires_at_utc",
]


@dataclass(slots=True)
class ComponentRow:
    """One row in ``out/state.csv``."""

    component: str
    status: str = "healthy"
    details: str = ""
    ttl_sec: float = 0.0
    expires_at_utc: str = ""
    last_updated: str = ""

    def to_csv_parts(self, now_utc: str) -> list[str]:
        return [
            now_utc,
            self.component,
            self.status,
            self.details,
            f"{self.ttl_sec:.0f}" if self.ttl_sec > 0 else "0",
            self.expires_at_utc,
        ]


# ═══════════════════════════════════════════════════════════════════════════
#  State store
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class ComponentStateStore:
    """In-memory tracker of live component status.

    Call ``process_events()`` each cycle with the newly read events.
    Call ``tick()`` to expire TTL-based statuses.
    Call ``write_csv()`` to atomically dump to ``out/state.csv``.
    """

    gateway: ComponentRow = field(
        default_factory=lambda: ComponentRow(component="gateway"),
    )
    api: ComponentRow = field(
        default_factory=lambda: ComponentRow(component="api"),
    )
    auth: ComponentRow = field(
        default_factory=lambda: ComponentRow(component="auth"),
    )
    db: ComponentRow = field(
        default_factory=lambda: ComponentRow(component="db"),
    )
    network: ComponentRow = field(
        default_factory=lambda: ComponentRow(component="network"),
    )

    # Internal: track blocked count separately
    _blocked_actors: int = 0
    _blocked_ips: int = 0

    # ── event processing ───────────────────────────────────────────────

    def process_events(self, events: list[Event]) -> None:
        """Scan *events* for state-change events and update component rows."""
        for ev in events:
            if "state_change" not in ev.tags:
                continue
            self._handle_state_event(ev)

    def _handle_state_event(self, ev: Event) -> None:
        ts = ev.timestamp

        # ── gateway: rate limiting ──────────────────────────────────
        if ev.event == "rate_limit_enabled":
            params = _parse_kv(ev.value)
            rps = params.get("rps", "?")
            burst = params.get("burst", "?")
            dur = int(params.get("dur", "0") or "0")
            self.gateway.status = "rate_limited"
            self.gateway.details = f"rps={rps} burst={burst}"
            self.gateway.ttl_sec = float(dur)
            self.gateway.expires_at_utc = _add_seconds(ts, dur)
            self.gateway.last_updated = ts

        elif ev.event == "rate_limit_disabled" or ev.event == "rate_limit_expired":
            self.gateway.status = "healthy"
            self.gateway.details = ""
            self.gateway.ttl_sec = 0.0
            self.gateway.expires_at_utc = ""
            self.gateway.last_updated = ts

        # ── api / collector: isolation ──────────────────────────────
        elif ev.event == "isolation_enabled":
            params = _parse_kv(ev.value)
            dur = int(params.get("duration", "0") or "0")
            self.api.status = "isolated"
            self.api.details = f"duration={dur}s"
            self.api.ttl_sec = float(dur)
            self.api.expires_at_utc = _add_seconds(ts, dur)
            self.api.last_updated = ts

        elif ev.event in ("isolation_released", "isolation_expired"):
            self.api.status = "healthy"
            self.api.details = ""
            self.api.ttl_sec = 0.0
            self.api.expires_at_utc = ""
            self.api.last_updated = ts

        # ── auth: actor / IP blocking ──────────────────────────────
        elif ev.event == "actor_blocked":
            params = _parse_kv(ev.value)
            dur = int(params.get("duration", "0") or "0")
            actor = params.get("actor", "")
            ip = params.get("ip", "")
            if actor:
                self._blocked_actors += 1
            if ip:
                self._blocked_ips += 1
            total = self._blocked_actors + self._blocked_ips
            self.auth.status = "blocking"
            self.auth.details = f"blocked={total} (actors={self._blocked_actors} ips={self._blocked_ips})"
            self.auth.ttl_sec = float(dur)
            self.auth.expires_at_utc = _add_seconds(ts, dur)
            self.auth.last_updated = ts

        elif ev.event == "actor_unblocked":
            params = _parse_kv(ev.value)
            actor = params.get("actor", "")
            ip = params.get("ip", "")
            if actor:
                self._blocked_actors = max(0, self._blocked_actors - 1)
            if ip:
                self._blocked_ips = max(0, self._blocked_ips - 1)
            total = self._blocked_actors + self._blocked_ips
            if total > 0:
                self.auth.status = "blocking"
                self.auth.details = f"blocked={total} (actors={self._blocked_actors} ips={self._blocked_ips})"
            else:
                self.auth.status = "healthy"
                self.auth.details = ""
                self.auth.ttl_sec = 0.0
                self.auth.expires_at_utc = ""
            self.auth.last_updated = ts

        elif ev.event == "block_expired":
            params = _parse_kv(ev.value)
            if "actor" in params:
                self._blocked_actors = max(0, self._blocked_actors - 1)
            if "ip" in params:
                self._blocked_ips = max(0, self._blocked_ips - 1)
            total = self._blocked_actors + self._blocked_ips
            if total > 0:
                self.auth.status = "blocking"
                self.auth.details = f"blocked={total} (actors={self._blocked_actors} ips={self._blocked_ips})"
            else:
                self.auth.status = "healthy"
                self.auth.details = ""
                self.auth.ttl_sec = 0.0
                self.auth.expires_at_utc = ""
            self.auth.last_updated = ts

        # ── db: backup / restore ───────────────────────────────────
        elif ev.event == "restore_started":
            params = _parse_kv(ev.value)
            snap = params.get("snapshot", ev.value)
            self.db.status = "restoring"
            self.db.details = f"from {snap}"
            self.db.ttl_sec = 10.0
            self.db.expires_at_utc = _add_seconds(ts, 10)
            self.db.last_updated = ts

        elif ev.event == "restore_completed":
            self.db.status = "healthy"
            self.db.details = "restored"
            self.db.ttl_sec = 0.0
            self.db.expires_at_utc = ""
            self.db.last_updated = ts

        elif ev.event == "backup_created" or ev.event == "db_backup_created":
            self.db.details = f"latest backup: {ev.value}"
            self.db.last_updated = ts

        elif ev.event == "db_corruption_detected":
            self.db.status = "corrupted"
            self.db.details = ev.value
            self.db.last_updated = ts

        elif ev.event == "restore_failed":
            self.db.status = "corrupted"
            self.db.details = f"restore failed: {ev.value}"
            self.db.ttl_sec = 0.0
            self.db.expires_at_utc = ""
            self.db.last_updated = ts

        # ── network ───────────────────────────────────────────────
        elif ev.event == "network_degraded":
            params = _parse_kv(ev.value)
            ttl = int(params.get("ttl_sec", "0") or "0")
            latency = params.get("latency_ms", "?")
            drop = params.get("drop_rate", "?")
            self.network.status = "degraded"
            self.network.details = f"latency={latency}ms drop={drop}"
            if ttl > 0:
                self.network.ttl_sec = float(ttl)
                self.network.expires_at_utc = _add_seconds(ts, ttl)
            self.network.last_updated = ts

        elif ev.event == "network_reset_applied" or ev.event == "network_recovered":
            self.network.status = "healthy"
            self.network.details = ""
            self.network.ttl_sec = 0.0
            self.network.expires_at_utc = ""
            self.network.last_updated = ts

    # ── TTL tick ───────────────────────────────────────────────────────

    def tick(self) -> None:
        """Decay TTL values based on current time vs expires_at_utc.

        If a component's TTL has expired, reset it to healthy.
        """
        now = datetime.now(tz=timezone.utc)
        for row in self._all_rows():
            if row.expires_at_utc and row.ttl_sec > 0:
                try:
                    exp = datetime.fromisoformat(
                        row.expires_at_utc.replace("Z", "+00:00"),
                    )
                    remaining = (exp - now).total_seconds()
                    if remaining <= 0:
                        # Expired -- reset to healthy
                        row.status = "healthy"
                        row.details = ""
                        row.ttl_sec = 0.0
                        row.expires_at_utc = ""
                    else:
                        row.ttl_sec = remaining
                except (ValueError, TypeError):
                    pass

    # ── CSV output ─────────────────────────────────────────────────────

    def write_csv(self, path: str) -> None:
        """Write current component state to CSV atomically."""
        now_utc = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines = [",".join(STATE_CSV_COLUMNS)]
        for row in self._all_rows():
            parts = row.to_csv_parts(now_utc)
            # Escape commas in details field
            escaped = []
            for p in parts:
                if "," in p:
                    escaped.append(f'"{p}"')
                else:
                    escaped.append(p)
            lines.append(",".join(escaped))
        _atomic_write(path, "\n".join(lines) + "\n")

    def _all_rows(self) -> list[ComponentRow]:
        return [self.gateway, self.api, self.auth, self.db, self.network]


# ═══════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════

_KV_RE = re.compile(r"(\w+)=([^,]+)")


def _parse_kv(value: str) -> dict[str, str]:
    """Parse 'key1=val1,key2=val2,...' into a dict."""
    return dict(_KV_RE.findall(value))


def _add_seconds(iso_ts: str, seconds: int) -> str:
    """Add *seconds* to an ISO timestamp and return ISO string."""
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        from datetime import timedelta

        result = dt + timedelta(seconds=seconds)
        return result.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        return ""
