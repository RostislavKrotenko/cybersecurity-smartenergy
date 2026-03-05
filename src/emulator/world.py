"""Component state model and action application for closed-loop emulation.

Each infrastructure component has mutable runtime state that actions from
the Analyzer can modify. The Emulator reads actions.jsonl, applies them
via ``apply_action()``, and emits state-change events back into
events.jsonl so the Analyzer can observe the effect.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.contracts.action import Action
from src.contracts.event import Event

log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
#  Component state models
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class GatewayState:
    rate_limit_enabled: bool = False
    rate_limit_rps: int = 0
    rate_limit_burst: int = 0
    rate_limit_expires: float = 0.0  # wall-clock monotonic


@dataclass
class ApiState:
    status: str = "healthy"  # healthy | degraded | isolated
    isolation_expires: float = 0.0


@dataclass
class AuthState:
    blocked_actors: dict[str, float] = field(default_factory=dict)  # actor -> expires
    blocked_ips: dict[str, float] = field(default_factory=dict)  # ip -> expires


@dataclass
class DbState:
    status: str = "healthy"  # healthy | corrupted | restoring
    snapshots: list[str] = field(default_factory=lambda: ["snapshot_init"])
    restoring_until: float = 0.0


@dataclass
class EdgeState:
    spoof_enabled: bool = False


@dataclass
class NetworkState:
    latency_ms: int = 0
    drop_rate: float = 0.0
    disconnected: bool = False


@dataclass
class WorldState:
    """Aggregate state of all emulated infrastructure components."""

    gateway: GatewayState = field(default_factory=GatewayState)
    api: ApiState = field(default_factory=ApiState)
    auth: AuthState = field(default_factory=AuthState)
    db: DbState = field(default_factory=DbState)
    edge: EdgeState = field(default_factory=EdgeState)
    network: NetworkState = field(default_factory=NetworkState)


# ═══════════════════════════════════════════════════════════════════════════
#  Action application
# ═══════════════════════════════════════════════════════════════════════════


def apply_action(state: WorldState, action: Action) -> list[Event]:
    """Apply a single action to the world state and return state-change events."""
    now = time.monotonic()
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    events: list[Event] = []

    act = action.action

    if act == "enable_rate_limit":
        state.gateway.rate_limit_enabled = True
        state.gateway.rate_limit_rps = action.params.get("rps", 100)
        state.gateway.rate_limit_burst = action.params.get("burst", 200)
        dur = action.params.get("duration_sec", 300)
        state.gateway.rate_limit_expires = now + dur
        events.append(_state_event(
            ts, "gateway", "api-gw-01", "rate_limit_enabled",
            f"rps={state.gateway.rate_limit_rps},burst={state.gateway.rate_limit_burst},dur={dur}",
            "high", action.correlation_id,
        ))
        log.info("ACTION APPLIED: enable_rate_limit rps=%d burst=%d dur=%ds",
                 state.gateway.rate_limit_rps, state.gateway.rate_limit_burst, dur)

    elif act == "disable_rate_limit":
        state.gateway.rate_limit_enabled = False
        state.gateway.rate_limit_rps = 0
        state.gateway.rate_limit_burst = 0
        state.gateway.rate_limit_expires = 0.0
        events.append(_state_event(
            ts, "gateway", "api-gw-01", "rate_limit_disabled", "manual",
            "medium", action.correlation_id,
        ))
        log.info("ACTION APPLIED: disable_rate_limit")

    elif act == "isolate_component":
        target = action.target_component
        dur = action.params.get("duration_sec", 120)
        if target in ("api", "collector"):
            state.api.status = "isolated"
            state.api.isolation_expires = now + dur
            events.append(_state_event(
                ts, target, action.target_id or target, "isolation_enabled",
                f"duration={dur}", "critical", action.correlation_id,
            ))
            log.info("ACTION APPLIED: isolate_component %s for %ds", target, dur)

    elif act == "release_isolation":
        target = action.target_component
        if target in ("api", "collector"):
            state.api.status = "healthy"
            state.api.isolation_expires = 0.0
            events.append(_state_event(
                ts, target, action.target_id or target, "isolation_released",
                "manual", "medium", action.correlation_id,
            ))
            log.info("ACTION APPLIED: release_isolation %s", target)

    elif act == "block_actor":
        actor = action.params.get("actor", "")
        ip = action.params.get("ip", "")
        dur = action.params.get("duration_sec", 600)
        if actor:
            state.auth.blocked_actors[actor] = now + dur
        if ip:
            state.auth.blocked_ips[ip] = now + dur
        target_str = f"actor={actor},ip={ip}"
        events.append(_state_event(
            ts, "auth", "gateway-01", "actor_blocked",
            f"{target_str},duration={dur}", "high", action.correlation_id,
        ))
        log.info("ACTION APPLIED: block_actor %s for %ds", target_str, dur)

    elif act == "unblock_actor":
        actor = action.params.get("actor", "")
        ip = action.params.get("ip", "")
        state.auth.blocked_actors.pop(actor, None)
        state.auth.blocked_ips.pop(ip, None)
        events.append(_state_event(
            ts, "auth", "gateway-01", "actor_unblocked",
            f"actor={actor},ip={ip}", "medium", action.correlation_id,
        ))
        log.info("ACTION APPLIED: unblock_actor actor=%s ip=%s", actor, ip)

    elif act == "backup_db":
        snap_name = action.params.get("name", f"snap_{int(time.time())}")
        state.db.snapshots.append(snap_name)
        events.append(_state_event(
            ts, "db", "db-primary", "backup_created",
            snap_name, "medium", action.correlation_id,
        ))
        log.info("ACTION APPLIED: backup_db -> %s", snap_name)

    elif act == "restore_db":
        snap = action.params.get("snapshot", "")
        if snap in state.db.snapshots:
            state.db.status = "restoring"
            restore_dur = 10.0  # simulated restore time
            state.db.restoring_until = now + restore_dur
            events.append(_state_event(
                ts, "db", "db-primary", "restore_started",
                f"snapshot={snap}", "critical", action.correlation_id,
            ))
            log.info("ACTION APPLIED: restore_db from %s", snap)
        else:
            log.warning("ACTION FAILED: restore_db snapshot '%s' not found", snap)

    else:
        log.warning("Unknown action type: %s", act)

    return events


def expire_state(state: WorldState) -> list[Event]:
    """Check timers, expire transient states, return state-change events."""
    now = time.monotonic()
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    events: list[Event] = []

    # Rate limit expiry
    if state.gateway.rate_limit_enabled and state.gateway.rate_limit_expires > 0:
        if now >= state.gateway.rate_limit_expires:
            state.gateway.rate_limit_enabled = False
            state.gateway.rate_limit_rps = 0
            state.gateway.rate_limit_burst = 0
            state.gateway.rate_limit_expires = 0.0
            events.append(_state_event(
                ts, "gateway", "api-gw-01", "rate_limit_expired", "auto",
                "low", "",
            ))
            log.info("STATE EXPIRED: rate_limit on gateway")

    # Isolation expiry
    if state.api.status == "isolated" and state.api.isolation_expires > 0:
        if now >= state.api.isolation_expires:
            state.api.status = "healthy"
            state.api.isolation_expires = 0.0
            events.append(_state_event(
                ts, "api", "api-gw-01", "isolation_expired", "auto",
                "low", "",
            ))
            log.info("STATE EXPIRED: isolation on api")

    # Actor/IP block expiry
    expired_actors = [a for a, t in state.auth.blocked_actors.items() if now >= t]
    for a in expired_actors:
        del state.auth.blocked_actors[a]
        events.append(_state_event(
            ts, "auth", "gateway-01", "block_expired",
            f"actor={a}", "low", "",
        ))

    expired_ips = [ip for ip, t in state.auth.blocked_ips.items() if now >= t]
    for ip in expired_ips:
        del state.auth.blocked_ips[ip]
        events.append(_state_event(
            ts, "auth", "gateway-01", "block_expired",
            f"ip={ip}", "low", "",
        ))

    # DB restore completion
    if state.db.status == "restoring" and state.db.restoring_until > 0:
        if now >= state.db.restoring_until:
            state.db.status = "healthy"
            state.db.restoring_until = 0.0
            events.append(_state_event(
                ts, "db", "db-primary", "restore_completed", "auto",
                "medium", "",
            ))
            log.info("STATE EXPIRED: db restore complete")

    return events


def is_actor_blocked(state: WorldState, actor: str, ip: str) -> bool:
    """Check if an actor or IP is currently blocked."""
    now = time.monotonic()
    if actor in state.auth.blocked_actors:
        if now < state.auth.blocked_actors[actor]:
            return True
    if ip in state.auth.blocked_ips:
        if now < state.auth.blocked_ips[ip]:
            return True
    return False


def is_rate_limited(state: WorldState) -> bool:
    """Check if the gateway rate limit is active."""
    return state.gateway.rate_limit_enabled


def is_isolated(state: WorldState, component: str) -> bool:
    """Check if a component is isolated."""
    if component in ("api", "collector"):
        return state.api.status == "isolated"
    return False


# ═══════════════════════════════════════════════════════════════════════════
#  Actions JSONL reader (tail mode)
# ═══════════════════════════════════════════════════════════════════════════


def read_new_actions(path: str, offset: int) -> tuple[list[Action], int]:
    """Read new action lines from *path* starting at *offset*.

    Returns (actions, new_offset).
    """
    import os
    actions: list[Action] = []
    try:
        size = os.path.getsize(path)
    except OSError:
        return actions, offset

    if size <= offset:
        return actions, offset

    with open(path, encoding="utf-8") as fh:
        fh.seek(offset)
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                a = Action.from_json(line)
                actions.append(a)
            except (json.JSONDecodeError, KeyError) as exc:
                log.debug("Skipping bad action line: %s", exc)
        new_offset = fh.tell()

    return actions, new_offset


# ═══════════════════════════════════════════════════════════════════════════
#  Helper
# ═══════════════════════════════════════════════════════════════════════════


def _state_event(
    ts: str, component: str, source: str, event: str, value: str,
    severity: str, correlation_id: str,
) -> Event:
    return Event(
        timestamp=ts,
        source=source,
        component=component,
        event=event,
        key="action_result",
        value=value,
        severity=severity,
        actor="system",
        ip="",
        unit="",
        tags="action;state_change",
        correlation_id=correlation_id,
    )
