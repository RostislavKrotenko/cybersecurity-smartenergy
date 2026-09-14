"""Модель стану компонентів і застосування дій у closed-loop емуляції.

Кожен компонент інфраструктури має змінний runtime-стан, на який впливають
дії аналізатора. Емулятор читає actions.jsonl, застосовує їх через
``apply_action()`` і повертає події зміни стану в events.jsonl, щоб аналізатор
бачив результат.

Коли з'явиться реальна інфраструктура SmartEnergy, емуляційні control-класи
можна замінити адаптерами з реальними API-викликами без зміни контракту.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.request import Request, urlopen

from src.adapters.action_router import ActionRouter, ComponentControls
from src.contracts.action import Action
from src.contracts.event import Event
from src.contracts.interfaces import (
    ActionResult,
    ActionStatus,
    ApiControl,
    AuthControl,
    DatabaseControl,
    GatewayControl,
    NetworkControl,
)

log = logging.getLogger(__name__)

NETWORK_SIM_URL = os.environ.get("NETWORK_SIM_URL", "")
DEFAULT_BACKUP_RETENTION = 5


def _backup_retention_limit() -> int:
    try:
        return max(1, int(os.environ.get("BACKUP_RETENTION", str(DEFAULT_BACKUP_RETENTION))))
    except ValueError:
        return DEFAULT_BACKUP_RETENTION


def _trim_db_snapshots(state: WorldState) -> None:
    retention = _backup_retention_limit()
    if len(state.db.snapshots) > retention:
        del state.db.snapshots[: len(state.db.snapshots) - retention]


@dataclass
class GatewayState:
    rate_limit_enabled: bool = False
    rate_limit_rps: int = 0
    rate_limit_burst: int = 0
    rate_limit_expires: float = 0.0  # монотонний час завершення


@dataclass
class ApiState:
    status: str = "healthy"  # допустимі стани: healthy, degraded, isolated
    isolation_expires: float = 0.0


@dataclass
class AuthState:
    blocked_actors: dict[str, float] = field(default_factory=dict)  # актор -> час завершення
    blocked_ips: dict[str, float] = field(default_factory=dict)  # IP -> час завершення


@dataclass
class DbState:
    status: str = "healthy"  # допустимі стани: healthy, corrupted, restoring
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
    degraded_until: float = 0.0


@dataclass
class WorldState:
    """Агрегований стан усіх емульованих компонентів інфраструктури."""

    gateway: GatewayState = field(default_factory=GatewayState)
    api: ApiState = field(default_factory=ApiState)
    auth: AuthState = field(default_factory=AuthState)
    db: DbState = field(default_factory=DbState)
    edge: EdgeState = field(default_factory=EdgeState)
    network: NetworkState = field(default_factory=NetworkState)


def _netsim_post(endpoint: str, body: dict) -> dict | None:
    """Надсилає JSON у network-sim і повертає відповідь або None при помилці."""
    url = NETWORK_SIM_URL
    if not url:
        return None
    try:
        data = json.dumps(body).encode()
        req = Request(
            f"{url}{endpoint}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except (URLError, OSError, json.JSONDecodeError) as exc:
        log.warning("network-sim %s failed: %s", endpoint, exc)
        return None


def _success(action_id: str, events: list[Event]) -> ActionResult:
    return ActionResult(
        success=True,
        action_id=action_id,
        status=ActionStatus.APPLIED,
        state_events=events,
    )


def _failed(action_id: str, error: str) -> ActionResult:
    return ActionResult(
        success=False,
        action_id=action_id,
        status=ActionStatus.FAILED,
        error=error,
    )


class EmulatedGatewayControl(GatewayControl):
    """Емуляційна реалізація GatewayControl на основі WorldState."""

    def __init__(self, state: WorldState):
        self.state = state

    def enable_rate_limit(
        self,
        *,
        action_id: str,
        correlation_id: str,
        rps: int,
        burst: int,
        duration_sec: int,
    ) -> ActionResult:
        now = time.monotonic()
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.state.gateway.rate_limit_enabled = True
        self.state.gateway.rate_limit_rps = rps
        self.state.gateway.rate_limit_burst = burst
        self.state.gateway.rate_limit_expires = now + duration_sec
        event = _state_event(
            ts,
            "gateway",
            "api-gw-01",
            "rate_limit_enabled",
            f"rps={rps},burst={burst},dur={duration_sec}",
            "high",
            correlation_id,
        )
        log.info("ACTION APPLIED: enable_rate_limit rps=%d burst=%d dur=%ds", rps, burst, duration_sec)
        return _success(action_id, [event])

    def disable_rate_limit(self, *, action_id: str, correlation_id: str) -> ActionResult:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.state.gateway.rate_limit_enabled = False
        self.state.gateway.rate_limit_rps = 0
        self.state.gateway.rate_limit_burst = 0
        self.state.gateway.rate_limit_expires = 0.0
        event = _state_event(
            ts,
            "gateway",
            "api-gw-01",
            "rate_limit_disabled",
            "manual",
            "medium",
            correlation_id,
        )
        log.info("ACTION APPLIED: disable_rate_limit")
        return _success(action_id, [event])


class EmulatedApiControl(ApiControl):
    """Емуляційна реалізація ApiControl на основі WorldState."""

    def __init__(self, state: WorldState):
        self.state = state

    def isolate_component(
        self,
        *,
        action_id: str,
        correlation_id: str,
        component_id: str,
        target_id: str,
        duration_sec: int,
    ) -> ActionResult:
        if component_id not in ("api", "collector"):
            return _failed(action_id, f"непідтримувана ціль ізоляції: {component_id}")

        now = time.monotonic()
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.state.api.status = "isolated"
        self.state.api.isolation_expires = now + duration_sec
        event = _state_event(
            ts,
            component_id,
            target_id or component_id,
            "isolation_enabled",
            f"duration={duration_sec}",
            "critical",
            correlation_id,
        )
        log.info("ACTION APPLIED: isolate_component %s for %ds", component_id, duration_sec)
        return _success(action_id, [event])

    def release_isolation(
        self,
        *,
        action_id: str,
        correlation_id: str,
        component_id: str,
        target_id: str,
    ) -> ActionResult:
        if component_id not in ("api", "collector"):
            return _failed(action_id, f"непідтримувана ціль ізоляції: {component_id}")

        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.state.api.status = "healthy"
        self.state.api.isolation_expires = 0.0
        event = _state_event(
            ts,
            component_id,
            target_id or component_id,
            "isolation_released",
            "manual",
            "medium",
            correlation_id,
        )
        log.info("ACTION APPLIED: release_isolation %s", component_id)
        return _success(action_id, [event])


class EmulatedAuthControl(AuthControl):
    """Емуляційна реалізація AuthControl на основі WorldState."""

    def __init__(self, state: WorldState):
        self.state = state

    def block_actor(
        self,
        *,
        action_id: str,
        correlation_id: str,
        actor: str,
        ip: str,
        duration_sec: int,
    ) -> ActionResult:
        now = time.monotonic()
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if actor:
            self.state.auth.blocked_actors[actor] = now + duration_sec
        if ip:
            self.state.auth.blocked_ips[ip] = now + duration_sec
        target_str = f"actor={actor},ip={ip}"
        event = _state_event(
            ts,
            "auth",
            "gateway-01",
            "actor_blocked",
            f"{target_str},duration={duration_sec}",
            "high",
            correlation_id,
        )
        log.info("ACTION APPLIED: block_actor %s for %ds", target_str, duration_sec)
        return _success(action_id, [event])

    def unblock_actor(
        self,
        *,
        action_id: str,
        correlation_id: str,
        actor: str,
        ip: str,
    ) -> ActionResult:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.state.auth.blocked_actors.pop(actor, None)
        self.state.auth.blocked_ips.pop(ip, None)
        event = _state_event(
            ts,
            "auth",
            "gateway-01",
            "actor_unblocked",
            f"actor={actor},ip={ip}",
            "medium",
            correlation_id,
        )
        log.info("ACTION APPLIED: unblock_actor actor=%s ip=%s", actor, ip)
        return _success(action_id, [event])


class EmulatedDatabaseControl(DatabaseControl):
    """Емуляційна реалізація DatabaseControl на основі WorldState."""

    def __init__(self, state: WorldState):
        self.state = state

    def backup(self, *, action_id: str, correlation_id: str, name: str) -> ActionResult:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        snap_name = name or f"snap_{int(time.time())}"
        self.state.db.snapshots.append(snap_name)
        _trim_db_snapshots(self.state)
        event = _state_event(
            ts,
            "db",
            "db-primary",
            "backup_created",
            snap_name,
            "medium",
            correlation_id,
        )
        log.info("ACTION APPLIED: backup_db -> %s", snap_name)
        return _success(action_id, [event])

    def restore(self, *, action_id: str, correlation_id: str, snapshot: str) -> ActionResult:
        snap = snapshot or "latest"
        if snap not in self.state.db.snapshots and snap != "latest":
            log.warning("ACTION FAILED: restore_db snapshot '%s' not found", snap)
            return _failed(action_id, f"snapshot не знайдено: {snap}")

        now = time.monotonic()
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.state.db.status = "restoring"
        restore_dur = 10.0
        self.state.db.restoring_until = now + restore_dur
        event = _state_event(
            ts,
            "db",
            "db-primary",
            "restore_started",
            f"snapshot={snap}",
            "critical",
            correlation_id,
        )
        log.info("ACTION APPLIED: restore_db from %s", snap)
        return _success(action_id, [event])

    def corrupt(self, *, action_id: str, correlation_id: str) -> ActionResult:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.state.db.status = "corrupted"
        event = _state_event(
            ts,
            "db",
            "db-primary",
            "db_corruption_detected",
            "integrity_violation",
            "critical",
            correlation_id,
        )
        log.info("ACTION APPLIED: corrupt_db")
        return _success(action_id, [event])

    def verify_integrity(self) -> bool:
        return self.state.db.status != "corrupted"


class EmulatedNetworkControl(NetworkControl):
    """Емуляційна реалізація NetworkControl на основі WorldState і network-sim."""

    def __init__(self, state: WorldState):
        self.state = state

    def degrade_network(
        self,
        *,
        action_id: str,
        correlation_id: str,
        latency_ms: int,
        drop_rate: float,
        ttl_sec: int,
        disconnected: bool,
    ) -> ActionResult:
        now = time.monotonic()
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.state.network.latency_ms = latency_ms
        self.state.network.drop_rate = drop_rate
        self.state.network.disconnected = disconnected
        self.state.network.degraded_until = now + ttl_sec
        _netsim_post(
            "/degrade",
            {
                "latency_ms": latency_ms,
                "drop_rate": drop_rate,
                "ttl_sec": ttl_sec,
                "disconnected": disconnected,
                "correlation_id": correlation_id,
            },
        )
        value = (
            f"latency_ms={latency_ms},drop_rate={drop_rate},"
            f"disconnected={disconnected},ttl_sec={ttl_sec}"
        )
        event = _state_event(
            ts,
            "network",
            "network-sim",
            "network_degraded",
            value,
            "high",
            correlation_id,
        )
        log.info("ACTION APPLIED: degrade_network %s", value)
        return _success(action_id, [event])

    def reset_network(self, *, action_id: str, correlation_id: str) -> ActionResult:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.state.network.latency_ms = 0
        self.state.network.drop_rate = 0.0
        self.state.network.disconnected = False
        self.state.network.degraded_until = 0.0
        _netsim_post("/reset", {"correlation_id": correlation_id})
        event = _state_event(
            ts,
            "network",
            "network-sim",
            "network_reset_applied",
            "healthy",
            "medium",
            correlation_id,
        )
        log.info("ACTION APPLIED: reset_network")
        return _success(action_id, [event])


def build_emulated_action_router(state: WorldState) -> ActionRouter:
    """Створює ActionRouter з control-класами на основі WorldState."""
    return ActionRouter(
        ComponentControls(
            gateway=EmulatedGatewayControl(state),
            api=EmulatedApiControl(state),
            auth=EmulatedAuthControl(state),
            db=EmulatedDatabaseControl(state),
            network=EmulatedNetworkControl(state),
        )
    )


def apply_action(state: WorldState, action: Action) -> list[Event]:
    """Застосовує одну дію до WorldState і повертає події зміни стану."""
    result = build_emulated_action_router(state).execute(action)
    if not result.success:
        log.warning("ACTION FAILED: %s", result.error)
    return result.state_events


def expire_state(state: WorldState) -> list[Event]:
    """Перевіряє таймери, завершує тимчасові стани і повертає події."""
    now = time.monotonic()
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    events: list[Event] = []

    if (
        state.gateway.rate_limit_enabled
        and state.gateway.rate_limit_expires > 0
        and now >= state.gateway.rate_limit_expires
    ):
        state.gateway.rate_limit_enabled = False
        state.gateway.rate_limit_rps = 0
        state.gateway.rate_limit_burst = 0
        state.gateway.rate_limit_expires = 0.0
        events.append(
            _state_event(
                ts,
                "gateway",
                "api-gw-01",
                "rate_limit_expired",
                "auto",
                "low",
                "",
            )
        )
        log.info("STATE EXPIRED: rate_limit on gateway")

    if (
        state.api.status == "isolated"
        and state.api.isolation_expires > 0
        and now >= state.api.isolation_expires
    ):
        state.api.status = "healthy"
        state.api.isolation_expires = 0.0
        events.append(
            _state_event(
                ts,
                "api",
                "api-gw-01",
                "isolation_expired",
                "auto",
                "low",
                "",
            )
        )
        log.info("STATE EXPIRED: isolation on api")

    expired_actors = [a for a, t in state.auth.blocked_actors.items() if now >= t]
    for a in expired_actors:
        del state.auth.blocked_actors[a]
        events.append(
            _state_event(
                ts,
                "auth",
                "gateway-01",
                "block_expired",
                f"actor={a}",
                "low",
                "",
            )
        )

    expired_ips = [ip for ip, t in state.auth.blocked_ips.items() if now >= t]
    for ip in expired_ips:
        del state.auth.blocked_ips[ip]
        events.append(
            _state_event(
                ts,
                "auth",
                "gateway-01",
                "block_expired",
                f"ip={ip}",
                "low",
                "",
            )
        )

    if (
        state.db.status == "restoring"
        and state.db.restoring_until > 0
        and now >= state.db.restoring_until
    ):
        state.db.status = "healthy"
        state.db.restoring_until = 0.0
        events.append(
            _state_event(
                ts,
                "db",
                "db-primary",
                "restore_completed",
                "auto",
                "medium",
                "",
            )
        )
        log.info("STATE EXPIRED: db restore complete")

    if state.network.degraded_until > 0 and now >= state.network.degraded_until:
        state.network.latency_ms = 0
        state.network.drop_rate = 0.0
        state.network.disconnected = False
        state.network.degraded_until = 0.0
        events.append(
            _state_event(
                ts,
                "network",
                "network-sim",
                "network_recovered",
                "auto_ttl_expired",
                "low",
                "",
            )
        )
        log.info("STATE EXPIRED: network degradation TTL")

    return events


def is_actor_blocked(state: WorldState, actor: str, ip: str) -> bool:
    """Перевіряє, чи actor або IP зараз заблокований."""
    now = time.monotonic()
    if actor in state.auth.blocked_actors and now < state.auth.blocked_actors[actor]:
        return True
    return ip in state.auth.blocked_ips and now < state.auth.blocked_ips[ip]


def is_rate_limited(state: WorldState) -> bool:
    """Перевіряє, чи активний rate limit на gateway."""
    return state.gateway.rate_limit_enabled


def is_isolated(state: WorldState, component: str) -> bool:
    """Перевіряє, чи компонент ізольований."""
    if component in ("api", "collector"):
        return state.api.status == "isolated"
    return False


def is_network_degraded(state: WorldState) -> bool:
    """Перевіряє, чи мережа зараз деградує."""
    return state.network.latency_ms > 0 or state.network.disconnected


def read_new_actions(path: str, offset: int) -> tuple[list[Action], int]:
    """Зчитує нові рядки дій із *path*, починаючи з *offset*.

    Повертає (actions, new_offset).
    """
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
                log.debug("Пропущено невалідний рядок дії: %s", exc)
        new_offset = fh.tell()

    return actions, new_offset


def _state_event(
    ts: str,
    component: str,
    source: str,
    event: str,
    value: str,
    severity: str,
    correlation_id: str,
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
