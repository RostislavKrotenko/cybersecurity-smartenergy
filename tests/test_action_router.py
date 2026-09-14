"""Тести ActionRouter та інтерфейсів керування компонентами."""

from __future__ import annotations

from src.adapters.action_router import ActionRouter, ComponentControls
from src.contracts.action import Action
from src.contracts.interfaces import ActionStatus
from src.emulator.world import WorldState, build_emulated_action_router, is_actor_blocked


def _action(action: str, target: str, params: dict | None = None) -> Action:
    return Action(
        ts_utc="2026-03-01T12:00:00Z",
        action=action,
        target_component=target,
        params=params or {},
        reason="test",
        correlation_id="INC-test",
        action_id=f"ACT-{action}",
    )


def test_router_reports_missing_component_control():
    router = ActionRouter(ComponentControls())

    result = router.execute(_action("enable_rate_limit", "gateway"))

    assert router.supports_action("enable_rate_limit") is False
    assert result.success is False
    assert result.status == ActionStatus.FAILED
    assert "gateway" in result.error


def test_router_executes_gateway_control_against_world_state():
    state = WorldState()
    router = build_emulated_action_router(state)

    assert router.supports_action("enable_rate_limit") is True
    result = router.execute(
        _action(
            "enable_rate_limit",
            "gateway",
            {"rps": 25, "burst": 50, "duration_sec": 30},
        )
    )

    assert result.success is True
    assert result.status == ActionStatus.APPLIED
    assert state.gateway.rate_limit_enabled is True
    assert state.gateway.rate_limit_rps == 25
    assert result.state_events[0].event == "rate_limit_enabled"


def test_router_executes_auth_control_against_world_state():
    state = WorldState()
    router = build_emulated_action_router(state)

    result = router.execute(
        _action(
            "block_actor",
            "auth",
            {"actor": "attacker", "ip": "10.0.0.8", "duration_sec": 120},
        )
    )

    assert result.success is True
    assert is_actor_blocked(state, "attacker", "")
    assert is_actor_blocked(state, "", "10.0.0.8")
    assert result.state_events[0].component == "auth"


def test_router_executes_database_control_against_world_state():
    state = WorldState()
    router = build_emulated_action_router(state)

    backup = router.execute(_action("backup_db", "db", {"name": "snap_router"}))
    restore = router.execute(_action("restore_db", "db", {"snapshot": "snap_router"}))

    assert backup.success is True
    assert "snap_router" in state.db.snapshots
    assert restore.success is True
    assert state.db.status == "restoring"
    assert restore.state_events[0].event == "restore_started"


def test_router_executes_network_control_against_world_state():
    state = WorldState()
    router = build_emulated_action_router(state)

    degraded = router.execute(
        _action(
            "degrade_network",
            "network",
            {"latency_ms": 180, "drop_rate": 0.2, "ttl_sec": 45},
        )
    )
    reset = router.execute(_action("reset_network", "network"))

    assert degraded.success is True
    assert degraded.state_events[0].event == "network_degraded"
    assert reset.success is True
    assert state.network.latency_ms == 0
    assert state.network.drop_rate == 0.0
