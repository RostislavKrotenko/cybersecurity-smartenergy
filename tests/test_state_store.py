"""Tests for ComponentStateStore: event processing, TTL decay, CSV output."""

from __future__ import annotations

import csv
import os
import tempfile

from src.analyzer.state_store import ComponentStateStore, _parse_kv
from src.contracts.action import Action
from src.contracts.event import Event
from src.emulator.world import WorldState, apply_action


def _state_event(
    component: str,
    event: str,
    value: str,
    ts: str = "2026-03-01T12:00:00Z",
) -> Event:
    return Event(
        timestamp=ts,
        source=f"{component}-01",
        component=component,
        event=event,
        key="action_result",
        value=value,
        severity="high",
        actor="system",
        ip="",
        unit="",
        tags="action;state_change",
        correlation_id="INC-0001",
    )


class TestComponentStateStore:
    def test_rate_limit_enabled(self):
        store = ComponentStateStore()
        ev = _state_event("gateway", "rate_limit_enabled", "rps=50,burst=100,dur=300")
        store.process_events([ev])
        assert store.gateway.status == "rate_limited"
        assert "rps=50" in store.gateway.details
        assert store.gateway.ttl_sec == 300.0

    def test_rate_limit_expired(self):
        store = ComponentStateStore()
        ev1 = _state_event("gateway", "rate_limit_enabled", "rps=50,burst=100,dur=300")
        ev2 = _state_event("gateway", "rate_limit_expired", "auto")
        store.process_events([ev1, ev2])
        assert store.gateway.status == "healthy"
        assert store.gateway.ttl_sec == 0.0

    def test_isolation_enabled(self):
        store = ComponentStateStore()
        ev = _state_event("api", "isolation_enabled", "duration=120")
        store.process_events([ev])
        assert store.api.status == "isolated"
        assert store.api.ttl_sec == 120.0

    def test_isolation_released(self):
        store = ComponentStateStore()
        ev1 = _state_event("api", "isolation_enabled", "duration=120")
        ev2 = _state_event("api", "isolation_released", "manual")
        store.process_events([ev1, ev2])
        assert store.api.status == "healthy"

    def test_isolation_expired(self):
        store = ComponentStateStore()
        ev1 = _state_event("api", "isolation_enabled", "duration=120")
        ev2 = _state_event("api", "isolation_expired", "auto")
        store.process_events([ev1, ev2])
        assert store.api.status == "healthy"

    def test_actor_blocked(self):
        store = ComponentStateStore()
        ev = _state_event("auth", "actor_blocked", "actor=bad,ip=10.0.0.1,duration=600")
        store.process_events([ev])
        assert store.auth.status == "blocking"
        assert "blocked=2" in store.auth.details  # 1 actor + 1 ip

    def test_actor_unblocked(self):
        store = ComponentStateStore()
        ev1 = _state_event("auth", "actor_blocked", "actor=bad,ip=10.0.0.1,duration=600")
        ev2 = _state_event("auth", "actor_unblocked", "actor=bad,ip=10.0.0.1")
        store.process_events([ev1, ev2])
        assert store.auth.status == "healthy"

    def test_block_expired(self):
        store = ComponentStateStore()
        ev1 = _state_event("auth", "actor_blocked", "actor=bad,duration=600")
        ev2 = _state_event("auth", "block_expired", "actor=bad")
        store.process_events([ev1, ev2])
        assert store.auth.status == "healthy"

    def test_restore_started(self):
        store = ComponentStateStore()
        ev = _state_event("db", "restore_started", "snapshot=snapshot_init")
        store.process_events([ev])
        assert store.db.status == "restoring"
        assert "snapshot_init" in store.db.details

    def test_restore_completed(self):
        store = ComponentStateStore()
        ev1 = _state_event("db", "restore_started", "snapshot=snapshot_init")
        ev2 = _state_event("db", "restore_completed", "auto")
        store.process_events([ev1, ev2])
        assert store.db.status == "healthy"
        assert store.db.details == "restored"

    def test_backup_created(self):
        store = ComponentStateStore()
        ev = _state_event("db", "backup_created", "snap_test_1")
        store.process_events([ev])
        assert "snap_test_1" in store.db.details

    def test_non_state_events_ignored(self):
        store = ComponentStateStore()
        ev = Event(
            timestamp="2026-03-01T12:00:00Z",
            source="api-gw-01",
            component="api",
            event="http_request",
            key="path",
            value="/api/v1/data",
            severity="low",
            actor="user1",
            ip="10.0.0.1",
            tags="access",
            correlation_id="",
        )
        store.process_events([ev])
        assert store.api.status == "healthy"

    def test_write_csv(self):
        store = ComponentStateStore()
        ev = _state_event("gateway", "rate_limit_enabled", "rps=50,burst=100,dur=300")
        store.process_events([ev])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "state.csv")
            store.write_csv(path)

            assert os.path.exists(path)
            with open(path) as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            assert len(rows) == 5  # gateway, api, auth, db, network
            gw_row = next(r for r in rows if r["component"] == "gateway")
            assert gw_row["status"] == "rate_limited"
            assert "rps=50" in gw_row["details"]

            api_row = next(r for r in rows if r["component"] == "api")
            assert api_row["status"] == "healthy"

    def test_write_csv_atomic_no_temp_files(self):
        store = ComponentStateStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "state.csv")
            store.write_csv(path)
            files = os.listdir(tmpdir)
            assert len(files) == 1
            assert files[0] == "state.csv"


class TestEndToEndActionToState:
    """Apply action in emulator -> state-change event -> state store."""

    def test_rate_limit_action_to_state(self):
        # 1. Apply action in emulator
        world = WorldState()
        action = Action(
            ts_utc="2026-03-01T12:00:00Z",
            action="enable_rate_limit",
            target_component="gateway",
            params={"rps": 50, "burst": 100, "duration_sec": 300},
            reason="test",
            correlation_id="INC-0001",
        )
        state_events = apply_action(world, action)

        # 2. Feed state-change events into store
        store = ComponentStateStore()
        store.process_events(state_events)

        # 3. Verify store reflects the action
        assert store.gateway.status == "rate_limited"
        assert "rps=50" in store.gateway.details
        assert store.gateway.ttl_sec == 300.0

    def test_isolation_action_to_state(self):
        world = WorldState()
        action = Action(
            ts_utc="2026-03-01T12:00:00Z",
            action="isolate_component",
            target_component="api",
            params={"duration_sec": 120},
            reason="test",
            correlation_id="INC-0002",
        )
        state_events = apply_action(world, action)

        store = ComponentStateStore()
        store.process_events(state_events)

        assert store.api.status == "isolated"
        assert store.api.ttl_sec == 120.0

    def test_block_actor_action_to_state(self):
        world = WorldState()
        action = Action(
            ts_utc="2026-03-01T12:00:00Z",
            action="block_actor",
            target_component="auth",
            params={"actor": "bad", "ip": "10.0.0.99", "duration_sec": 600},
            reason="test",
            correlation_id="INC-0003",
        )
        state_events = apply_action(world, action)

        store = ComponentStateStore()
        store.process_events(state_events)

        assert store.auth.status == "blocking"
        assert "blocked=" in store.auth.details

    def test_restore_db_action_to_state(self):
        world = WorldState()
        action = Action(
            ts_utc="2026-03-01T12:00:00Z",
            action="restore_db",
            target_component="db",
            params={"snapshot": "snapshot_init"},
            reason="test",
            correlation_id="INC-0004",
        )
        state_events = apply_action(world, action)

        store = ComponentStateStore()
        store.process_events(state_events)

        assert store.db.status == "restoring"

    def test_full_cycle_to_csv(self):
        """Apply action -> state event -> store -> CSV -> read back."""
        world = WorldState()
        actions = [
            Action(
                ts_utc="2026-03-01T12:00:00Z",
                action="enable_rate_limit",
                target_component="gateway",
                params={"rps": 50, "burst": 100, "duration_sec": 300},
                reason="test",
                correlation_id="INC-0001",
            ),
            Action(
                ts_utc="2026-03-01T12:00:01Z",
                action="block_actor",
                target_component="auth",
                params={"actor": "bad", "duration_sec": 600},
                reason="test",
                correlation_id="INC-0002",
            ),
        ]

        all_events = []
        for a in actions:
            all_events.extend(apply_action(world, a))

        store = ComponentStateStore()
        store.process_events(all_events)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "state.csv")
            store.write_csv(path)

            with open(path) as f:
                reader = csv.DictReader(f)
                rows = {r["component"]: r for r in reader}

            assert rows["gateway"]["status"] == "rate_limited"
            assert rows["auth"]["status"] == "blocking"
            assert rows["api"]["status"] == "healthy"
            assert rows["db"]["status"] == "healthy"


class TestParseKv:
    def test_simple(self):
        result = _parse_kv("rps=50,burst=100,dur=300")
        assert result == {"rps": "50", "burst": "100", "dur": "300"}

    def test_with_equals_in_value(self):
        result = _parse_kv("actor=bad,ip=10.0.0.1")
        assert result["actor"] == "bad"
        assert result["ip"] == "10.0.0.1"

    def test_empty(self):
        result = _parse_kv("")
        assert result == {}


class TestComponentStatusCardNan:
    """Verify that component_status_card handles NaN/None/empty details."""

    def test_nan_details_cleaned(self):
        from src.dashboard.ui.cards import component_status_card

        html = component_status_card("gateway", "healthy", "nan", 0.0)
        # "nan" should not appear as visible text in the card
        assert "nan" not in html

    def test_none_details_cleaned(self):
        from src.dashboard.ui.cards import component_status_card

        html = component_status_card("api", "isolated", "None", 120.0)
        assert ">None<" not in html

    def test_empty_details_no_details_row(self):
        from src.dashboard.ui.cards import component_status_card

        html = component_status_card("db", "healthy", "", 0.0)
        # When details is empty, no details row should be rendered
        assert "policy-metric-item" not in html

    def test_real_details_shown(self):
        from src.dashboard.ui.cards import component_status_card

        html = component_status_card("gateway", "rate_limited", "rps=50 burst=100", 300.0)
        assert "rps=50" in html
        assert "RATE LIMITED" in html
        assert "TTL" in html
