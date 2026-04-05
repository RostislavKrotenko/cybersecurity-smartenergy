"""End-to-end test: incident -> decision -> emit_actions -> emulator apply_actions.

Verifies the full closed-loop cycle where:
1. A set of attack events feeds the detector.
2. The detector produces alerts; the correlator groups them into incidents.
3. The decision engine maps incidents to concrete Action objects.
4. Actions are written to a JSONL file and read back.
5. The emulator applies the actions to WorldState.
6. WorldState changes are observable (blocked actors, rate limiting, etc.)
   and generate corresponding state-change events.
7. State-change events confirm actions (emitted -> applied).
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from src.analyzer.correlator import correlate
from src.analyzer.decision import decide, emit_actions
from src.analyzer.detector import detect
from src.analyzer.pipeline import _confirm_actions
from src.analyzer.state_store import ComponentStateStore
from src.contracts.action import Action, ActionAck
from src.contracts.event import Event
from src.emulator.world import (
    WorldState,
    apply_action,
    is_isolated,
    is_rate_limited,
    read_new_actions,
)
from src.shared.config_loader import load_yaml


def _bf_events(n: int = 8, ip: str = "10.0.0.99") -> list[Event]:
    """Generate *n* brute-force auth_failure events from *ip*."""
    return [
        Event(
            timestamp=f"2026-03-01T12:00:{i:02d}Z",
            source="gateway-01",
            component="api",
            event="auth_failure",
            key="username",
            value="admin",
            severity="high",
            actor="unknown",
            ip=ip,
            tags="auth;failure",
            correlation_id="COR-BF-TEST",
        )
        for i in range(n)
    ]


def _ddos_events(n: int = 12) -> list[Event]:
    """Generate *n* rate_exceeded events plus a service_status degraded."""
    events = [
        Event(
            timestamp=f"2026-03-01T12:01:{i:02d}Z",
            source="api-gw-01",
            component="api",
            event="rate_exceeded",
            key="rps",
            value=str(500 + i * 10),
            severity="high",
            actor="",
            ip="",
            tags="ddos;flood",
            correlation_id="COR-DDOS-TEST",
        )
        for i in range(n)
    ]
    events.append(
        Event(
            timestamp="2026-03-01T12:01:15Z",
            source="api-gw-01",
            component="api",
            event="service_status",
            key="status",
            value="degraded",
            severity="critical",
            actor="",
            ip="",
            tags="availability",
            correlation_id="COR-DDOS-TEST",
        )
    )
    return events


class TestClosedLoopActionCycle:
    """Full closed-loop: events -> detect -> correlate -> decide -> apply."""

    def test_brute_force_blocks_actor(self):
        rules_cfg = load_yaml("config/rules.yaml")

        events = _bf_events(8, ip="10.0.0.99")
        alerts = detect(events, rules_cfg)
        assert len(alerts) > 0

        incidents = correlate(alerts, "baseline")
        assert len(incidents) > 0
        for i, inc in enumerate(incidents):
            inc.incident_id = f"INC-{i + 1:04d}"

        acted: set[str] = set()
        actions = decide(incidents, acted)
        assert any(a.action == "block_actor" for a in actions)

        state = WorldState()
        all_state_events: list[Event] = []
        for a in actions:
            evts = apply_action(state, a)
            all_state_events.extend(evts)

        # Actor or IP should be blocked
        assert len(state.auth.blocked_actors) > 0 or len(state.auth.blocked_ips) > 0
        # State-change event should have been generated
        assert any(e.event == "actor_blocked" for e in all_state_events)

    def test_ddos_enables_rate_limit(self):
        rules_cfg = load_yaml("config/rules.yaml")

        events = _ddos_events(12)
        alerts = detect(events, rules_cfg)
        incidents = correlate(alerts, "baseline")
        for i, inc in enumerate(incidents):
            inc.incident_id = f"INC-{i + 1:04d}"

        acted: set[str] = set()
        actions = decide(incidents, acted)
        assert any(a.action == "enable_rate_limit" for a in actions)

        state = WorldState()
        all_state_events: list[Event] = []
        for a in actions:
            evts = apply_action(state, a)
            all_state_events.extend(evts)

        assert is_rate_limited(state)
        assert any(e.event == "rate_limit_enabled" for e in all_state_events)

    def test_file_roundtrip(self):
        """Write actions to JSONL, read back, apply -- verify world state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "actions.jsonl")

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
                    action="isolate_component",
                    target_component="api",
                    params={"duration_sec": 60},
                    reason="test",
                    correlation_id="INC-0002",
                ),
            ]
            emit_actions(actions, path)

            # Verify file was created and is valid JSONL
            assert os.path.exists(path)
            with open(path) as f:
                lines = f.readlines()
            assert len(lines) == 2
            for line in lines:
                obj = json.loads(line)
                assert "action" in obj

            # Read back via the emulator's reader
            read_acts, _offset = read_new_actions(path, 0)
            assert len(read_acts) == 2

            # Apply to world
            state = WorldState()
            all_events: list[Event] = []
            for a in read_acts:
                evts = apply_action(state, a)
                all_events.extend(evts)

            assert is_rate_limited(state)
            assert is_isolated(state, "api")
            assert any(e.event == "rate_limit_enabled" for e in all_events)
            assert any(e.event == "isolation_enabled" for e in all_events)


class TestActionConfirmation:
    """Verify that state-change events mark actions as 'applied'."""

    def test_confirm_marks_applied(self):
        action = Action(
            ts_utc="2026-03-01T12:00:00Z",
            action="enable_rate_limit",
            target_component="gateway",
            params={"rps": 50},
            reason="test",
            correlation_id="INC-0001",
            status="emitted",
        )
        index: dict[str, list[Action]] = {"INC-0001": [action]}

        ev = Event(
            timestamp="2026-03-01T12:00:02Z",
            source="api-gw-01",
            component="gateway",
            event="rate_limit_enabled",
            key="action_result",
            value="rps=50,burst=200,dur=300",
            severity="high",
            actor="system",
            ip="",
            tags="action;state_change",
            correlation_id="INC-0001",
        )
        changed = _confirm_actions([ev], index)
        assert changed is True
        assert action.status == "applied"

    def test_ignores_non_state_events(self):
        action = Action(
            ts_utc="2026-03-01T12:00:00Z",
            action="enable_rate_limit",
            target_component="gateway",
            params={},
            reason="test",
            correlation_id="INC-0001",
            status="emitted",
        )
        index: dict[str, list[Action]] = {"INC-0001": [action]}

        ev = Event(
            timestamp="2026-03-01T12:00:02Z",
            source="api-gw-01",
            component="gateway",
            event="http_request",
            key="path",
            value="/api/v1/data",
            severity="low",
            actor="user1",
            ip="",
            tags="access",
            correlation_id="INC-0001",
        )
        changed = _confirm_actions([ev], index)
        assert changed is False
        assert action.status == "emitted"

    def test_idempotent_no_duplicate_update(self):
        action = Action(
            ts_utc="2026-03-01T12:00:00Z",
            action="enable_rate_limit",
            target_component="gateway",
            params={},
            reason="test",
            correlation_id="INC-0001",
            status="applied",  # already applied
        )
        index: dict[str, list[Action]] = {"INC-0001": [action]}

        ev = Event(
            timestamp="2026-03-01T12:00:02Z",
            source="api-gw-01",
            component="gateway",
            event="rate_limit_enabled",
            key="action_result",
            value="rps=50",
            severity="high",
            actor="system",
            ip="",
            tags="action;state_change",
            correlation_id="INC-0001",
        )
        changed = _confirm_actions([ev], index)
        assert changed is False

    def test_unknown_cor_id_ignored(self):
        index: dict[str, list[Action]] = {}

        ev = Event(
            timestamp="2026-03-01T12:00:02Z",
            source="api-gw-01",
            component="gateway",
            event="rate_limit_enabled",
            key="action_result",
            value="rps=50",
            severity="high",
            actor="system",
            ip="",
            tags="action;state_change",
            correlation_id="INC-9999",
        )
        changed = _confirm_actions([ev], index)
        assert changed is False

    def test_full_cycle_emit_apply_confirm(self):
        """End-to-end: emit action -> emulator applies -> state-change event -> confirm."""
        action = Action(
            ts_utc="2026-03-01T12:00:00Z",
            action="enable_rate_limit",
            target_component="gateway",
            params={"rps": 50, "burst": 100, "duration_sec": 300},
            reason="INC-0001: availability_attack/critical",
            correlation_id="INC-0001",
            status="emitted",
        )
        index: dict[str, list[Action]] = {"INC-0001": [action]}

        # Emulator applies the action
        state = WorldState()
        state_events = apply_action(state, action)
        assert len(state_events) > 0
        assert is_rate_limited(state)

        # Analyzer confirms action from state-change events
        changed = _confirm_actions(state_events, index)
        assert changed is True
        assert action.status == "applied"

        # State store also picks up the change
        store = ComponentStateStore()
        store.process_events(state_events)
        assert store.gateway.status == "rate_limited"
        assert "rps=50" in store.gateway.details
        assert store.gateway.ttl_sec == 300.0


class TestActionAckMechanism:
    """Tests for the ACK file mechanism (actions_applied.jsonl)."""

    def test_action_ack_json_roundtrip(self):
        ack = ActionAck(
            action_id="ACT-abc12345",
            correlation_id="INC-0001",
            target_component="gateway",
            action="enable_rate_limit",
            applied_ts_utc="2026-03-01T12:00:05Z",
            result="success",
            state_event="rate_limit_enabled",
        )
        line = ack.to_json()
        restored = ActionAck.from_json(line)
        assert restored.action_id == "ACT-abc12345"
        assert restored.result == "success"
        assert restored.state_event == "rate_limit_enabled"

    def test_action_has_action_id(self):
        a = Action(
            ts_utc="2026-03-01T12:00:00Z",
            action="enable_rate_limit",
            target_component="gateway",
        )
        assert a.action_id.startswith("ACT-")
        assert len(a.action_id) == 12  # "ACT-" + 8 hex chars

    def test_action_id_in_json(self):
        a = Action(
            ts_utc="2026-03-01T12:00:00Z",
            action="enable_rate_limit",
            target_component="gateway",
        )
        d = json.loads(a.to_json())
        assert "action_id" in d
        assert d["action_id"] == a.action_id

    def test_read_acks_updates_status_and_state(self):
        from src.analyzer.pipeline import _read_acks

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create an action
            action = Action(
                ts_utc="2026-03-01T12:00:00Z",
                action="enable_rate_limit",
                target_component="gateway",
                params={"rps": 50, "burst": 100, "duration_sec": 300},
                reason="test",
                correlation_id="INC-0001",
                status="emitted",
                action_id="ACT-test0001",
            )
            actions_by_id = {"ACT-test0001": action}

            # Write an ACK
            ack = ActionAck(
                action_id="ACT-test0001",
                correlation_id="INC-0001",
                target_component="gateway",
                action="enable_rate_limit",
                applied_ts_utc="2026-03-01T12:00:02Z",
                result="success",
                state_event="rate_limit_enabled",
            )
            ack_path = os.path.join(tmpdir, "actions_applied.jsonl")
            with open(ack_path, "w") as f:
                f.write(ack.to_json() + "\n")

            store = ComponentStateStore()
            out_p = Path(tmpdir)
            _new_offset, changed = _read_acks(
                ack_path,
                0,
                actions_by_id,
                [action],
                store,
                out_p,
            )

            # Action should be marked as applied
            assert action.status == "applied"
            assert changed is True

            # State store should reflect the change
            assert store.gateway.status == "rate_limited"
            assert "rps=50" in store.gateway.details

    def test_read_acks_failed_action(self):
        from src.analyzer.pipeline import _read_acks

        with tempfile.TemporaryDirectory() as tmpdir:
            action = Action(
                ts_utc="2026-03-01T12:00:00Z",
                action="restore_db",
                target_component="db",
                params={"snapshot": "snap_missing"},
                reason="test",
                correlation_id="INC-0005",
                status="emitted",
                action_id="ACT-fail0001",
            )
            actions_by_id = {"ACT-fail0001": action}

            ack = ActionAck(
                action_id="ACT-fail0001",
                correlation_id="INC-0005",
                target_component="db",
                action="restore_db",
                applied_ts_utc="2026-03-01T12:00:02Z",
                result="failed",
                error="snapshot not found",
            )
            ack_path = os.path.join(tmpdir, "actions_applied.jsonl")
            with open(ack_path, "w") as f:
                f.write(ack.to_json() + "\n")

            store = ComponentStateStore()
            _, changed = _read_acks(
                ack_path,
                0,
                actions_by_id,
                [action],
                store,
                Path(tmpdir),
            )

            assert action.status == "failed"
            assert changed is True
            # State store should NOT change for failed results
            assert store.db.status == "healthy"
