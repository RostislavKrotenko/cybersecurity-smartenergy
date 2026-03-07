"""Tests for closed-loop: Action contract, world state, decision engine, atomic writes."""

from __future__ import annotations

import json
import os
import tempfile
import time

import pytest

from src.contracts.action import Action, ActionType
from src.contracts.incident import Incident
from src.analyzer.decision import decide, emit_actions, write_actions_csv
from src.analyzer.reporter import _atomic_write
from src.emulator.world import (
    WorldState,
    apply_action,
    expire_state,
    is_actor_blocked,
    is_isolated,
    is_rate_limited,
    read_new_actions,
)


# ═══════════════════════════════════════════════════════════════════════════
#  Action contract tests
# ═══════════════════════════════════════════════════════════════════════════


class TestActionContract:
    def test_action_to_json_roundtrip(self):
        a = Action(
            ts_utc="2026-03-01T12:00:00Z",
            action="enable_rate_limit",
            target_component="gateway",
            params={"rps": 50, "burst": 100, "duration_sec": 300},
            reason="INC-0001: availability_attack/critical",
            correlation_id="INC-0001",
        )
        j = a.to_json()
        restored = Action.from_json(j)
        assert restored.action == "enable_rate_limit"
        assert restored.params["rps"] == 50
        assert restored.params["burst"] == 100
        assert restored.correlation_id == "INC-0001"

    def test_action_from_dict(self):
        d = {
            "ts_utc": "2026-03-01T12:00:00Z",
            "action": "block_actor",
            "target_component": "auth",
            "params": '{"actor":"unknown","duration_sec":600}',
            "reason": "test",
        }
        a = Action.from_dict(d)
        assert a.action == "block_actor"
        assert a.params["actor"] == "unknown"
        assert a.params["duration_sec"] == 600

    def test_action_csv_row(self):
        a = Action(
            ts_utc="2026-03-01T12:00:00Z",
            action="backup_db",
            target_component="db",
            params={"name": "snap_1"},
            reason="test",
            correlation_id="INC-0002",
        )
        row = a.to_csv_row()
        assert "backup_db" in row
        assert "db" in row
        assert "INC-0002" in row

    def test_action_csv_header(self):
        header = Action.csv_header()
        assert "ts_utc" in header
        assert "action" in header
        assert "target_component" in header

    def test_all_action_types_exist(self):
        expected = [
            "enable_rate_limit", "disable_rate_limit",
            "isolate_component", "release_isolation",
            "block_actor", "unblock_actor",
            "backup_db", "restore_db",
        ]
        for name in expected:
            assert ActionType(name) is not None


# ═══════════════════════════════════════════════════════════════════════════
#  World state / apply_actions tests
# ═══════════════════════════════════════════════════════════════════════════


class TestWorldState:
    def _make_action(self, action: str, target: str = "gateway",
                     params: dict | None = None, cor_id: str = "") -> Action:
        return Action(
            ts_utc="2026-03-01T12:00:00Z",
            action=action,
            target_component=target,
            params=params or {},
            reason="test",
            correlation_id=cor_id,
        )

    def test_enable_rate_limit(self):
        state = WorldState()
        assert not is_rate_limited(state)
        action = self._make_action("enable_rate_limit", params={
            "rps": 50, "burst": 100, "duration_sec": 300,
        })
        events = apply_action(state, action)
        assert is_rate_limited(state)
        assert state.gateway.rate_limit_rps == 50
        assert len(events) >= 1
        assert events[0].event == "rate_limit_enabled"

    def test_disable_rate_limit(self):
        state = WorldState()
        state.gateway.rate_limit_enabled = True
        state.gateway.rate_limit_rps = 50
        action = self._make_action("disable_rate_limit")
        events = apply_action(state, action)
        assert not is_rate_limited(state)
        assert events[0].event == "rate_limit_disabled"

    def test_isolate_component(self):
        state = WorldState()
        assert not is_isolated(state, "api")
        action = self._make_action(
            "isolate_component", target="api",
            params={"duration_sec": 120},
        )
        events = apply_action(state, action)
        assert is_isolated(state, "api")
        assert state.api.status == "isolated"
        assert events[0].event == "isolation_enabled"

    def test_release_isolation(self):
        state = WorldState()
        state.api.status = "isolated"
        action = self._make_action("release_isolation", target="api")
        events = apply_action(state, action)
        assert not is_isolated(state, "api")
        assert events[0].event == "isolation_released"

    def test_block_actor(self):
        state = WorldState()
        action = self._make_action("block_actor", target="auth", params={
            "actor": "attacker", "ip": "10.0.0.1", "duration_sec": 600,
        })
        events = apply_action(state, action)
        assert is_actor_blocked(state, "attacker", "")
        assert is_actor_blocked(state, "", "10.0.0.1")
        assert not is_actor_blocked(state, "legit_user", "192.168.1.1")
        assert events[0].event == "actor_blocked"

    def test_unblock_actor(self):
        state = WorldState()
        state.auth.blocked_actors["attacker"] = time.monotonic() + 600
        action = self._make_action("unblock_actor", target="auth", params={
            "actor": "attacker",
        })
        events = apply_action(state, action)
        assert not is_actor_blocked(state, "attacker", "")
        assert events[0].event == "actor_unblocked"

    def test_backup_db(self):
        state = WorldState()
        initial_snaps = len(state.db.snapshots)
        action = self._make_action("backup_db", target="db", params={
            "name": "snap_test",
        })
        events = apply_action(state, action)
        assert len(state.db.snapshots) == initial_snaps + 1
        assert "snap_test" in state.db.snapshots
        assert events[0].event == "backup_created"

    def test_restore_db(self):
        state = WorldState()
        action = self._make_action("restore_db", target="db", params={
            "snapshot": "snapshot_init",
        })
        events = apply_action(state, action)
        assert state.db.status == "restoring"
        assert events[0].event == "restore_started"

    def test_restore_db_missing_snapshot(self):
        state = WorldState()
        action = self._make_action("restore_db", target="db", params={
            "snapshot": "nonexistent",
        })
        events = apply_action(state, action)
        assert state.db.status == "healthy"
        assert len(events) == 0

    def test_expire_state_rate_limit(self):
        state = WorldState()
        state.gateway.rate_limit_enabled = True
        state.gateway.rate_limit_expires = time.monotonic() - 1  # already expired
        events = expire_state(state)
        assert not state.gateway.rate_limit_enabled
        assert len(events) >= 1

    def test_expire_state_db_restore(self):
        state = WorldState()
        state.db.status = "restoring"
        state.db.restoring_until = time.monotonic() - 1  # already done
        events = expire_state(state)
        assert state.db.status == "healthy"
        assert any(e.event == "restore_completed" for e in events)


# ═══════════════════════════════════════════════════════════════════════════
#  Decision engine tests
# ═══════════════════════════════════════════════════════════════════════════


class TestDecisionEngine:
    def _make_incident(self, inc_id: str, threat: str, sev: str = "high",
                       component: str = "api", desc: str = "") -> Incident:
        return Incident(
            incident_id=inc_id,
            policy="baseline",
            threat_type=threat,
            severity=sev,
            component=component,
            event_count=5,
            start_ts="2026-03-01T12:00:00Z",
            detect_ts="2026-03-01T12:00:30Z",
            recover_ts="2026-03-01T12:02:30Z",
            mttd_sec=30.0,
            mttr_sec=120.0,
            impact_score=0.7,
            description=desc or f"Test {threat}",
            response_action="notify",
        )

    def test_decide_credential_attack(self):
        inc = self._make_incident("INC-0001", "credential_attack",
                                  desc="Brute-force: 8 auth failures from 10.0.0.1")
        acted = set()
        actions = decide([inc], acted)
        assert len(actions) >= 1
        assert actions[0].action == "block_actor"
        assert "INC-0001" in acted

    def test_decide_availability_attack(self):
        inc = self._make_incident("INC-0002", "availability_attack")
        acted = set()
        actions = decide([inc], acted)
        assert any(a.action == "enable_rate_limit" for a in actions)

    def test_decide_integrity_attack(self):
        inc = self._make_incident("INC-0003", "integrity_attack")
        acted = set()
        actions = decide([inc], acted)
        assert any(a.action == "isolate_component" for a in actions)

    def test_decide_outage(self):
        inc = self._make_incident("INC-0004", "outage", component="db")
        acted = set()
        actions = decide([inc], acted)
        action_names = [a.action for a in actions]
        assert "backup_db" in action_names
        assert "restore_db" in action_names

    def test_decide_no_duplicate(self):
        inc = self._make_incident("INC-0005", "credential_attack")
        acted = set()
        actions1 = decide([inc], acted)
        actions2 = decide([inc], acted)
        assert len(actions1) >= 1
        assert len(actions2) == 0

    def test_emit_actions_to_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "actions.jsonl")
            a1 = Action(
                ts_utc="2026-03-01T12:00:00Z",
                action="enable_rate_limit",
                target_component="gateway",
                params={"rps": 50},
                reason="test",
            )
            emit_actions([a1], path)
            with open(path) as f:
                lines = f.readlines()
            assert len(lines) == 1
            obj = json.loads(lines[0])
            assert obj["action"] == "enable_rate_limit"


# ═══════════════════════════════════════════════════════════════════════════
#  Action JSONL reader tests
# ═══════════════════════════════════════════════════════════════════════════


class TestReadNewActions:
    def test_read_new_actions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "actions.jsonl")
            a1 = Action(
                ts_utc="2026-03-01T12:00:00Z",
                action="block_actor",
                target_component="auth",
                params={"actor": "bad", "duration_sec": 60},
                reason="test",
            )
            with open(path, "w") as f:
                f.write(a1.to_json() + "\n")

            actions, offset = read_new_actions(path, 0)
            assert len(actions) == 1
            assert actions[0].action == "block_actor"
            assert offset > 0

            # Second read: no new data
            actions2, offset2 = read_new_actions(path, offset)
            assert len(actions2) == 0
            assert offset2 == offset

            # Append another action
            a2 = Action(
                ts_utc="2026-03-01T12:01:00Z",
                action="backup_db",
                target_component="db",
                params={"name": "snap_2"},
                reason="test",
            )
            with open(path, "a") as f:
                f.write(a2.to_json() + "\n")

            actions3, _offset3 = read_new_actions(path, offset)
            assert len(actions3) == 1
            assert actions3[0].action == "backup_db"


# ═══════════════════════════════════════════════════════════════════════════
#  Atomic write tests
# ═══════════════════════════════════════════════════════════════════════════


class TestAtomicWrite:
    def test_atomic_write_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.csv")
            _atomic_write(path, "header\nrow1\n")
            assert os.path.exists(path)
            with open(path) as f:
                content = f.read()
            assert content == "header\nrow1\n"

    def test_atomic_write_replaces_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.csv")
            _atomic_write(path, "v1\n")
            _atomic_write(path, "v2\n")
            with open(path) as f:
                content = f.read()
            assert content == "v2\n"

    def test_atomic_write_no_partial_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.csv")
            _atomic_write(path, "complete content\n")
            # No .tmp files should remain
            tmp_files = [f for f in os.listdir(tmpdir)
                         if f.endswith(".tmp")]
            assert len(tmp_files) == 0

    def test_actions_csv_atomic(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "actions.csv")
            actions = [
                Action(
                    ts_utc="2026-03-01T12:00:00Z",
                    action="enable_rate_limit",
                    target_component="gateway",
                    params={"rps": 50},
                    reason="test",
                    correlation_id="INC-0001",
                ),
                Action(
                    ts_utc="2026-03-01T12:01:00Z",
                    action="block_actor",
                    target_component="auth",
                    params={"actor": "bad"},
                    reason="test",
                    correlation_id="INC-0002",
                ),
            ]
            write_actions_csv(actions, path)
            with open(path) as f:
                lines = f.readlines()
            assert len(lines) == 3  # header + 2 rows
            assert lines[0].strip().startswith("action_id")


# ═══════════════════════════════════════════════════════════════════════════
#  Metrics correctness (integration with actions)
# ═══════════════════════════════════════════════════════════════════════════


class TestMetricsWithActions:
    def test_metrics_compute_with_incidents(self):
        from src.analyzer.metrics import compute
        from src.contracts.incident import Incident

        incidents = [
            Incident(
                incident_id="INC-001",
                policy="baseline",
                threat_type="availability_attack",
                severity="critical",
                component="api",
                event_count=15,
                start_ts="2026-03-01T12:00:00Z",
                detect_ts="2026-03-01T12:00:15Z",
                recover_ts="2026-03-01T12:03:15Z",
                mttd_sec=15.0,
                mttr_sec=180.0,
                impact_score=0.98,
                description="DDoS flood",
                response_action="rate_limit",
            ),
        ]
        m = compute(incidents, "baseline", horizon_sec=3600)
        assert m.availability_pct < 100.0
        assert m.total_downtime_hr > 0
        assert m.mean_mttd_min == pytest.approx(0.25, abs=0.01)
        assert m.mean_mttr_min == pytest.approx(3.0, abs=0.01)

    def test_metrics_empty_incidents(self):
        from src.analyzer.metrics import compute
        m = compute([], "baseline", horizon_sec=3600)
        assert m.availability_pct == 100.0
        assert m.total_downtime_hr == 0.0


# ═══════════════════════════════════════════════════════════════════════════
#  End-to-end closed-loop test
# ═══════════════════════════════════════════════════════════════════════════


class TestEndToEndClosedLoop:
    """Verify the full feedback cycle: events -> detect -> decide -> apply."""

    def test_full_closed_loop_cycle(self):
        """Emulate a full cycle: brute-force events -> incident -> action -> world state."""
        from src.analyzer.correlator import correlate
        from src.analyzer.detector import detect
        from src.contracts.event import Event
        from src.shared.config_loader import load_yaml

        rules_cfg = load_yaml("config/rules.yaml")

        # 1. Generate brute-force events (8 auth_failure from same IP)
        events = []
        for i in range(8):
            events.append(Event(
                timestamp=f"2026-03-01T12:00:{i:02d}Z",
                source="gateway-01",
                component="api",
                event="auth_failure",
                key="username",
                value="admin",
                severity="high",
                actor="unknown",
                ip="192.168.8.55",
                tags="auth;failure",
                correlation_id="COR-DEMO-TEST",
            ))

        # 2. Detect -> should produce alerts
        alerts = detect(events, rules_cfg)
        assert len(alerts) > 0

        # 3. Correlate -> should produce incidents
        incidents = correlate(alerts, "baseline")
        assert len(incidents) > 0
        for i, inc in enumerate(incidents):
            inc.incident_id = f"INC-{i+1:04d}"

        # 4. Decide -> should produce block_actor action
        acted = set()
        actions = decide(incidents, acted)
        assert len(actions) >= 1
        assert any(a.action == "block_actor" for a in actions)

        # 5. Apply to world state -> actor should be blocked
        state = WorldState()
        for action in actions:
            apply_action(state, action)

        # The block_actor action should have blocked something
        assert (
            len(state.auth.blocked_actors) > 0
            or len(state.auth.blocked_ips) > 0
        )

    def test_actions_roundtrip_through_file(self):
        """Write actions to JSONL, read them back, apply to world."""
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
                    action="block_actor",
                    target_component="auth",
                    params={"actor": "bad", "ip": "10.0.0.99", "duration_sec": 60},
                    reason="test",
                    correlation_id="INC-0002",
                ),
            ]
            emit_actions(actions, path)

            # Read back
            read_actions, _offset = read_new_actions(path, 0)
            assert len(read_actions) == 2

            # Apply to world
            state = WorldState()
            all_events = []
            for a in read_actions:
                evts = apply_action(state, a)
                all_events.extend(evts)

            assert is_rate_limited(state)
            assert is_actor_blocked(state, "bad", "10.0.0.99")
            assert len(all_events) >= 2

    def test_availability_critical_triggers_isolation(self):
        """Critical availability_attack should trigger both rate_limit AND isolation."""
        inc = Incident(
            incident_id="INC-0010",
            policy="baseline",
            threat_type="availability_attack",
            severity="critical",
            component="api",
            event_count=15,
            start_ts="2026-03-01T12:00:00Z",
            detect_ts="2026-03-01T12:00:15Z",
            recover_ts="2026-03-01T12:03:15Z",
            mttd_sec=15.0,
            mttr_sec=180.0,
            impact_score=0.98,
            description="DDoS flood: 15 rate_exceeded on api-gw-01 + service impact",
            response_action="rate_limit",
        )
        acted = set()
        actions = decide([inc], acted)
        action_names = [a.action for a in actions]
        assert "enable_rate_limit" in action_names
        assert "isolate_component" in action_names

    def test_availability_high_no_isolation(self):
        """High (non-critical) availability_attack should NOT trigger isolation."""
        inc = Incident(
            incident_id="INC-0011",
            policy="baseline",
            threat_type="availability_attack",
            severity="high",
            component="api",
            event_count=10,
            start_ts="2026-03-01T12:00:00Z",
            detect_ts="2026-03-01T12:00:15Z",
            recover_ts="2026-03-01T12:03:15Z",
            mttd_sec=15.0,
            mttr_sec=180.0,
            impact_score=0.7,
            description="DDoS flood",
            response_action="rate_limit",
        )
        acted = set()
        actions = decide([inc], acted)
        action_names = [a.action for a in actions]
        assert "enable_rate_limit" in action_names
        assert "isolate_component" not in action_names

