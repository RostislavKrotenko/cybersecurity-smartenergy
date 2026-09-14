"""Наскрізний тест: інцидент -> рішення -> emit_actions -> apply_actions емулятора.

Перевіряє повний closed-loop цикл:
1. Набір атакувальних подій потрапляє в детектор.
2. Детектор формує алерти, а корелятор групує їх в інциденти.
3. Двигун рішень перетворює інциденти на конкретні Action-об'єкти.
4. Дії записуються в JSONL файл і зчитуються назад.
5. Емулятор застосовує дії до WorldState.
6. Зміни WorldState видимі через блокування акторів, rate limiting тощо
   та генерують відповідні state-change події.
7. Події зміни стану підтверджують дії (emitted -> applied).
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
    """Генерує *n* brute-force auth_failure подій з *ip*."""
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
    """Генерує *n* rate_exceeded подій і degraded service_status."""
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
    """Повний closed-loop: події -> detect -> correlate -> decide -> apply."""

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

        # Актор або IP має бути заблокований.
        assert len(state.auth.blocked_actors) > 0 or len(state.auth.blocked_ips) > 0
        # Має бути згенерована state-change подія.
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
        """Записує дії в JSONL, читає назад і перевіряє WorldState."""
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

            # Перевірка, що файл створений і є валідним JSONL.
            assert os.path.exists(path)
            with open(path) as f:
                lines = f.readlines()
            assert len(lines) == 2
            for line in lines:
                obj = json.loads(line)
                assert "action" in obj

            # Зчитування через reader емулятора.
            read_acts, _offset = read_new_actions(path, 0)
            assert len(read_acts) == 2

            # Застосування до WorldState.
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
    """Перевіряє, що state-change події маркують дії як 'applied'."""

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
            status="applied",  # вже застосовано
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
        """Наскрізно: emit action -> застосування емулятором -> state-change -> confirm."""
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

        # Емулятор застосовує дію.
        state = WorldState()
        state_events = apply_action(state, action)
        assert len(state_events) > 0
        assert is_rate_limited(state)

        # Аналізатор підтверджує дію за state-change подіями.
        changed = _confirm_actions(state_events, index)
        assert changed is True
        assert action.status == "applied"

        # Сховище стану також підхоплює зміну.
        store = ComponentStateStore()
        store.process_events(state_events)
        assert store.gateway.status == "rate_limited"
        assert "rps=50" in store.gateway.details
        assert store.gateway.ttl_sec == 300.0


class TestActionAckMechanism:
    """Тести механізму ACK-файла (actions_applied.jsonl)."""

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
        assert len(a.action_id) == 12  # "ACT-" + 8 hex-символів

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
            # Створення дії.
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

            # Запис ACK.
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

            # Дія має бути позначена як applied.
            assert action.status == "applied"
            assert changed is True

            # Сховище стану має відобразити зміну.
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
            # Сховище стану не має змінюватися для failed-результатів.
            assert store.db.status == "healthy"
