"""Оркестратор аналітичного конвеєра SmartEnergy.

Конвеєр включає етапи: завантаження подій, детекція, кореляція,
розрахунок метрик, формування звітів і (опційно) емісію дій реагування.
Модуль підтримує plug-and-play інтеграцію через інтерфейси `EventSource`,
`ActionSink` і `ActionFeedback`.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

from src.analyzer.correlator import correlate
from src.analyzer.decision import decide, write_actions_csv
from src.analyzer.detector import detect
from src.analyzer.metrics import compute
from src.analyzer.policy_engine import (
    get_modifiers,
    list_policy_names,
    load_policies,
    rank_controls,
)
from src.analyzer.reporter import (
    write_incidents_csv,
    write_plots,
    write_report_html,
    write_report_txt,
    write_results_csv,
)
from src.analyzer.state_store import ComponentStateStore
from src.contracts.action import Action, ActionAck
from src.contracts.event import Event
from src.contracts.interfaces import ActionFeedback, ActionSink, EventSource
from src.shared.config_loader import load_yaml
from src.shared.time_utils import parse_iso_ts as _ts

log = logging.getLogger(__name__)


def load_events_csv(path: str) -> list[Event]:
    """Завантажує події з CSV файлу."""
    events: list[Event] = []
    with open(path, encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            events.append(Event.from_dict(row))
    log.info("Loaded %d events from CSV: %s", len(events), path)
    return events


def load_events_jsonl(path: str) -> list[Event]:
    """Завантажує події з JSONL файлу."""
    events: list[Event] = []
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                events.append(Event.from_dict(obj))
            except (json.JSONDecodeError, KeyError) as exc:
                log.warning("Skipping JSONL line %d: %s", line_no, exc)
    log.info("Loaded %d events from JSONL: %s", len(events), path)
    return events


def load_events(path: str) -> list[Event]:
    """Автовизначає формат та завантажує події."""
    p = Path(path)
    if p.suffix in (".jsonl", ".ndjson"):
        return load_events_jsonl(path)
    return load_events_csv(path)


def load_events_from_source(event_source: EventSource, limit: int = 10000) -> list[Event]:
    """Завантажує події через адаптер `EventSource`.

    Args:
        event_source: Реалізація джерела подій (файл, Kafka, SIEM тощо).
        limit: Максимальна кількість подій для читання.

    Returns:
        Список об'єктів `Event`.
    """
    events = event_source.read_batch(limit=limit)
    log.info("Loaded %d events from EventSource", len(events))
    return events


def run_pipeline(
    input_path: str,
    out_dir: str = "out",
    policy_names: list[str] | None = None,
    config_dir: str = "config",
    horizon_days: float | None = None,
) -> dict[str, Any]:
    """Виконує повний аналітичний конвеєр та записує результати.

    Args:
        input_path: Шлях до вхідного файлу.
        out_dir: Директорія виводу.
        policy_names: Список політик для аналізу.
        config_dir: Директорія конфігурації.
        horizon_days: Горизонт аналізу в днях.

    Returns:
        Словник з результатами аналізу.
    """
    events = load_events(input_path)
    if not events:
        log.warning("No events loaded from %s — nothing to analyse.", input_path)
        return {"events": [], "alerts": {}, "incidents": {}, "metrics": {}, "control_ranking": []}

    if horizon_days is not None and horizon_days > 0:
        horizon_sec = horizon_days * 86400
    else:
        if len(events) > 1:
            start = _ts(events[0].timestamp)
            end = _ts(events[-1].timestamp)
            span = (end - start).total_seconds()
            horizon_sec = max(span, 3600)
        else:
            horizon_sec = 3600

    rules_cfg = load_yaml(f"{config_dir}/rules.yaml")
    policies_cfg = load_policies(config_dir)

    available = list_policy_names(policies_cfg)
    if policy_names is None or policy_names == ["all"]:
        selected = available
    else:
        selected = [p for p in policy_names if p in available]
        missing = set(policy_names) - set(available)
        if missing:
            log.warning("Unknown policies ignored: %s", ", ".join(sorted(missing)))

    all_metrics = []
    all_incidents: list[Any] = []
    results: dict[str, Any] = {
        "events": events,
        "alerts": {},
        "incidents": {},
        "metrics": {},
        "control_ranking": [],
    }

    for pname in selected:
        modifiers = get_modifiers(policies_cfg, pname)

        alerts = detect(events, rules_cfg, policy_modifiers=modifiers)
        log.info("Policy %-10s  alerts=%d", pname, len(alerts))

        incidents = correlate(alerts, pname, policy_modifiers=modifiers)
        log.info("Policy %-10s  incidents=%d", pname, len(incidents))

        m = compute(incidents, pname, horizon_sec=horizon_sec)
        log.info(
            "Policy %-10s  availability=%.2f%%  downtime=%.4f h",
            pname,
            m.availability_pct,
            m.total_downtime_hr,
        )

        results["alerts"][pname] = alerts
        results["incidents"][pname] = incidents
        results["metrics"][pname] = m

        all_metrics.append(m)
        all_incidents.extend(incidents)

    control_ranking = rank_controls(policies_cfg, selected)
    results["control_ranking"] = control_ranking

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    write_results_csv(all_metrics, str(out / "results.csv"))
    write_incidents_csv(all_incidents, str(out / "incidents.csv"))
    write_report_txt(all_metrics, all_incidents, control_ranking, str(out / "report.txt"))
    write_report_html(all_metrics, all_incidents, control_ranking, str(out / "report.html"))
    write_plots(all_metrics, str(out / "plots"))

    log.info("Pipeline complete. Outputs in %s/", out_dir)
    return results


def watch_pipeline(
    input_path: str,
    out_dir: str = "out",
    policy_names: list[str] | None = None,
    config_dir: str = "config",
    horizon_days: float | None = None,
    poll_interval_sec: float = 1.0,
    rolling_window_min: float = 5.0,
    actions_path: str | None = None,
    applied_path: str | None = None,
    state_input_path: str | None = None,
) -> None:
    """Зворотно сумісна обгортка над watch-конвеєром на адаптерах."""
    event_source, state_source, action_sink, action_feedback = create_file_live_adapters(
        events_path=input_path,
        state_events_path=state_input_path,
        actions_path=actions_path,
        applied_path=applied_path,
        actions_csv_path=f"{out_dir}/actions.csv" if actions_path else None,
    )

    watch_pipeline_with_adapters(
        event_source=event_source,
        out_dir=out_dir,
        policy_names=policy_names,
        config_dir=config_dir,
        horizon_days=horizon_days,
        poll_interval_sec=poll_interval_sec,
        rolling_window_min=rolling_window_min,
        state_event_source=state_source,
        action_sink=action_sink,
        action_feedback=action_feedback,
    )


def watch_pipeline_with_adapters(
    event_source: EventSource,
    out_dir: str = "out",
    policy_names: list[str] | None = None,
    config_dir: str = "config",
    horizon_days: float | None = None,
    poll_interval_sec: float = 1.0,
    rolling_window_min: float = 5.0,
    state_event_source: EventSource | None = None,
    action_sink: ActionSink | None = None,
    action_feedback: ActionFeedback | None = None,
) -> None:
    """Live watch-конвеєр на основі абстрактних адаптерів.

    Усі live-операції введення/виведення виконуються через інтерфейси:
    `EventSource`, `ActionSink` та `ActionFeedback`.
    """
    rules_cfg = load_yaml(f"{config_dir}/rules.yaml")
    policies_cfg = load_policies(config_dir)
    available = list_policy_names(policies_cfg)
    if policy_names is None or policy_names == ["all"]:
        selected = available
    else:
        selected = [p for p in policy_names if p in available]

    iteration = 0
    tick_counter = 0
    rolling_sec = rolling_window_min * 60.0
    inc_counter = 0
    all_incidents: list[Any] = []
    all_actions: list[Action] = []
    acted_incidents: set[str] = set()
    state_store = ComponentStateStore()
    last_action_emit_ts: dict[str, float] = {}
    actions_by_cor_id: dict[str, list[Action]] = {}
    actions_by_id: dict[str, Action] = {}
    feedback_offset: Any = None

    if horizon_days is not None and horizon_days > 0:
        horizon_sec = horizon_days * 86400
    else:
        horizon_sec = max(rolling_sec, 3600.0)

    out_p = Path(out_dir)
    out_p.mkdir(parents=True, exist_ok=True)

    pre_events = event_source.read_batch()
    if pre_events:
        state_store.process_events(pre_events)
        inc_counter, all_incidents = _incremental_detect(
            pre_events, rules_cfg, policies_cfg, selected, inc_counter,
        )
        state_store.tick()
        state_store.write_csv(str(out_p / "state.csv"))
        _write_live_output(
            all_incidents, selected, policies_cfg, horizon_sec, out_p,
            actions_count=len(all_actions),
        )

    if state_event_source is not None:
        pre_state_events = state_event_source.read_batch()
        if pre_state_events:
            state_store.process_events(pre_state_events)
            state_store.tick()
            state_store.write_csv(str(out_p / "state.csv"))

    print("Analyzer watch mode (adapter-based)")
    print(
        f"  poll interval: {poll_interval_sec:.1f}s, "
        f"rolling window: {rolling_window_min:.0f} min, "
        f"policies: {', '.join(selected)}"
    )
    if action_sink is not None:
        print("  actions -> ActionSink")
    if action_feedback is not None:
        print("  applied <- ActionFeedback")
    if state_event_source is not None:
        print("  state   <- EventSource (state stream)")
    print("  Press Ctrl+C to stop.")

    event_iter = event_source.read_stream(poll_interval_sec=poll_interval_sec)
    state_iter = (
        state_event_source.read_stream(poll_interval_sec=poll_interval_sec)
        if state_event_source is not None
        else None
    )

    try:
        while True:
            tick_counter += 1
            new_events = next(event_iter)
            state_events = next(state_iter) if state_iter is not None else []

            acks_changed = False
            if action_feedback is not None:
                acks, feedback_offset = action_feedback.read_acks(since=feedback_offset)
                if acks:
                    acks_changed = _apply_acks(
                        acks,
                        actions_by_id,
                        all_actions,
                        state_store,
                    )
                if acks_changed:
                    write_actions_csv(all_actions, str(out_p / "actions.csv"))
                    state_store.write_csv(str(out_p / "state.csv"))

            if new_events:
                iteration += 1
                state_store.process_events(new_events)

                if actions_by_cor_id and _confirm_actions(new_events, actions_by_cor_id):
                    write_actions_csv(all_actions, str(out_p / "actions.csv"))

                if state_events:
                    state_store.process_events(state_events)
                    if actions_by_cor_id and _confirm_actions(state_events, actions_by_cor_id):
                        write_actions_csv(all_actions, str(out_p / "actions.csv"))

                inc_counter, new_incs = _incremental_detect(
                    new_events, rules_cfg, policies_cfg, selected, inc_counter,
                )
                all_incidents.extend(new_incs)

                if action_sink is not None and new_incs:
                    new_actions = decide(new_incs, acted_incidents)
                    new_actions = _throttle_actions(new_actions, last_action_emit_ts)
                    new_actions = _apply_restore_lock(new_actions, all_actions)
                    if new_actions:
                        tracking_ids = action_sink.emit_batch(new_actions)
                        for action, tracking_id in zip(new_actions, tracking_ids):
                            action.action_id = tracking_id
                        all_actions.extend(new_actions)
                        for a in new_actions:
                            actions_by_cor_id.setdefault(a.correlation_id, []).append(a)
                            actions_by_id[a.action_id] = a
                        write_actions_csv(all_actions, str(out_p / "actions.csv"))
                        log.info(
                            "EMITTED %d new actions (%d total)",
                            len(new_actions), len(all_actions),
                        )

                if rolling_sec > 0 and all_incidents:
                    latest = max(_ts(i.start_ts) for i in all_incidents)
                    cutoff = latest - timedelta(seconds=rolling_sec)
                    before = len(all_incidents)
                    all_incidents = [i for i in all_incidents if _ts(i.start_ts) >= cutoff]
                    expired = before - len(all_incidents)
                    if expired:
                        log.debug("Expired %d old incidents", expired)

                state_store.tick()
                state_store.write_csv(str(out_p / "state.csv"))
                _write_live_output(
                    all_incidents, selected, policies_cfg, horizon_sec, out_p,
                    actions_count=len(all_actions),
                )

                log.info(
                    "[tick %d] iter %d: +%d events (+%d state), +%d incidents, %d active, %d actions total",
                    tick_counter,
                    iteration,
                    len(new_events),
                    len(state_events),
                    len(new_incs),
                    len(all_incidents),
                    len(all_actions),
                )
            elif state_events:
                state_store.process_events(state_events)
                if actions_by_cor_id and _confirm_actions(state_events, actions_by_cor_id):
                    write_actions_csv(all_actions, str(out_p / "actions.csv"))
                state_store.tick()
                state_store.write_csv(str(out_p / "state.csv"))
                log.info(
                    "[tick %d] state-only update: +%d state events",
                    tick_counter,
                    len(state_events),
                )
            elif tick_counter % 10 == 0:
                state_store.tick()
                state_store.write_csv(str(out_p / "state.csv"))
                log.info(
                    "[tick %d] Heartbeat: %d active incidents, %d actions, waiting...",
                    tick_counter,
                    len(all_incidents),
                    len(all_actions),
                )
    except KeyboardInterrupt:
        print(
            f"\nWatch stopped. Active incidents: {len(all_incidents)}, "
            f"Total actions: {len(all_actions)}"
        )
    finally:
        event_source.close()
        if state_event_source is not None:
            state_event_source.close()
        if action_feedback is not None:
            action_feedback.close()
        if action_sink is not None:
            action_sink.close()


_ACK_TO_STATE_EVENT: dict[str, str] = {
    "rate_limit_enabled": "rate_limit_enabled",
    "rate_limit_disabled": "rate_limit_disabled",
    "isolation_enabled": "isolation_enabled",
    "isolation_released": "isolation_released",
    "actor_blocked": "actor_blocked",
    "actor_unblocked": "actor_unblocked",
    "restore_started": "restore_started",
    "restore_completed": "restore_completed",
    "restore_failed": "restore_failed",
    "backup_created": "backup_created",
    "db_backup_created": "db_backup_created",
    "db_corruption_detected": "db_corruption_detected",
    "network_degraded": "network_degraded",
    "network_reset_applied": "network_reset_applied",
    "network_recovered": "network_recovered",
}


def _read_acks(
    path: str,
    offset: int,
    actions_by_id: dict[str, Action],
    all_actions: list[Action],
    state_store: ComponentStateStore,
    out_p: Path,
) -> tuple[int, bool]:
    """Читає нові ACK-записи з `path`, починаючи з `offset`.

    Для кожного ACK оновлює статус відповідної дії та, за потреби,
    генерує синтетичну state-change подію для `state_store`.

    Returns:
        Кортеж `(new_offset, changed)`.
    """
    changed = False
    try:
        size = os.path.getsize(path)
    except OSError:
        return offset, changed

    if size <= offset:
        return offset, changed

    acks: list[ActionAck] = []
    with open(path, encoding="utf-8") as fh:
        fh.seek(offset)
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ack = ActionAck.from_json(line)
                acks.append(ack)
            except (json.JSONDecodeError, KeyError) as exc:
                log.debug("Skipping bad ACK line: %s", exc)
        new_offset = fh.tell()

    changed = _apply_acks(acks, actions_by_id, all_actions, state_store)
    if acks:
        log.info("ACKS READ: %d from %s", len(acks), path)

    return new_offset, changed


def _apply_acks(
    acks: list[ActionAck],
    actions_by_id: dict[str, Action],
    all_actions: list[Action],
    state_store: ComponentStateStore,
) -> bool:
    """Застосовує ACK до структур відстеження дій і стану в пам'яті."""
    changed = False
    if not acks:
        return changed

    if actions_by_id:
        by_id = actions_by_id
    else:
        by_id = {a.action_id: a for a in all_actions}

    for ack in acks:
        act = by_id.get(ack.action_id)
        if act:
            new_status = "applied" if ack.result == "success" else "failed"
            if act.status != new_status:
                old_status = act.status
                act.status = new_status
                changed = True
                log.info(
                    "ACK: action_id=%s %s -> %s (was %s, cor=%s)",
                    ack.action_id,
                    ack.action,
                    act.status,
                    old_status,
                    ack.correlation_id,
                )

        se = ack.state_event
        if se and se in _ACK_TO_STATE_EVENT and ack.result == "success":
            synthetic = Event(
                timestamp=ack.applied_ts_utc,
                source=f"{ack.target_component}-01",
                component=ack.target_component,
                event=se,
                key="action_result",
                value=_build_ack_value(ack, act),
                severity="high",
                actor="system",
                ip="",
                unit="",
                tags="action;state_change",
                correlation_id=ack.correlation_id,
            )
            state_store.process_events([synthetic])
            log.info(
                "STATE from ACK: %s -> %s (cor=%s)",
                ack.target_component,
                se,
                ack.correlation_id,
            )

    return changed


def _build_ack_value(ack: ActionAck, act: Action | None) -> str:
    """Формує поле `value` для синтетичної state-change події з ACK."""
    if act is None:
        return ack.action
    params = act.params
    if ack.state_event == "rate_limit_enabled":
        rps = params.get("rps", 100)
        burst = params.get("burst", 200)
        dur = params.get("duration_sec", 300)
        return f"rps={rps},burst={burst},dur={dur}"
    if ack.state_event == "isolation_enabled":
        dur = params.get("duration_sec", 120)
        return f"duration={dur}"
    if ack.state_event == "actor_blocked":
        actor = params.get("actor", "")
        ip = params.get("ip", "")
        dur = params.get("duration_sec", 600)
        return f"actor={actor},ip={ip},duration={dur}"
    if ack.state_event == "restore_started":
        snap = params.get("snapshot", "")
        return f"snapshot={snap}"
    if ack.state_event in ("restore_completed", "restore_failed"):
        snap = params.get("snapshot", "")
        return f"snapshot={snap}"
    if ack.state_event in ("backup_created", "db_backup_created"):
        return params.get("name", "snapshot")
    if ack.state_event == "network_degraded":
        latency = params.get("latency_ms", 0)
        drop = params.get("drop_rate", 0)
        ttl = params.get("ttl_sec", 0)
        return f"latency_ms={latency},drop_rate={drop},ttl_sec={ttl}"
    if ack.state_event in ("network_reset_applied", "network_recovered"):
        return "healthy"
    return ack.action


_CONFIRM_EVENTS = frozenset({
    "rate_limit_enabled",
    "rate_limit_disabled",
    "isolation_enabled",
    "isolation_released",
    "actor_blocked",
    "actor_unblocked",
    "restore_started",
    "restore_completed",
    "backup_created",
    "db_backup_created",
    "network_degraded",
    "network_reset_applied",
    "network_recovered",
})


def _confirm_actions(
    events: list[Event],
    actions_index: dict[str, list[Action]],
) -> bool:
    """Підтверджує застосування дій за state-change подіями.

    Returns:
        `True`, якщо оновлено статус хоча б однієї дії.
    """
    changed = False
    for ev in events:
        if "state_change" not in ev.tags:
            continue
        if ev.event not in _CONFIRM_EVENTS:
            continue
        cor_id = ev.correlation_id
        if not cor_id or cor_id not in actions_index:
            continue
        for act in actions_index[cor_id]:
            if act.status != "applied":
                act.status = "applied"
                changed = True
                log.info(
                    "ACTION CONFIRMED: %s (cor=%s) -> applied",
                    act.action, cor_id,
                )
    return changed


def _incremental_detect(
    events: list[Event],
    rules_cfg: dict[str, Any],
    policies_cfg: dict[str, Any],
    selected: list[str],
    inc_counter: int,
) -> tuple[int, list[Any]]:
    """Виконує `detect -> correlate` для подій у межах кожної політики.

    Returns:
        Оновлений лічильник інцидентів і список нових інцидентів.
    """
    new_incidents: list[Any] = []
    for pname in selected:
        modifiers = get_modifiers(policies_cfg, pname)
        alerts = detect(events, rules_cfg, policy_modifiers=modifiers)
        incidents = correlate(alerts, pname, policy_modifiers=modifiers)
        for inc in incidents:
            inc_counter += 1
            inc.incident_id = f"INC-{inc_counter:04d}"
        new_incidents.extend(incidents)
    return inc_counter, new_incidents


def _write_live_output(
    incidents: list[Any],
    selected: list[str],
    policies_cfg: dict[str, Any],
    horizon_sec: float,
    out_p: Path,
    actions_count: int = 0,
) -> None:
    """Обчислює метрики за інцидентами та оновлює live-виходи у `out/`."""
    all_metrics = []
    for pname in selected:
        policy_incs = [i for i in incidents if i.policy == pname]
        m = compute(policy_incs, pname, horizon_sec=horizon_sec)
        all_metrics.append(m)

    control_ranking = rank_controls(policies_cfg, selected)
    write_results_csv(all_metrics, str(out_p / "results.csv"))
    write_incidents_csv(incidents, str(out_p / "incidents.csv"))
    write_report_txt(
        all_metrics, incidents, control_ranking, str(out_p / "report.txt"),
        actions_count=actions_count,
    )


def _throttle_actions(
    actions: list[Action],
    last_emit_ts: dict[str, float],
) -> list[Action]:
    """Приглушує дубльовані дії в межах cooldown-вікон для кожного типу."""
    if not actions:
        return actions

    cooldown_sec: dict[str, float] = {
        "backup_db": 20.0,
        "restore_db": 90.0,
        "degrade_network": 45.0,
        "reset_network": 30.0,
        "enable_rate_limit": 20.0,
        "isolate_component": 20.0,
        "block_actor": 20.0,
    }

    now = time.monotonic()
    kept: list[Action] = []
    dropped = 0

    for a in actions:
        cd = cooldown_sec.get(a.action, 0.0)
        key = f"{a.action}|{a.target_component}|{a.target_id}|{a.params}"
        prev = last_emit_ts.get(key, 0.0)
        if cd > 0 and (now - prev) < cd:
            dropped += 1
            continue
        last_emit_ts[key] = now
        kept.append(a)

    if dropped:
        log.info("THROTTLE: dropped %d duplicate actions by cooldown", dropped)

    return kept


def _apply_restore_lock(
    actions: list[Action],
    all_actions: list[Action],
) -> list[Action]:
    """Блокує нові `restore_db`, доки попереднє відновлення не завершено."""
    if not actions:
        return actions

    has_unresolved_restore = any(
        a.action == "restore_db"
        and a.target_component == "db"
        and a.status in {"pending", "emitted"}
        for a in all_actions
    )

    if not has_unresolved_restore:
        return actions

    kept: list[Action] = []
    blocked = 0
    for a in actions:
        if a.action == "restore_db" and a.target_component == "db":
            blocked += 1
            continue
        kept.append(a)

    if blocked:
        log.info("RESTORE LOCK: blocked %d restore_db actions while previous restore is unresolved", blocked)

    return kept


def _run_analysis(
    events: list[Event],
    rules_cfg: dict[str, Any],
    policies_cfg: dict[str, Any],
    selected: list[str],
    out_dir: str,
    horizon_days: float | None,
) -> dict[str, Any]:
    """Внутрішній helper для повного проходу `detect->correlate->metrics`.

    Returns:
        Словник зі зведенням (`total_incidents`, `total_alerts`).
    """
    if horizon_days is not None and horizon_days > 0:
        horizon_sec = horizon_days * 86400
    else:
        if len(events) > 1:
            start = _ts(events[0].timestamp)
            end = _ts(events[-1].timestamp)
            span = (end - start).total_seconds()
            horizon_sec = max(span, 3600)
        else:
            horizon_sec = 3600

    all_metrics = []
    all_incidents: list[Any] = []
    total_alerts = 0

    for pname in selected:
        modifiers = get_modifiers(policies_cfg, pname)
        alerts = detect(events, rules_cfg, policy_modifiers=modifiers)
        total_alerts += len(alerts)
        incidents = correlate(alerts, pname, policy_modifiers=modifiers)
        m = compute(incidents, pname, horizon_sec=horizon_sec)
        all_metrics.append(m)
        all_incidents.extend(incidents)

    control_ranking = rank_controls(policies_cfg, selected)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_results_csv(all_metrics, str(out / "results.csv"))
    write_incidents_csv(all_incidents, str(out / "incidents.csv"))
    write_report_txt(all_metrics, all_incidents, control_ranking, str(out / "report.txt"))

    return {"total_incidents": len(all_incidents), "total_alerts": total_alerts}


def run_pipeline_with_adapters(
    event_source: EventSource,
    action_sink: ActionSink | None = None,
    out_dir: str = "out",
    policy_names: list[str] | None = None,
    config_dir: str = "config",
    horizon_days: float | None = None,
) -> dict[str, Any]:
    """Запускає конвеєр аналізу через plug-and-play адаптери.

    Args:
        event_source: Реалізація `EventSource` (файл, Kafka, SIEM тощо).
        action_sink: Опційний `ActionSink` для емісії дій реагування.
        out_dir: Директорія для звітів.
        policy_names: Список політик для аналізу.
        config_dir: Директорія конфігурації.
        horizon_days: Горизонт аналізу в днях.

    Returns:
        Словник з результатами аналізу.
    """
    events = event_source.read_batch()
    if not events:
        log.warning("No events from EventSource — nothing to analyse.")
        return {"events": [], "alerts": {}, "incidents": {}, "metrics": {}, "control_ranking": []}

    if horizon_days is not None and horizon_days > 0:
        horizon_sec = horizon_days * 86400
    else:
        if len(events) > 1:
            start = _ts(events[0].timestamp)
            end = _ts(events[-1].timestamp)
            span = (end - start).total_seconds()
            horizon_sec = max(span, 3600)
        else:
            horizon_sec = 3600

    rules_cfg = load_yaml(f"{config_dir}/rules.yaml")
    policies_cfg = load_policies(config_dir)

    available = list_policy_names(policies_cfg)
    if policy_names is None or policy_names == ["all"]:
        selected = available
    else:
        selected = [p for p in policy_names if p in available]

    all_metrics = []
    all_incidents: list[Any] = []
    all_actions: list[Action] = []
    acted_incidents: set[str] = set()
    results: dict[str, Any] = {
        "events": events,
        "alerts": {},
        "incidents": {},
        "metrics": {},
        "actions": [],
        "control_ranking": [],
    }

    for pname in selected:
        modifiers = get_modifiers(policies_cfg, pname)
        alerts = detect(events, rules_cfg, policy_modifiers=modifiers)
        incidents = correlate(alerts, pname, policy_modifiers=modifiers)
        m = compute(incidents, pname, horizon_sec=horizon_sec)

        results["alerts"][pname] = alerts
        results["incidents"][pname] = incidents
        results["metrics"][pname] = m

        all_metrics.append(m)
        all_incidents.extend(incidents)

    if action_sink and all_incidents:
        actions = decide(all_incidents, acted_incidents)
        if actions:
            action_sink.emit_batch(actions)
            all_actions.extend(actions)
            results["actions"] = actions
            log.info("Emitted %d actions via ActionSink", len(actions))

    control_ranking = rank_controls(policies_cfg, selected)
    results["control_ranking"] = control_ranking

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_results_csv(all_metrics, str(out / "results.csv"))
    write_incidents_csv(all_incidents, str(out / "incidents.csv"))
    write_report_txt(all_metrics, all_incidents, control_ranking, str(out / "report.txt"))
    write_report_html(all_metrics, all_incidents, control_ranking, str(out / "report.html"))
    write_plots(all_metrics, str(out / "plots"))

    event_source.close()
    if action_sink:
        action_sink.close()

    log.info("Pipeline (adapters) complete. Outputs in %s/", out_dir)
    return results


def create_file_adapters(
    events_path: str,
    actions_path: str | None = None,
    actions_csv_path: str | None = None,
) -> tuple[EventSource, ActionSink | None]:
    """Створює файлові адаптери для офлайн/CLI запуску конвеєра.

    Args:
        events_path: Шлях до файлу подій (CSV або JSONL).
        actions_path: Опційний шлях до JSONL-файлу дій.
        actions_csv_path: Опційний шлях до CSV-зведення дій.

    Returns:
        Кортеж `(EventSource, ActionSink | None)`.
    """
    from src.adapters.file_adapter import FileActionSink, FileEventSource

    event_source = FileEventSource(events_path)
    action_sink = None
    if actions_path:
        action_sink = FileActionSink(actions_path, csv_path=actions_csv_path)

    return event_source, action_sink


def create_file_live_adapters(
    events_path: str,
    state_events_path: str | None = None,
    actions_path: str | None = None,
    applied_path: str | None = None,
    actions_csv_path: str | None = None,
) -> tuple[EventSource, EventSource | None, ActionSink | None, ActionFeedback | None]:
    """Створює набір файлових адаптерів для live watch-режиму."""
    from src.adapters.file_adapter import FileActionFeedback, FileActionSink, FileEventSource

    event_source = FileEventSource(events_path)
    state_source = None
    if state_events_path and state_events_path != events_path:
        state_source = FileEventSource(state_events_path)

    action_sink = None
    if actions_path:
        action_sink = FileActionSink(actions_path, csv_path=actions_csv_path)

    action_feedback = None
    if applied_path:
        action_feedback = FileActionFeedback(applied_path)

    return event_source, state_source, action_sink, action_feedback

