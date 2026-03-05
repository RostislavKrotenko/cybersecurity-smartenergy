"""Оркестратор: завантаження подій -> детекція -> кореляція -> метрики -> звіт."""

from __future__ import annotations

import csv
import json
import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from src.analyzer.correlator import correlate
from src.analyzer.decision import decide, emit_actions, write_actions_csv
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
from src.shared.config_loader import load_yaml

log = logging.getLogger(__name__)


def _ts(iso: str) -> datetime:
    """Парсить ISO-8601 timestamp у datetime."""
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


# ═══════════════════════════════════════════════════════════════════════════
#  Event loaders
# ═══════════════════════════════════════════════════════════════════════════


def _parse_event(row: dict[str, str]) -> Event:
    """Створює Event зі словника."""
    return Event(
        timestamp=row.get("timestamp", ""),
        source=row.get("source", ""),
        component=row.get("component", ""),
        event=row.get("event", ""),
        key=row.get("key", ""),
        value=str(row.get("value", "")),
        severity=row.get("severity", "low"),
        actor=row.get("actor", ""),
        ip=row.get("ip", ""),
        unit=row.get("unit", ""),
        tags=row.get("tags", ""),
        correlation_id=row.get("correlation_id", ""),
    )


def load_events_csv(path: str) -> list[Event]:
    """Завантажує події з CSV файлу."""
    events: list[Event] = []
    with open(path, encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            events.append(_parse_event(row))
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
                events.append(_parse_event(obj))
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


# ═══════════════════════════════════════════════════════════════════════════
#  Pipeline core
# ═══════════════════════════════════════════════════════════════════════════


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

    # Compute horizon_sec from horizon_days or derive from event time span
    if horizon_days is not None and horizon_days > 0:
        horizon_sec = horizon_days * 86400
    else:
        if len(events) > 1:
            start = _ts(events[0].timestamp)
            end = _ts(events[-1].timestamp)
            span = (end - start).total_seconds()
            horizon_sec = max(span, 3600)  # at least 1 hour
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

    # ── write outputs ────────────────────────────────────────────────────
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    write_results_csv(all_metrics, str(out / "results.csv"))
    write_incidents_csv(all_incidents, str(out / "incidents.csv"))
    write_report_txt(all_metrics, all_incidents, control_ranking, str(out / "report.txt"))
    write_report_html(all_metrics, all_incidents, control_ranking, str(out / "report.html"))
    write_plots(all_metrics, str(out / "plots"))

    log.info("Pipeline complete. Outputs in %s/", out_dir)
    return results


# ═══════════════════════════════════════════════════════════════════════════
#  Watch mode (tail JSONL)
# ═══════════════════════════════════════════════════════════════════════════


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
) -> None:
    """Tail a JSONL file and incrementally detect new incidents.

    Unlike batch mode which re-analyses ALL events from scratch, the watch
    pipeline performs **incremental** detection:

    1. Each poll cycle reads only *newly appended* lines.
    2. Detection + correlation run on the **new events only**, producing
       fresh incidents that get appended to a running incident list.
    3. Incidents older than *rolling_window_min* are expired, so the
       dashboard shows a live, evolving picture instead of a frozen count.
    4. Metrics are recomputed on the active incident set each cycle.
    5. When *actions_path* is provided, the decision engine maps new
       incidents to actions and writes them to actions.jsonl for the
       Emulator to consume (closed-loop).
    """
    rules_cfg = load_yaml(f"{config_dir}/rules.yaml")
    policies_cfg = load_policies(config_dir)
    available = list_policy_names(policies_cfg)
    if policy_names is None or policy_names == ["all"]:
        selected = available
    else:
        selected = [p for p in policy_names if p in available]

    file_offset: int = 0
    iteration = 0
    tick_counter = 0
    rolling_sec = rolling_window_min * 60.0
    inc_counter = 0                      # global incident numbering
    all_incidents: list[Any] = []        # persistent across cycles
    all_actions: list[Action] = []       # accumulated actions for CSV export
    acted_incidents: set[str] = set()    # incident IDs already acted upon
    state_store = ComponentStateStore()  # live component state tracker
    # Map correlation_id -> list of Action objects for status tracking
    _actions_by_cor_id: dict[str, list[Action]] = {}
    # Map action_id -> Action for ACK-based status tracking
    _actions_by_id: dict[str, Action] = {}
    # File offset for tailing actions_applied.jsonl
    _applied_offset: int = 0

    # Horizon: fixed if given, otherwise use the rolling window size
    if horizon_days is not None and horizon_days > 0:
        horizon_sec = horizon_days * 86400
    else:
        horizon_sec = max(rolling_sec, 3600.0)

    out_p = Path(out_dir)
    out_p.mkdir(parents=True, exist_ok=True)

    # If file already exists, pre-load and run initial analysis
    if os.path.isfile(input_path):
        pre_events = load_events(input_path)
        file_offset = os.path.getsize(input_path)
        if pre_events:
            log.info(
                "Watch: pre-loaded %d events (offset=%d)",
                len(pre_events),
                file_offset,
            )
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
            if actions_path and all_incidents:
                new_actions = decide(all_incidents, acted_incidents)
                if new_actions:
                    emit_actions(new_actions, actions_path)
                    all_actions.extend(new_actions)
                    for a in new_actions:
                        _actions_by_cor_id.setdefault(a.correlation_id, []).append(a)
                        _actions_by_id[a.action_id] = a
                    write_actions_csv(all_actions, str(out_p / "actions.csv"))

            log.info("Watch: initial analysis -> %d incidents", len(all_incidents))

    print(f"Analyzer watch mode -> {input_path}")
    print(
        f"  poll interval: {poll_interval_sec:.1f}s, "
        f"rolling window: {rolling_window_min:.0f} min, "
        f"policies: {', '.join(selected)}"
    )
    if actions_path:
        print(f"  actions -> {actions_path} (closed-loop)")
    if applied_path:
        print(f"  applied <- {applied_path} (ACK)")
    print("  Press Ctrl+C to stop.")

    try:
        while True:
            new_events: list[Event] = []
            tick_counter += 1

            if os.path.isfile(input_path):
                current_size = os.path.getsize(input_path)
                if current_size > file_offset:
                    with open(input_path, encoding="utf-8") as fh:
                        fh.seek(file_offset)
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                obj = json.loads(line)
                                new_events.append(_parse_event(obj))
                            except (json.JSONDecodeError, KeyError) as exc:
                                log.debug("Skipping line: %s", exc)
                    file_offset = current_size

            # ── Read ACKs from actions_applied.jsonl ──────────────
            acks_changed = False
            if applied_path and os.path.isfile(applied_path):
                _applied_offset, acks_changed = _read_acks(
                    applied_path, _applied_offset,
                    _actions_by_id, all_actions, state_store,
                    out_p,
                )
                if acks_changed:
                    write_actions_csv(all_actions, str(out_p / "actions.csv"))
                    state_store.write_csv(str(out_p / "state.csv"))

            if new_events:
                iteration += 1

                # ── Update component state from state-change events ──
                state_store.process_events(new_events)

                # ── Confirm applied actions from state-change events ──
                # (fallback for live_direct mode where events.jsonl has state_change)
                if _actions_by_cor_id:
                    if _confirm_actions(new_events, _actions_by_cor_id):
                        write_actions_csv(all_actions, str(out_p / "actions.csv"))

                # ── Detect + correlate ONLY new events ──────────────
                inc_counter, new_incs = _incremental_detect(
                    new_events, rules_cfg, policies_cfg, selected, inc_counter,
                )
                all_incidents.extend(new_incs)

                # ── Decision engine: emit actions for new incidents ──
                if actions_path and new_incs:
                    new_actions = decide(new_incs, acted_incidents)
                    if new_actions:
                        emit_actions(new_actions, actions_path)
                        all_actions.extend(new_actions)
                        for a in new_actions:
                            _actions_by_cor_id.setdefault(a.correlation_id, []).append(a)
                            _actions_by_id[a.action_id] = a
                        write_actions_csv(all_actions, str(out_p / "actions.csv"))
                        log.info(
                            "EMITTED %d new actions (%d total)",
                            len(new_actions), len(all_actions),
                        )

                # ── Expire old incidents outside the rolling window ─
                if rolling_sec > 0 and all_incidents:
                    latest = max(_ts(i.start_ts) for i in all_incidents)
                    cutoff = latest - timedelta(seconds=rolling_sec)
                    before = len(all_incidents)
                    all_incidents = [
                        i for i in all_incidents if _ts(i.start_ts) >= cutoff
                    ]
                    expired = before - len(all_incidents)
                    if expired:
                        log.debug("Expired %d old incidents", expired)

                # ── Tick TTLs and write state.csv ─────────────────
                state_store.tick()
                state_store.write_csv(str(out_p / "state.csv"))

                # ── Recompute metrics & write output ────────────────
                _write_live_output(
                    all_incidents, selected, policies_cfg, horizon_sec, out_p,
                    actions_count=len(all_actions),
                )

                log.info(
                    "[tick %d] iter %d: +%d events, +%d incidents, %d active, %d actions total",
                    tick_counter,
                    iteration,
                    len(new_events),
                    len(new_incs),
                    len(all_incidents),
                    len(all_actions),
                )
            elif tick_counter % 10 == 0:
                # Tick TTLs even when idle so state.csv reflects decay
                state_store.tick()
                state_store.write_csv(str(out_p / "state.csv"))
                log.info(
                    "[tick %d] Heartbeat: %d active incidents, %d actions, waiting...",
                    tick_counter,
                    len(all_incidents),
                    len(all_actions),
                )

            time.sleep(poll_interval_sec)
    except KeyboardInterrupt:
        print(
            f"\nWatch stopped. Active incidents: {len(all_incidents)}, "
            f"Total actions: {len(all_actions)}"
        )


# ── ACK reader (actions_applied.jsonl) ────────────────────────────────────

# Map ACK state_event -> synthetic Event for the state_store
_ACK_TO_STATE_EVENT: dict[str, str] = {
    "rate_limit_enabled": "rate_limit_enabled",
    "rate_limit_disabled": "rate_limit_disabled",
    "isolation_enabled": "isolation_enabled",
    "isolation_released": "isolation_released",
    "actor_blocked": "actor_blocked",
    "actor_unblocked": "actor_unblocked",
    "restore_started": "restore_started",
    "backup_created": "backup_created",
}


def _read_acks(
    path: str,
    offset: int,
    actions_by_id: dict[str, Action],
    all_actions: list[Action],
    state_store: "ComponentStateStore",
    out_p: Path,
) -> tuple[int, bool]:
    """Read new ACK lines from *path* starting at *offset*.

    For each ACK, marks the corresponding Action as 'applied' (or 'failed')
    and feeds a synthetic state-change event into the state_store so that
    component status updates even in live_normalized mode.

    Returns (new_offset, changed).
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

    for ack in acks:
        # Update action status
        act = actions_by_id.get(ack.action_id)
        if act and act.status != ack.result:
            old_status = act.status
            act.status = "applied" if ack.result == "success" else "failed"
            changed = True
            log.info(
                "ACK: action_id=%s %s -> %s (was %s, cor=%s)",
                ack.action_id, ack.action, act.status, old_status,
                ack.correlation_id,
            )

        # Feed state_store with a synthetic state-change event
        se = ack.state_event
        if se and se in _ACK_TO_STATE_EVENT and ack.result == "success":
            # Build a synthetic Event so the state_store picks it up
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
                ack.target_component, se, ack.correlation_id,
            )

    if acks:
        log.info("ACKS READ: %d from %s", len(acks), path)

    return new_offset, changed


def _build_ack_value(ack: ActionAck, act: Action | None) -> str:
    """Build the value string for a synthetic state-change event from an ACK."""
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
    if ack.state_event == "backup_created":
        return params.get("name", "snapshot")
    return ack.action


# ── action confirmation from state-change events ──────────────────────────

# State-change event types that confirm an action was applied
_CONFIRM_EVENTS = frozenset({
    "rate_limit_enabled",
    "rate_limit_disabled",
    "isolation_enabled",
    "isolation_released",
    "actor_blocked",
    "actor_unblocked",
    "restore_started",
    "backup_created",
})


def _confirm_actions(
    events: list[Event],
    actions_index: dict[str, list[Action]],
) -> bool:
    """Scan *events* for state-change confirmations and mark matching actions as 'applied'.

    Returns True if any action status was updated.
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


# ── Watch-mode helpers ──────────────────────────────────────────────────────


def _incremental_detect(
    events: list[Event],
    rules_cfg: dict[str, Any],
    policies_cfg: dict[str, Any],
    selected: list[str],
    inc_counter: int,
) -> tuple[int, list[Any]]:
    """Run detect -> correlate on *events* for each policy.

    Returns updated inc_counter and new incidents with globally unique IDs.
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
    """Compute metrics on *incidents* and write results / incidents / report."""
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


def _run_analysis(
    events: list[Event],
    rules_cfg: dict[str, Any],
    policies_cfg: dict[str, Any],
    selected: list[str],
    out_dir: str,
    horizon_days: float | None,
) -> dict[str, Any]:
    """Internal helper: run detect -> correlate -> metrics -> write for all policies.

    Returns a dict with summary info (total_incidents, total_alerts).
    """
    # Compute horizon_sec from horizon_days or derive from event time span
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
