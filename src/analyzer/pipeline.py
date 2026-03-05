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
from src.contracts.action import Action
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
    all_actions: list[Action] = []       # accumulated actions for CSV
    acted_incidents: set[str] = set()    # incident IDs already handled

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
            inc_counter, all_incidents = _incremental_detect(
                pre_events, rules_cfg, policies_cfg, selected, inc_counter,
            )
            _write_live_output(
                all_incidents, selected, policies_cfg, horizon_sec, out_p,
            )
            # Decision engine for pre-loaded incidents
            if actions_path and all_incidents:
                new_actions = decide(all_incidents, acted_incidents)
                if new_actions:
                    emit_actions(new_actions, actions_path)
                    all_actions.extend(new_actions)
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

            if new_events:
                iteration += 1

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
                        write_actions_csv(all_actions, str(out_p / "actions.csv"))

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

                # ── Recompute metrics & write output ────────────────
                _write_live_output(
                    all_incidents, selected, policies_cfg, horizon_sec, out_p,
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
    write_report_txt(all_metrics, incidents, control_ranking, str(out_p / "report.txt"))


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
