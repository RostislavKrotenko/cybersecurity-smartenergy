"""Pipeline — orchestrator: load events -> detect -> correlate -> metrics -> report.

Supports CSV and JSONL input. In watch mode the pipeline tails a JSONL
file and re-runs analysis incrementally each time new lines appear.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from src.analyzer.correlator import correlate
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
from datetime import datetime

from src.contracts.event import Event
from src.shared.config_loader import load_yaml

log = logging.getLogger(__name__)


def _ts(iso: str) -> datetime:
    """Parse ISO-8601 timestamp to datetime."""
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


# ═══════════════════════════════════════════════════════════════════════════
#  Event loaders
# ═══════════════════════════════════════════════════════════════════════════

def _parse_event(row: dict[str, str]) -> Event:
    """Build an Event from a dict (row from CSV DictReader or JSON object)."""
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
    """Load events from a CSV file that follows the Event Contract."""
    events: list[Event] = []
    with open(path, encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            events.append(_parse_event(row))
    log.info("Loaded %d events from CSV: %s", len(events), path)
    return events


def load_events_jsonl(path: str) -> list[Event]:
    """Load events from a JSONL (one JSON object per line) file."""
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
    """Auto-detect format by file extension and load events."""
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
    """Execute the full analysis pipeline and write outputs.

    Returns
    -------
    dict with keys: events, alerts (per-policy), incidents (per-policy),
    metrics (per-policy), control_ranking.
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
            pname, m.availability_pct, m.total_downtime_hr,
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
) -> None:
    """Tail a JSONL file and re-run the pipeline on each batch of new lines.

    The function blocks until interrupted (Ctrl+C). It keeps a file offset
    and re-reads only newly appended lines, then re-runs the full
    detect -> correlate -> metrics -> report chain on the accumulated events.
    """
    rules_cfg = load_yaml(f"{config_dir}/rules.yaml")
    policies_cfg = load_policies(config_dir)
    available = list_policy_names(policies_cfg)
    if policy_names is None or policy_names == ["all"]:
        selected = available
    else:
        selected = [p for p in policy_names if p in available]

    accumulated_events: list[Event] = []
    file_offset: int = 0
    iteration = 0

    # If file already exists pre-load existing lines
    if os.path.isfile(input_path):
        accumulated_events = load_events(input_path)
        file_offset = os.path.getsize(input_path)
        log.info("Watch: pre-loaded %d events (offset=%d)", len(accumulated_events), file_offset)

    print(f"Analyzer watch mode -> {input_path}")
    print(f"  poll interval: {poll_interval_sec:.1f}s, policies: {', '.join(selected)}")
    print("  Press Ctrl+C to stop.")

    try:
        while True:
            new_events: list[Event] = []

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
                accumulated_events.extend(new_events)
                iteration += 1
                log.info(
                    "Watch iteration %d: +%d new, %d total events",
                    iteration, len(new_events), len(accumulated_events),
                )

                # Re-run full analysis on accumulated state
                _run_analysis(
                    events=accumulated_events,
                    rules_cfg=rules_cfg,
                    policies_cfg=policies_cfg,
                    selected=selected,
                    out_dir=out_dir,
                    horizon_days=horizon_days,
                )

            time.sleep(poll_interval_sec)
    except KeyboardInterrupt:
        print(f"\nWatch stopped. Total events processed: {len(accumulated_events)}")


def _run_analysis(
    events: list[Event],
    rules_cfg: dict[str, Any],
    policies_cfg: dict[str, Any],
    selected: list[str],
    out_dir: str,
    horizon_days: float | None,
) -> None:
    """Internal helper: run detect -> correlate -> metrics -> write for all policies."""
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

    for pname in selected:
        modifiers = get_modifiers(policies_cfg, pname)
        alerts = detect(events, rules_cfg, policy_modifiers=modifiers)
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
