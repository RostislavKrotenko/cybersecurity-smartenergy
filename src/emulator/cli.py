"""CLI entry-point for the SmartEnergy Emulator.

Usage examples
--------------
# Batch mode (default, 1 h, seed=42, CSV output):
python -m src.emulator

# Batch JSONL:
python -m src.emulator --format jsonl --out data/events.jsonl

# Live mode (stream events to JSONL with 500 ms intervals):
python -m src.emulator --live --live-interval-ms 500 --out data/events_live.jsonl

# Live mode with event cap:
python -m src.emulator --live --max-events 500 --out data/events_live.jsonl
"""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from src.emulator.engine import (
    EmulatorEngine,
    stream_jsonl,
    stream_jsonl_infinite,
    write_csv,
    write_jsonl,
)
from src.shared.config_loader import load_yaml
from src.shared.logger import setup_logging


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="smartenergy-emulator",
        description="Generate synthetic SmartEnergy events (batch or live mode).",
    )
    p.add_argument(
        "--days", type=int, default=None,
        help="Simulation length in days. Overrides scenarios.yaml duration_sec. "
             "If omitted the YAML value is used (default 3600 s = 1 h).",
    )
    p.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for deterministic output (default: 42).",
    )
    p.add_argument(
        "--out", type=str, default="data/events.csv",
        help="Output file path (default: data/events.csv).",
    )
    p.add_argument(
        "--format", type=str, choices=["csv", "jsonl"], default="csv",
        help="Output format: csv (default) or jsonl.",
    )
    p.add_argument(
        "--scenario_set", type=str, default="all",
        help="Comma-separated scenario names to inject, or 'all' (default: all).",
    )
    p.add_argument(
        "--start_time", type=str, default=None,
        help="Simulation start time in ISO-8601 (e.g. 2026-02-26T10:00:00Z). "
             "Defaults to value in scenarios.yaml.",
    )
    p.add_argument(
        "--components", type=str, default="config/components.yaml",
        help="Path to components.yaml (default: config/components.yaml).",
    )
    p.add_argument(
        "--scenarios", type=str, default="config/scenarios.yaml",
        help="Path to scenarios.yaml (default: config/scenarios.yaml).",
    )
    # Live mode flags
    p.add_argument(
        "--live", action="store_true", default=False,
        help="Enable live streaming mode (events written to JSONL with delays).",
    )
    p.add_argument(
        "--live-interval-ms", type=int, default=1000,
        help="Interval between event writes in live mode, ms (default: 1000).",
    )
    p.add_argument(
        "--max-events", type=int, default=None,
        help="Maximum number of events to generate (optional cap).",
    )
    p.add_argument(
        "--raw-log-dir", type=str, default=None,
        help="Directory for raw syslog-style log files (api.log, auth.log, edge.log). "
             "Only used in --live mode.",
    )
    p.add_argument(
        "--log-level", type=str, default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO).",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    setup_logging(args.log_level)

    components_cfg = load_yaml(args.components)
    scenarios_cfg = load_yaml(args.scenarios)

    start_time: datetime | None = None
    if args.start_time:
        start_time = datetime.fromisoformat(args.start_time.replace("Z", "+00:00"))

    engine = EmulatorEngine(
        components_cfg=components_cfg,
        scenarios_cfg=scenarios_cfg,
        seed=args.seed,
        days=args.days,
        start_time=start_time,
        scenario_set=args.scenario_set,
    )

    out_path = Path(args.out)

    if args.live:
        # ---- Live mode: stream to JSONL with delays ----
        if out_path.suffix not in (".jsonl", ".ndjson"):
            out_path = out_path.with_suffix(".jsonl")
        interval_sec = args.live_interval_ms / 1000.0
        raw_log_dir = Path(args.raw_log_dir) if args.raw_log_dir else None
        print(f"Emulator live mode -> {out_path}")
        print(f"  interval: {args.live_interval_ms} ms, max_events: {args.max_events or 'infinite'}")
        if raw_log_dir:
            print(f"  raw logs -> {raw_log_dir}/")
        print("  Press Ctrl+C to stop.")
        try:
            if args.max_events is not None:
                # Finite live mode (legacy)
                count = stream_jsonl(
                    engine=engine,
                    path=out_path,
                    interval_sec=interval_sec,
                    max_events=args.max_events,
                )
                print(f"Emulator live mode complete: {count} events -> {out_path}")
            else:
                # Infinite live mode (default for live)
                stream_jsonl_infinite(
                    engine=engine,
                    path=out_path,
                    interval_sec=interval_sec,
                    raw_log_dir=raw_log_dir,
                )
        except KeyboardInterrupt:
            print("\nEmulator stopped by user.")
    else:
        # ---- Batch mode: generate all then write ----
        events = engine.run()
        if args.max_events and len(events) > args.max_events:
            events = events[:args.max_events]

        if args.format == "jsonl":
            if out_path.suffix not in (".jsonl", ".ndjson", ".json"):
                out_path = out_path.with_suffix(".jsonl")
            write_jsonl(events, out_path)
        else:
            if out_path.suffix != ".csv":
                out_path = out_path.with_suffix(".csv")
            write_csv(events, out_path)

        print(f"Emulator batch complete: {len(events)} events -> {out_path}")


if __name__ == "__main__":
    main()
