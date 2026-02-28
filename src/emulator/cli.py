"""Командний інтерфейс емулятора SmartEnergy."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from src.emulator.engine import (
    EmulatorEngine,
    stream_demo_highrate,
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
        "--days",
        type=int,
        default=None,
        help="Simulation length in days. Overrides scenarios.yaml duration_sec. "
        "If omitted the YAML value is used (default 3600 s = 1 h).",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for deterministic output (default: 42).",
    )
    p.add_argument(
        "--out",
        type=str,
        default="data/events.csv",
        help="Output file path (default: data/events.csv).",
    )
    p.add_argument(
        "--format",
        type=str,
        choices=["csv", "jsonl"],
        default="csv",
        help="Output format: csv (default) or jsonl.",
    )
    p.add_argument(
        "--scenario_set",
        type=str,
        default="all",
        help="Comma-separated scenario names to inject, or 'all' (default: all).",
    )
    p.add_argument(
        "--start_time",
        type=str,
        default=None,
        help="Simulation start time in ISO-8601 (e.g. 2026-02-26T10:00:00Z). "
        "Defaults to value in scenarios.yaml.",
    )
    p.add_argument(
        "--components",
        type=str,
        default="config/components.yaml",
        help="Path to components.yaml (default: config/components.yaml).",
    )
    p.add_argument(
        "--scenarios",
        type=str,
        default="config/scenarios.yaml",
        help="Path to scenarios.yaml (default: config/scenarios.yaml).",
    )
    # Live mode flags
    p.add_argument(
        "--live",
        action="store_true",
        default=False,
        help="Enable live streaming mode (events written to JSONL with delays).",
    )
    p.add_argument(
        "--live-interval-ms",
        type=int,
        default=1000,
        help="Interval between event writes in live mode, ms (default: 1000).",
    )
    p.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="Maximum number of events to generate (optional cap).",
    )
    p.add_argument(
        "--raw-log-dir",
        type=str,
        default=None,
        help="Directory for raw syslog-style log files (api.log, auth.log, system.log). "
        "Only used in --live mode.",
    )
    p.add_argument(
        "--csv-out",
        type=str,
        default=None,
        help="Also write a CSV file in live mode (append batches). Example: data/live/events.csv",
    )
    p.add_argument(
        "--profile",
        type=str,
        default="default",
        choices=["default", "demo_high_rate"],
        help="Emulation profile. demo_high_rate: short cycles, frequent attacks "
        "(default: default).",
    )
    p.add_argument(
        "--attack-rate",
        type=float,
        default=1.0,
        help="Attack rate multiplier: >1 increases attack count and frequency, "
        "<1 decreases. (default: 1.0).",
    )
    p.add_argument(
        "--attack-every-sec",
        type=float,
        default=10.0,
        help="Seconds between attack burst injections in demo_high_rate "
        "profile (default: 10). Round-robin across 5 scenarios.",
    )
    p.add_argument(
        "--background-events-per-tick",
        type=int,
        default=20,
        help="Number of benign background events emitted per tick in "
        "demo_high_rate profile (default: 20).",
    )
    p.add_argument(
        "--max-file-mb",
        type=float,
        default=50.0,
        help="Max output file size in MB before rotation (default: 50). "
        "Applies to JSONL and CSV in live mode.",
    )
    p.add_argument(
        "--log-level",
        type=str,
        default="INFO",
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
        profile=args.profile,
        attack_rate=args.attack_rate,
    )

    out_path = Path(args.out)

    if args.live:
        # ---- Live mode: stream to JSONL with delays ----
        if out_path.suffix not in (".jsonl", ".ndjson"):
            out_path = out_path.with_suffix(".jsonl")
        interval_sec = args.live_interval_ms / 1000.0
        raw_log_dir = Path(args.raw_log_dir) if args.raw_log_dir else None
        csv_out = Path(args.csv_out) if args.csv_out else None
        print(f"Emulator live mode -> {out_path}")
        print(
            f"  interval: {args.live_interval_ms} ms, max_events: {args.max_events or 'infinite'}"
        )
        print(f"  profile: {args.profile}, attack_rate: {args.attack_rate}")
        if args.profile == "demo_high_rate":
            print(
                f"  attack_every: {args.attack_every_sec}s, "
                f"bg/tick: {args.background_events_per_tick}, "
                f"max_file: {args.max_file_mb} MB"
            )
        if raw_log_dir:
            print(f"  raw logs -> {raw_log_dir}/")
        if csv_out:
            print(f"  csv out  -> {csv_out}")
        print("  Press Ctrl+C to stop.")
        try:
            if args.profile == "demo_high_rate":
                # Purpose-built high-rate demo loop
                stream_demo_highrate(
                    engine=engine,
                    path=out_path,
                    interval_sec=interval_sec,
                    attack_every_sec=args.attack_every_sec,
                    bg_per_tick=args.background_events_per_tick,
                    max_file_mb=args.max_file_mb,
                    raw_log_dir=raw_log_dir,
                    csv_out=csv_out,
                )
            elif args.max_events is not None:
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
                    csv_out=csv_out,
                )
        except KeyboardInterrupt:
            print("\nEmulator stopped by user.")
    else:
        # ---- Batch mode: generate all then write ----
        events = engine.run()
        if args.max_events and len(events) > args.max_events:
            events = events[: args.max_events]

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
