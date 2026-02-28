"""CLI entry-point for the SmartEnergy Analyzer.

Usage examples
--------------
# Batch mode (CSV input):
python -m src.analyzer --input data/events.csv

# Batch mode (JSONL input):
python -m src.analyzer --input data/events.jsonl

# Watch mode (tail JSONL produced by live emulator):
python -m src.analyzer --input data/events_live.jsonl --watch
"""

from __future__ import annotations

import argparse

from src.analyzer.pipeline import run_pipeline, watch_pipeline
from src.shared.logger import setup_logging


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analyzer",
        description="SmartEnergy Analyzer — light SIEM: detect, correlate, report",
    )
    p.add_argument(
        "--input",
        default="data/events.csv",
        help="Input file (CSV or JSONL). Format auto-detected by extension. "
             "Default: data/events.csv",
    )
    p.add_argument(
        "--out-dir",
        default="out",
        help="Output directory. Default: out/",
    )
    p.add_argument(
        "--policies",
        default="all",
        help=(
            "Comma-separated policy names to analyse. "
            "Use 'all' for all available. Default: all"
        ),
    )
    p.add_argument(
        "--config-dir",
        default="config",
        help="Directory with rules.yaml and policies.yaml. Default: config/",
    )
    p.add_argument(
        "--horizon-days",
        type=float,
        default=None,
        help=(
            "Analysis horizon in days. If omitted, uses the time span "
            "of the input data (minimum 1 hour)."
        ),
    )
    p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed (reserved for stochastic response simulation).",
    )
    # Watch / live mode flags
    p.add_argument(
        "--watch",
        action="store_true",
        default=False,
        help="Enable watch mode: tail the input JSONL and re-analyse on new data.",
    )
    p.add_argument(
        "--poll-interval-ms",
        type=int,
        default=1000,
        help="Poll interval for watch mode, ms (default: 1000).",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level. Default: INFO",
    )
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    setup_logging(args.log_level)

    policy_list = (
        [p.strip() for p in args.policies.split(",")]
        if args.policies != "all"
        else ["all"]
    )

    if args.watch:
        watch_pipeline(
            input_path=args.input,
            out_dir=args.out_dir,
            policy_names=policy_list,
            config_dir=args.config_dir,
            horizon_days=args.horizon_days,
            poll_interval_sec=args.poll_interval_ms / 1000.0,
        )
    else:
        run_pipeline(
            input_path=args.input,
            out_dir=args.out_dir,
            policy_names=policy_list,
            config_dir=args.config_dir,
            horizon_days=args.horizon_days,
        )


if __name__ == "__main__":
    main()
