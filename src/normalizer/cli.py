"""Командний інтерфейс нормалізатора SmartEnergy."""

from __future__ import annotations

import argparse

from src.normalizer.pipeline import NormalizerPipeline
from src.shared.logger import setup_logging


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="normalizer",
        description="SmartEnergy Normalizer -- raw logs -> Event Contract CSV/JSONL",
    )
    p.add_argument(
        "--inputs",
        default="logs/*.log",
        help="Glob pattern for input raw log files (default: logs/*.log)",
    )
    p.add_argument(
        "--mapping",
        default="config/mapping.yaml",
        help="Path to mapping config (default: config/mapping.yaml)",
    )
    p.add_argument(
        "--out",
        default="data/events.csv",
        help="Output path -- Event Contract format (default: data/events.csv). "
        "In follow mode with .jsonl extension, appends JSONL.",
    )
    p.add_argument(
        "--quarantine",
        default="out/quarantine.csv",
        help="Quarantine CSV for rejected lines (default: out/quarantine.csv)",
    )
    p.add_argument(
        "--stats",
        default="out/normalize_stats.json",
        help="Stats JSON path (default: out/normalize_stats.json)",
    )
    p.add_argument(
        "--timezone",
        default="UTC",
        help=(
            "Timezone of source logs. Timestamps are treated as being in this "
            "timezone and converted to UTC. Default: UTC. "
            "Examples: Europe/Kyiv, US/Eastern"
        ),
    )
    # Follow (live) mode flags
    p.add_argument(
        "--follow",
        action="store_true",
        default=False,
        help="Enable follow mode: tail input logs continuously and append "
        "normalized events to --out (JSONL recommended).",
    )
    p.add_argument(
        "--poll-interval-ms",
        type=int,
        default=1000,
        help="Poll interval for follow mode, ms (default: 1000).",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    setup_logging(args.log_level)

    pipeline = NormalizerPipeline(
        mapping_path=args.mapping,
        tz_name=args.timezone,
    )

    if args.follow:
        pipeline.follow(
            input_glob=args.inputs,
            out_path=args.out,
            poll_interval_sec=args.poll_interval_ms / 1000.0,
        )
    else:
        pipeline.run(
            input_glob=args.inputs,
            out_path=args.out,
            quarantine_path=args.quarantine,
            stats_path=args.stats,
        )


if __name__ == "__main__":
    main()
