"""Командний інтерфейс аналізатора SmartEnergy."""

from __future__ import annotations

import argparse

from src.analyzer.pipeline import (
    create_file_adapters,
    run_pipeline_with_adapters,
    watch_pipeline,
)
from src.shared.logger import setup_logging


def build_parser() -> argparse.ArgumentParser:
    """Створює та налаштовує CLI-парсер аргументів аналізатора."""
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
        help=("Comma-separated policy names to analyse. Use 'all' for all available. Default: all"),
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
        "--rolling-window-min",
        type=float,
        default=5.0,
        help=(
            "Rolling analysis window in minutes (watch mode only). "
            "Events older than this are dropped before each analysis cycle "
            "so that the incident set refreshes over time. Default: 5."
        ),
    )
    p.add_argument(
        "--actions-path",
        type=str,
        default=None,
        help="Path to actions.jsonl for closed-loop output (watch mode only). "
        "When set, the analyzer emits response actions for the Emulator.",
    )
    p.add_argument(
        "--applied-path",
        type=str,
        default=None,
        help="Path to actions_applied.jsonl (ACK input from Emulator). "
        "Analyzer reads this to update action statuses and component state.",
    )
    p.add_argument(
        "--state-input",
        type=str,
        default=None,
        help=(
            "Optional JSONL path with raw state-change events (e.g. data/live/events.jsonl). "
            "Used only to update component state.csv in watch mode."
        ),
    )
    p.add_argument(
        "--integration-mode",
        default="active",
        choices=["dry-run", "shadow", "active"],
        help=(
            "Режим інтеграційного rollout: dry-run (лише план), "
            "shadow (план + shadow CSV) або active (емісія у ActionSink). "
            "За замовчуванням: active"
        ),
    )
    p.add_argument(
        "--shadow-actions-path",
        type=str,
        default=None,
        help=(
            "Опційний шлях CSV для запланованих дій у режимі dry-run/shadow. "
            "За замовчуванням: out/actions_dry_run.csv або out/actions_shadow.csv."
        ),
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level. Default: INFO",
    )
    return p


def main(argv: list[str] | None = None) -> None:
    """Запускає аналізатор у разовому або watch-режимі залежно від параметрів."""
    args = build_parser().parse_args(argv)
    setup_logging(args.log_level)

    policy_list = (
        [p.strip() for p in args.policies.split(",")] if args.policies != "all" else ["all"]
    )

    if args.watch:
        watch_pipeline(
            input_path=args.input,
            out_dir=args.out_dir,
            policy_names=policy_list,
            config_dir=args.config_dir,
            horizon_days=args.horizon_days,
            poll_interval_sec=args.poll_interval_ms / 1000.0,
            rolling_window_min=args.rolling_window_min,
            actions_path=args.actions_path,
            applied_path=args.applied_path,
            state_input_path=args.state_input,
            integration_mode=args.integration_mode,
            shadow_actions_path=args.shadow_actions_path,
        )
    else:
        event_source, action_sink = create_file_adapters(
            events_path=args.input,
            actions_path=args.actions_path,
            actions_csv_path=f"{args.out_dir}/actions.csv" if args.actions_path else None,
        )

        run_pipeline_with_adapters(
            event_source=event_source,
            action_sink=action_sink,
            out_dir=args.out_dir,
            policy_names=policy_list,
            config_dir=args.config_dir,
            horizon_days=args.horizon_days,
            integration_mode=args.integration_mode,
            shadow_actions_path=args.shadow_actions_path,
        )


if __name__ == "__main__":
    main()
