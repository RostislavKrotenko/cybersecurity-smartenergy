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
        description="Аналізатор SmartEnergy — легка SIEM: детекція, кореляція, звіт",
    )
    p.add_argument(
        "--input",
        default="data/events.csv",
        help="Вхідний файл (CSV або JSONL). Формат визначається за розширенням. "
        "За замовчуванням: data/events.csv",
    )
    p.add_argument(
        "--out-dir",
        default="out",
        help="Директорія виходу. За замовчуванням: out/",
    )
    p.add_argument(
        "--policies",
        default="all",
        help="Назви політик через кому. Значення 'all' запускає всі доступні політики.",
    )
    p.add_argument(
        "--config-dir",
        default="config",
        help="Директорія з rules.yaml і policies.yaml. За замовчуванням: config/",
    )
    p.add_argument(
        "--horizon-days",
        type=float,
        default=None,
        help=(
            "Горизонт аналізу в днях. Якщо не заданий, використовується часовий "
            "діапазон вхідних даних (мінімум 1 година)."
        ),
    )
    p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Seed генератора випадковості для відтворюваності симуляції реагування.",
    )
    p.add_argument(
        "--watch",
        action="store_true",
        default=False,
        help="Увімкнути watch-режим: читати input JSONL tail-режимом і переаналізовувати нові дані.",
    )
    p.add_argument(
        "--poll-interval-ms",
        type=int,
        default=1000,
        help="Інтервал опитування у watch-режимі, мс (за замовчуванням: 1000).",
    )
    p.add_argument(
        "--rolling-window-min",
        type=float,
        default=5.0,
        help=(
            "Rolling-вікно аналізу у хвилинах (тільки watch-режим). "
            "Старіші події відкидаються перед кожним циклом, щоб набір "
            "інцидентів оновлювався з часом. За замовчуванням: 5."
        ),
    )
    p.add_argument(
        "--actions-path",
        type=str,
        default=None,
        help="Шлях до actions.jsonl для closed-loop виходу (тільки watch-режим). "
        "Якщо задано, аналізатор емітить дії реагування для емулятора.",
    )
    p.add_argument(
        "--applied-path",
        type=str,
        default=None,
        help="Шлях до actions_applied.jsonl (ACK-вхід від емулятора). "
        "Аналізатор читає його для оновлення статусів дій і стану компонентів.",
    )
    p.add_argument(
        "--state-input",
        type=str,
        default=None,
        help=(
            "Опційний JSONL шлях із сирими подіями зміни стану, наприклад "
            "data/live/events.jsonl. Використовується лише для оновлення "
            "state.csv у watch-режимі."
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
        help="Рівень логування. За замовчуванням: INFO",
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
