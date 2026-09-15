"""Командний інтерфейс аналізатора SmartEnergy."""

from __future__ import annotations

import argparse
import os

from src.adapters.file_adapter import (
    FileActionFeedback,
    FileActionSink,
    FileEventSource,
)
from src.analyzer.live_runtime import (
    watch_pipeline_with_recovery,
)
from src.analyzer.pipeline import (
    run_pipeline_with_adapters,
)
from src.shared.logger import setup_logging


def _optional_environment_path(
    name: str,
) -> str | None:
    """Повертає непорожній шлях зі змінної середовища."""
    value = os.getenv(name, "").strip()
    return value or None


def create_file_adapters(
    events_path: str,
    actions_path: str | None = None,
    actions_csv_path: str | None = None,
) -> tuple[
    FileEventSource,
    FileActionSink | None,
]:
    """Створює файлові адаптери для разового запуску.

    Аргументи:
        events_path: Шлях до CSV або JSONL-файла подій.
        actions_path: Опційний JSONL-файл дій.
        actions_csv_path: Опційний CSV-файл дій.

    Повертає:
        Джерело подій і опційний приймач дій.
    """
    event_source = FileEventSource(
        events_path
    )
    action_sink = None

    if actions_path:
        action_sink = FileActionSink(
            actions_path,
            csv_path=actions_csv_path,
        )

    return event_source, action_sink


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
    integration_mode: str = "active",
    shadow_actions_path: str | None = None,
) -> None:
    """Запускає потоковий аналіз із checkpoint та відновленням.

    JSONL checkpoint-и зберігають позиції читання, а CSV-файли
    у директорії результатів відновлюють інциденти, дії та стан.
    """
    event_source = FileEventSource(
        input_path,
        checkpoint_path=(
            _optional_environment_path(
                "ANALYZER_EVENT_CHECKPOINT_PATH"
            )
        ),
    )

    state_source = None

    if (
        state_input_path
        and state_input_path != input_path
    ):
        state_source = FileEventSource(
            state_input_path,
            checkpoint_path=(
                _optional_environment_path(
                    "ANALYZER_STATE_CHECKPOINT_PATH"
                )
            ),
        )

    action_sink = None

    if actions_path:
        # CSV тут навмисно не передається.
        # Повний actions.csv веде live runtime.
        # Інакше close() файлового адаптера після рестарту
        # перезапише історію лише діями поточного процесу.
        action_sink = FileActionSink(
            actions_path
        )

    action_feedback = None

    if applied_path:
        action_feedback = FileActionFeedback(
            applied_path,
            checkpoint_path=(
                _optional_environment_path(
                    "ANALYZER_ACK_CHECKPOINT_PATH"
                )
            ),
        )

    watch_pipeline_with_recovery(
        event_source=event_source,
        out_dir=out_dir,
        policy_names=policy_names,
        config_dir=config_dir,
        horizon_days=horizon_days,
        poll_interval_sec=(
            poll_interval_sec
        ),
        rolling_window_min=(
            rolling_window_min
        ),
        state_event_source=state_source,
        action_sink=action_sink,
        action_feedback=action_feedback,
        integration_mode=integration_mode,
        shadow_actions_path=(
            shadow_actions_path
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    """Створює CLI-парсер аналізатора."""
    parser = argparse.ArgumentParser(
        prog="analyzer",
        description=(
            "Аналізатор SmartEnergy: "
            "детекція, кореляція, "
            "метрики та активне реагування"
        ),
    )

    parser.add_argument(
        "--input",
        default="data/events.csv",
        help=(
            "Вхідний CSV або JSONL-файл. "
            "За замовчуванням: data/events.csv"
        ),
    )
    parser.add_argument(
        "--out-dir",
        default="out",
        help=(
            "Директорія результатів. "
            "За замовчуванням: out/"
        ),
    )
    parser.add_argument(
        "--policies",
        default="all",
        help=(
            "Назви політик через кому або all."
        ),
    )
    parser.add_argument(
        "--config-dir",
        default="config",
        help=(
            "Директорія rules.yaml "
            "і policies.yaml."
        ),
    )
    parser.add_argument(
        "--horizon-days",
        type=float,
        default=None,
        help=(
            "Горизонт аналізу в днях."
        ),
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help=(
            "Seed генератора для "
            "відтворюваної симуляції."
        ),
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        default=False,
        help=(
            "Увімкнути потокове читання JSONL."
        ),
    )
    parser.add_argument(
        "--poll-interval-ms",
        type=int,
        default=1000,
        help=(
            "Інтервал опитування у мілісекундах."
        ),
    )
    parser.add_argument(
        "--rolling-window-min",
        type=float,
        default=5.0,
        help=(
            "Розмір рухомого вікна у хвилинах."
        ),
    )
    parser.add_argument(
        "--actions-path",
        type=str,
        default=None,
        help=(
            "Шлях до actions.jsonl."
        ),
    )
    parser.add_argument(
        "--applied-path",
        type=str,
        default=None,
        help=(
            "Шлях до actions_applied.jsonl."
        ),
    )
    parser.add_argument(
        "--state-input",
        type=str,
        default=None,
        help=(
            "Опційний JSONL-потік "
            "змін стану компонентів."
        ),
    )
    parser.add_argument(
        "--integration-mode",
        default="active",
        choices=[
            "dry-run",
            "shadow",
            "active",
        ],
        help=(
            "Режим інтеграції."
        ),
    )
    parser.add_argument(
        "--shadow-actions-path",
        type=str,
        default=None,
        help=(
            "CSV-план дій для shadow "
            "або dry-run режиму."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=[
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
        ],
        help="Рівень журналювання.",
    )

    return parser


def main(
    argv: list[str] | None = None,
) -> None:
    """Запускає Analyzer у разовому або потоковому режимі."""
    args = build_parser().parse_args(argv)
    setup_logging(args.log_level)

    policy_list = (
        [
            policy.strip()
            for policy
            in args.policies.split(",")
            if policy.strip()
        ]
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
            poll_interval_sec=(
                args.poll_interval_ms
                / 1000.0
            ),
            rolling_window_min=(
                args.rolling_window_min
            ),
            actions_path=args.actions_path,
            applied_path=args.applied_path,
            state_input_path=args.state_input,
            integration_mode=(
                args.integration_mode
            ),
            shadow_actions_path=(
                args.shadow_actions_path
            ),
        )
        return

    event_source, action_sink = (
        create_file_adapters(
            events_path=args.input,
            actions_path=args.actions_path,
            actions_csv_path=(
                f"{args.out_dir}/actions.csv"
                if args.actions_path
                else None
            ),
        )
    )

    run_pipeline_with_adapters(
        event_source=event_source,
        action_sink=action_sink,
        out_dir=args.out_dir,
        policy_names=policy_list,
        config_dir=args.config_dir,
        horizon_days=args.horizon_days,
        integration_mode=(
            args.integration_mode
        ),
        shadow_actions_path=(
            args.shadow_actions_path
        ),
    )


if __name__ == "__main__":
    main()