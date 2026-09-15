"""Командний інтерфейс аналізатора SmartEnergy."""

from __future__ import annotations

import argparse
import os

from src.adapters.file_adapter import (
    FileActionFeedback,
    FileActionSink,
    FileEventSource,
)
from src.analyzer.pipeline import (
    run_pipeline_with_adapters,
    watch_pipeline_with_adapters,
)
from src.shared.logger import setup_logging


class _LiveFileEventSource(FileEventSource):
    """Файлове джерело з tail-семантикою для потокового режиму.

    На відміну від пакетного файлового адаптера, перше читання
    враховує поточний offset та збережений checkpoint. Завдяки
    цьому початкові події не обробляються двічі.
    """

    def read_batch(self, limit: int = 10000):
        """Читає початковий пакет із поточної checkpoint-позиції."""
        if self.path.suffix.lower() in {
            ".jsonl",
            ".ndjson",
        }:
            return self._read_new_lines()

        return super().read_batch(limit=limit)


def _optional_environment_path(name: str) -> str | None:
    """Повертає непорожній шлях зі змінної середовища."""
    value = os.getenv(name, "").strip()
    return value or None


def create_file_adapters(
    events_path: str,
    actions_path: str | None = None,
    actions_csv_path: str | None = None,
) -> tuple[FileEventSource, FileActionSink | None]:
    """Створює файлові адаптери для разового запуску аналізатора.

    Аргументи:
        events_path: Шлях до CSV або JSONL-файла подій.
        actions_path: Опційний шлях до JSONL-файла дій.
        actions_csv_path: Опційний шлях до CSV-зведення дій.

    Повертає:
        Джерело подій та опційний приймач дій.
    """
    event_source = FileEventSource(events_path)
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
    """Запускає потоковий аналіз із підтримкою checkpoint.

    Для основного потоку подій, потоку стану та ACK створюються
    окремі checkpoint-файли. Після перезапуску читання триває
    з останньої збереженої позиції.
    """
    event_source = _LiveFileEventSource(
        input_path,
        checkpoint_path=_optional_environment_path(
            "ANALYZER_EVENT_CHECKPOINT_PATH"
        ),
    )

    state_source = None

    if (
        state_input_path
        and state_input_path != input_path
    ):
        state_source = _LiveFileEventSource(
            state_input_path,
            checkpoint_path=_optional_environment_path(
                "ANALYZER_STATE_CHECKPOINT_PATH"
            ),
        )

    action_sink = None

    if actions_path:
        action_sink = FileActionSink(
            actions_path,
            csv_path=f"{out_dir}/actions.csv",
        )

    action_feedback = None

    if applied_path:
        action_feedback = FileActionFeedback(
            applied_path,
            checkpoint_path=_optional_environment_path(
                "ANALYZER_ACK_CHECKPOINT_PATH"
            ),
        )

    watch_pipeline_with_adapters(
        event_source=event_source,
        out_dir=out_dir,
        policy_names=policy_names,
        config_dir=config_dir,
        horizon_days=horizon_days,
        poll_interval_sec=poll_interval_sec,
        rolling_window_min=rolling_window_min,
        state_event_source=state_source,
        action_sink=action_sink,
        action_feedback=action_feedback,
        integration_mode=integration_mode,
        shadow_actions_path=shadow_actions_path,
    )


def build_parser() -> argparse.ArgumentParser:
    """Створює та налаштовує CLI-парсер аналізатора."""
    parser = argparse.ArgumentParser(
        prog="analyzer",
        description=(
            "Аналізатор SmartEnergy — легка SIEM: "
            "детекція, кореляція та формування звітів"
        ),
    )

    parser.add_argument(
        "--input",
        default="data/events.csv",
        help=(
            "Вхідний CSV або JSONL-файл. Формат визначається "
            "за розширенням. За замовчуванням: data/events.csv"
        ),
    )
    parser.add_argument(
        "--out-dir",
        default="out",
        help="Директорія результатів. За замовчуванням: out/",
    )
    parser.add_argument(
        "--policies",
        default="all",
        help=(
            "Назви політик через кому. Значення all запускає "
            "всі доступні політики."
        ),
    )
    parser.add_argument(
        "--config-dir",
        default="config",
        help=(
            "Директорія з rules.yaml і policies.yaml. "
            "За замовчуванням: config/"
        ),
    )
    parser.add_argument(
        "--horizon-days",
        type=float,
        default=None,
        help=(
            "Горизонт аналізу в днях. Якщо значення не задане, "
            "використовується часовий діапазон вхідних даних."
        ),
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help=(
            "Seed генератора випадковості для відтворюваності "
            "симуляції реагування."
        ),
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        default=False,
        help=(
            "Увімкнути потоковий режим читання нових подій "
            "із JSONL-файла."
        ),
    )
    parser.add_argument(
        "--poll-interval-ms",
        type=int,
        default=1000,
        help=(
            "Інтервал опитування у потоковому режимі, "
            "у мілісекундах. За замовчуванням: 1000."
        ),
    )
    parser.add_argument(
        "--rolling-window-min",
        type=float,
        default=5.0,
        help=(
            "Розмір рухомого вікна аналізу у хвилинах. "
            "За замовчуванням: 5."
        ),
    )
    parser.add_argument(
        "--actions-path",
        type=str,
        default=None,
        help=(
            "Шлях до actions.jsonl для передавання дій "
            "підсистемі Control."
        ),
    )
    parser.add_argument(
        "--applied-path",
        type=str,
        default=None,
        help=(
            "Шлях до actions_applied.jsonl із підтвердженнями "
            "виконаних дій."
        ),
    )
    parser.add_argument(
        "--state-input",
        type=str,
        default=None,
        help=(
            "Опційний JSONL-файл із подіями зміни стану "
            "компонентів SmartEnergy."
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
            "Режим інтеграції: dry-run, shadow або active. "
            "За замовчуванням: active."
        ),
    )
    parser.add_argument(
        "--shadow-actions-path",
        type=str,
        default=None,
        help=(
            "Опційний шлях до CSV-файла запланованих дій "
            "у режимі dry-run або shadow."
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
        help="Рівень журналювання. За замовчуванням: INFO.",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    """Запускає аналізатор у разовому або потоковому режимі."""
    args = build_parser().parse_args(argv)
    setup_logging(args.log_level)

    policy_list = (
        [
            policy.strip()
            for policy in args.policies.split(",")
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
                args.poll_interval_ms / 1000.0
            ),
            rolling_window_min=args.rolling_window_min,
            actions_path=args.actions_path,
            applied_path=args.applied_path,
            state_input_path=args.state_input,
            integration_mode=args.integration_mode,
            shadow_actions_path=args.shadow_actions_path,
        )
        return

    event_source, action_sink = create_file_adapters(
        events_path=args.input,
        actions_path=args.actions_path,
        actions_csv_path=(
            f"{args.out_dir}/actions.csv"
            if args.actions_path
            else None
        ),
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