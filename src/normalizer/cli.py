"""Командний інтерфейс нормалізатора SmartEnergy."""

from __future__ import annotations

import argparse

from src.adapters import FileEventSink
from src.contracts.interfaces import EventSink
from src.normalizer.pipeline import NormalizerPipeline
from src.shared.logger import setup_logging


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="normalizer",
        description="Нормалізатор SmartEnergy: сирі логи -> Event Contract CSV/JSONL",
    )
    p.add_argument(
        "--inputs",
        default="logs/*.log",
        help="Glob-шаблон для вхідних сирих логів (за замовчуванням: logs/*.log)",
    )
    p.add_argument(
        "--mapping",
        default="config/mapping.yaml",
        help="Шлях до mapping-конфігу (за замовчуванням: config/mapping.yaml)",
    )
    p.add_argument(
        "--out",
        default="data/events.csv",
        help="Шлях виходу у форматі Event Contract (за замовчуванням: data/events.csv). "
        "У follow-режимі з розширенням .jsonl додає JSONL.",
    )
    p.add_argument(
        "--quarantine",
        default="out/quarantine.csv",
        help="CSV-карантин для відхилених рядків (за замовчуванням: out/quarantine.csv)",
    )
    p.add_argument(
        "--stats",
        default="out/normalize_stats.json",
        help="Шлях до JSON-статистики (за замовчуванням: out/normalize_stats.json)",
    )
    p.add_argument(
        "--timezone",
        default="UTC",
        help=(
            "Часовий пояс вихідних логів. Timestamp вважаються такими, що "
            "належать цьому часовому поясу, і конвертуються в UTC. "
            "За замовчуванням: UTC. Приклади: Europe/Kyiv, US/Eastern"
        ),
    )
    p.add_argument(
        "--follow",
        action="store_true",
        default=False,
        help="Увімкнути follow-режим: постійно читати input-логи tail-режимом "
        "і додавати нормалізовані події в --out (рекомендовано JSONL).",
    )
    p.add_argument(
        "--poll-interval-ms",
        type=int,
        default=1000,
        help="Інтервал опитування у follow-режимі, мс (за замовчуванням: 1000).",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Рівень логування (за замовчуванням: INFO)",
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
        event_sink: EventSink = FileEventSink(args.out)
        try:
            pipeline.run_with_sink(
                input_glob=args.inputs,
                event_sink=event_sink,
                quarantine_path=args.quarantine,
                stats_path=args.stats,
            )
        finally:
            event_sink.close()


if __name__ == "__main__":
    main()
