"""Командний інтерфейс емулятора SmartEnergy.

Використовує EventSink інтерфейс для plug-and-play виводу подій.
За замовчуванням використовується FileEventSink, але можна замінити
на KafkaEventSink, MqttEventSink тощо.
"""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from src.adapters import FileEventSink
from src.contracts.interfaces import EventSink
from src.emulator.engine import (
    EmulatorEngine,
    stream_demo_highrate,
    stream_jsonl,
    stream_jsonl_infinite,
    stream_to_sink,
)
from src.shared.config_loader import load_yaml
from src.shared.logger import setup_logging


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="smartenergy-emulator",
        description="Генерує синтетичні події SmartEnergy у batch або live режимі.",
    )
    p.add_argument(
        "--days",
        type=int,
        default=None,
        help="Тривалість симуляції у днях. Перевизначає scenarios.yaml duration_sec. "
        "Якщо не задано, використовується YAML-значення (типово 3600 с = 1 год).",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Seed генератора випадковості для детермінованого виходу (за замовчуванням: 42).",
    )
    p.add_argument(
        "--out",
        type=str,
        default="data/events.csv",
        help="Шлях вихідного файла (за замовчуванням: data/events.csv).",
    )
    p.add_argument(
        "--format",
        type=str,
        choices=["csv", "jsonl"],
        default="csv",
        help="Формат виходу: csv (за замовчуванням) або jsonl.",
    )
    p.add_argument(
        "--scenario_set",
        type=str,
        default="all",
        help="Назви сценаріїв через кому або 'all' для всіх сценаріїв.",
    )
    p.add_argument(
        "--start_time",
        type=str,
        default=None,
        help="Час старту симуляції в ISO-8601, наприклад 2026-02-26T10:00:00Z. "
        "За замовчуванням береться зі scenarios.yaml.",
    )
    p.add_argument(
        "--components",
        type=str,
        default="config/components.yaml",
        help="Шлях до components.yaml (за замовчуванням: config/components.yaml).",
    )
    p.add_argument(
        "--scenarios",
        type=str,
        default="config/scenarios.yaml",
        help="Шлях до scenarios.yaml (за замовчуванням: config/scenarios.yaml).",
    )
    p.add_argument(
        "--live",
        action="store_true",
        default=False,
        help="Увімкнути live-режим із потоковим записом подій у JSONL із затримками.",
    )
    p.add_argument(
        "--live-interval-ms",
        type=int,
        default=1000,
        help="Інтервал між записами подій у live-режимі, мс (за замовчуванням: 1000).",
    )
    p.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="Максимальна кількість подій для генерації (опційний ліміт).",
    )
    p.add_argument(
        "--raw-log-dir",
        type=str,
        default=None,
        help="Директорія для сирих логів у syslog-стилі (api.log, auth.log, system.log). "
        "Використовується лише з --live.",
    )
    p.add_argument(
        "--csv-out",
        type=str,
        default=None,
        help="Додатково писати CSV у live-режимі пакетами. Приклад: data/live/events.csv",
    )
    p.add_argument(
        "--profile",
        type=str,
        default="default",
        choices=["default", "demo_high_rate"],
        help="Профіль емуляції. demo_high_rate: короткі цикли та часті атаки.",
    )
    p.add_argument(
        "--attack-rate",
        type=float,
        default=1.0,
        help="Множник інтенсивності атак: >1 збільшує кількість і частоту, <1 зменшує.",
    )
    p.add_argument(
        "--attack-every-sec",
        type=float,
        default=10.0,
        help="Секунди між burst-атаками у demo_high_rate профілі. Сценарії йдуть по колу.",
    )
    p.add_argument(
        "--background-events-per-tick",
        type=int,
        default=20,
        help="Кількість безпечних фонових подій на такт у demo_high_rate профілі.",
    )
    p.add_argument(
        "--max-file-mb",
        type=float,
        default=50.0,
        help="Максимальний розмір вихідного файла в MB перед ротацією. Діє для JSONL і CSV.",
    )
    p.add_argument(
        "--actions-path",
        type=str,
        default=None,
        help="Шлях до actions.jsonl для closed-loop зворотного зв'язку від аналізатора. "
        "Використовується з --live --profile demo_high_rate.",
    )
    p.add_argument(
        "--applied-path",
        type=str,
        default=None,
        help="Шлях до actions_applied.jsonl для ACK-виходу. "
        "Емулятор записує підтвердження після застосування дій.",
    )
    p.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Рівень логування (за замовчуванням: INFO).",
    )
    return p.parse_args(argv)


def _stream_to_sink_infinite(
    engine: EmulatorEngine,
    event_sink: EventSink,
    interval_sec: float,
) -> None:
    """Запускає безкінечний live-потік через EventSink циклами симуляції."""
    total = 0
    while True:
        count = stream_to_sink(
            engine=engine,
            event_sink=event_sink,
            interval_sec=interval_sec,
            max_events=None,
        )
        total += count
        print(f"  цикл завершено: +{count} подій (усього={total})")


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
        if out_path.suffix not in (".jsonl", ".ndjson"):
            out_path = out_path.with_suffix(".jsonl")
        interval_sec = args.live_interval_ms / 1000.0
        raw_log_dir = Path(args.raw_log_dir) if args.raw_log_dir else None
        csv_out = Path(args.csv_out) if args.csv_out else None
        actions_path = Path(args.actions_path) if args.actions_path else None
        applied_path = Path(args.applied_path) if args.applied_path else None
        print(f"Live-режим емулятора -> {out_path}")
        print(
            f"  інтервал: {args.live_interval_ms} мс, "
            f"max_events: {args.max_events or 'без обмеження'}"
        )
        print(f"  профіль: {args.profile}, attack_rate: {args.attack_rate}")
        if args.profile == "demo_high_rate":
            print(
                f"  атака кожні: {args.attack_every_sec}s, "
                f"фон/тик: {args.background_events_per_tick}, "
                f"макс. файл: {args.max_file_mb} MB"
            )
        if raw_log_dir:
            print(f"  сирі логи -> {raw_log_dir}/")
        if csv_out:
            print(f"  CSV      -> {csv_out}")
        if actions_path:
            print(f"  дії      <- {actions_path} (closed-loop)")
        if applied_path:
            print(f"  ACK      -> {applied_path}")
        print("  Натисніть Ctrl+C для зупинки.")
        try:
            sink_mode = args.profile != "demo_high_rate" and raw_log_dir is None and csv_out is None

            if sink_mode:
                print("  режим: EventSink")
                event_sink: EventSink = FileEventSink(str(out_path))
                try:
                    if args.max_events is not None:
                        count = stream_to_sink(
                            engine=engine,
                            event_sink=event_sink,
                            interval_sec=interval_sec,
                            max_events=args.max_events,
                        )
                        print(f"Live-режим емулятора завершено: {count} подій -> {out_path}")
                    else:
                        _stream_to_sink_infinite(
                            engine=engine,
                            event_sink=event_sink,
                            interval_sec=interval_sec,
                        )
                finally:
                    event_sink.close()
            elif args.profile == "demo_high_rate":
                stream_demo_highrate(
                    engine=engine,
                    path=out_path,
                    interval_sec=interval_sec,
                    attack_every_sec=args.attack_every_sec,
                    bg_per_tick=args.background_events_per_tick,
                    max_file_mb=args.max_file_mb,
                    raw_log_dir=raw_log_dir,
                    csv_out=csv_out,
                    actions_path=actions_path,
                    applied_path=applied_path,
                )
            elif args.max_events is not None:
                count = stream_jsonl(
                    engine=engine,
                    path=out_path,
                    interval_sec=interval_sec,
                    max_events=args.max_events,
                )
                print(f"Live-режим емулятора завершено: {count} подій -> {out_path}")
            else:
                stream_jsonl_infinite(
                    engine=engine,
                    path=out_path,
                    interval_sec=interval_sec,
                    raw_log_dir=raw_log_dir,
                    csv_out=csv_out,
                )
        except KeyboardInterrupt:
            print("\nЕмулятор зупинено користувачем.")
    else:
        events = engine.run()
        if args.max_events and len(events) > args.max_events:
            events = events[: args.max_events]

        if args.format == "jsonl":
            if out_path.suffix not in (".jsonl", ".ndjson", ".json"):
                out_path = out_path.with_suffix(".jsonl")
        else:
            if out_path.suffix != ".csv":
                out_path = out_path.with_suffix(".csv")

        event_sink: EventSink = FileEventSink(str(out_path))
        event_sink.emit_batch(events)
        event_sink.close()

        print(f"Batch-режим емулятора завершено: {len(events)} подій -> {out_path} (через EventSink)")


if __name__ == "__main__":
    main()
