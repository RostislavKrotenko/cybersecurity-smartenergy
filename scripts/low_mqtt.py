#!/usr/bin/env python3
"""Демонструє нормальний струм, його падіння та відновлення через MQTT.

Скрипт публікує тільки у локальний сервіс ``mosquitto`` з поточного
Docker Compose. Він не змінює конфігурацію broker та не блокує видавців.
SECMS має пропустити штатні пакети, ізолювати серію пакетів із пониженим
струмом під нормальною напругою та показати MQTT-інцидент у React UI.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True, slots=True)
class Phase:
    """Опис однієї фази MQTT-демонстрації."""

    title: str
    current_a: float
    messages: int


def _run(arguments: Sequence[str], *, capture_output: bool = False) -> str:
    """Виконує команду без shell і повертає стандартний вивід."""

    result = subprocess.run(
        list(arguments),
        check=True,
        text=True,
        capture_output=capture_output,
    )
    return result.stdout.strip() if capture_output else ""


def _compose_command(compose_file: Path, *arguments: str) -> tuple[str, ...]:
    """Формує команду Docker Compose для вибраного файла."""

    return (
        "docker",
        "compose",
        "-f",
        str(compose_file),
        *arguments,
    )


def _publish(
    *,
    compose_file: Path,
    topic: str,
    username: str,
    password: str,
    payload: dict[str, object],
) -> None:
    """Публікує один Smart Energy payload через локальний broker."""

    _run(
        _compose_command(
            compose_file,
            "exec",
            "-T",
            "mosquitto",
            "mosquitto_pub",
            "-h",
            "127.0.0.1",
            "-p",
            "1883",
            "-u",
            username,
            "-P",
            password,
            "-t",
            topic,
            "-m",
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        )
    )


def _run_phase(
    *,
    compose_file: Path,
    phase: Phase,
    topic: str,
    username: str,
    password: str,
    interval_seconds: float,
    run_id: str,
) -> None:
    """Послідовно надсилає повідомлення однієї фази."""

    print(
        f"\n{phase.title}: {phase.current_a:g} A, "
        f"повідомлень: {phase.messages}",
        flush=True,
    )

    for index in range(phase.messages):
        correlation_id = f"mqtt-low-current-{run_id}-{index}"
        payload: dict[str, object] = {
            "source": "secms-demo",
            "status": "online",
            "correlation_id": correlation_id,
            "devices": {
                "controlled-load": {
                    "v": 230.0,
                    "i": phase.current_a,
                }
            },
        }
        _publish(
            compose_file=compose_file,
            topic=topic,
            username=username,
            password=password,
            payload=payload,
        )
        print(f"  {index + 1}/{phase.messages}: {phase.current_a:g} A", flush=True)
        if index + 1 < phase.messages:
            time.sleep(interval_seconds)


def _parse_arguments() -> argparse.Namespace:
    """Читає та перевіряє параметри локального сценарію."""

    parser = argparse.ArgumentParser(
        description=(
            "MQTT-демонстрація: нормальний струм → понижений струм → "
            "відновлення"
        )
    )
    parser.add_argument("--compose-file", default="docker-compose.yaml")
    parser.add_argument("--topic", default="sensor/data")
    parser.add_argument("--username", default="simulator")
    parser.add_argument("--password", default="simulator_pass")
    parser.add_argument("--normal-current", type=float, default=2.0)
    parser.add_argument("--low-current", type=float, default=0.1)
    parser.add_argument("--normal-messages", type=int, default=3)
    parser.add_argument("--anomaly-messages", type=int, default=6)
    parser.add_argument("--recovery-messages", type=int, default=3)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument(
        "--ui-url",
        default="http://127.0.0.1:5173/cybersecurity",
    )
    args = parser.parse_args()

    if not 0 <= args.low_current < args.normal_current:
        parser.error("Понижений струм має бути невід'ємним і меншим за штатний")
    if not 0.1 <= args.interval <= 30:
        parser.error("Інтервал має бути в діапазоні 0.1–30 секунд")
    for name in ("normal_messages", "anomaly_messages", "recovery_messages"):
        if not 1 <= getattr(args, name) <= 100:
            parser.error(f"{name} має бути в діапазоні 1–100")

    return args


def main() -> int:
    """Перевіряє стенд і запускає три безпечні MQTT-фази."""

    args = _parse_arguments()
    compose_file = Path(args.compose_file).resolve()
    if not compose_file.is_file():
        print(f"ПОМИЛКА: не знайдено {compose_file}", file=sys.stderr)
        return 2

    try:
        broker_id = _run(
            _compose_command(compose_file, "ps", "-q", "mosquitto"),
            capture_output=True,
        )
        collector_id = _run(
            _compose_command(compose_file, "ps", "-q", "cybersecurity-collector"),
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"ПОМИЛКА Docker Compose: {error}", file=sys.stderr)
        return 2

    if not broker_id or not collector_id:
        print(
            "ПОМИЛКА: спочатку запустіть mosquitto та cybersecurity-collector",
            file=sys.stderr,
        )
        return 2

    run_id = uuid.uuid4().hex[:8]
    phases = (
        Phase("Штатний режим", args.normal_current, args.normal_messages),
        Phase("Понижений струм", args.low_current, args.anomaly_messages),
        Phase("Відновлення", args.normal_current, args.recovery_messages),
    )

    try:
        for phase in phases:
            _run_phase(
                compose_file=compose_file,
                phase=phase,
                topic=args.topic,
                username=args.username,
                password=args.password,
                interval_seconds=args.interval,
                run_id=f"{run_id}-{phase.title}",
            )
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"ПОМИЛКА публікації MQTT: {error}", file=sys.stderr)
        return 1

    print("\nСценарій завершено.")
    print(f"Відкрийте або оновіть UI: {args.ui_url}")
    print(
        "Очікувано: записи з пониженим струмом у карантині та "
        "інцидент аномалії MQTT. Штатні пакети залишаються в телеметрії."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
