"""Двигун рішень для перетворення інцидентів на дії реагування.

Модуль використовує детермінований playbook: на основі типу загрози,
критичності й ураженого компонента вибираються дозволені захисні дії.
Такий підхід полегшує аудит, тестування та пояснення роботи системи.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.contracts.action import Action
from src.contracts.incident import Incident
from src.contracts.interfaces import ActionSink
from src.shared.file_utils import atomic_write
from src.shared.severity import SEV_ORDER as _SEV_ORDER

log = logging.getLogger(__name__)

_DDOS_RATE_PER_SECOND = 10
_DDOS_BURST_CAPACITY = 20
_DDOS_RATE_LIMIT_DURATION_SEC = 300
_DDOS_ISOLATION_DURATION_SEC = 60


_PLAYBOOK: dict[str, list[dict[str, Any]]] = {
    "availability_attack": [
        {
            "action": "enable_rate_limit",
            "target_component": "gateway",
            "params": {
                "rps": _DDOS_RATE_PER_SECOND,
                "burst": _DDOS_BURST_CAPACITY,
                "duration_sec": _DDOS_RATE_LIMIT_DURATION_SEC,
            },
        },
        {
            "action": "isolate_component",
            "target_component": "api",
            "params": {
                "duration_sec": _DDOS_ISOLATION_DURATION_SEC,
            },
            "min_severity": "critical",
        },
    ],
}


def decide(
    incidents: list[Incident],
    already_acted: set[str],
) -> list[Action]:
    """Формує дії для нових інцидентів.

    Аргументи:
        incidents: Нові інциденти, для яких необхідно визначити реакцію.
        already_acted: Ідентифікатори інцидентів, які вже були оброблені.

    Повертає:
        Список сформованих захисних дій.
    """
    actions: list[Action] = []
    timestamp = datetime.now(
        tz=timezone.utc,
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    for incident in incidents:
        if incident.incident_id in already_acted:
            continue

        templates = _PLAYBOOK.get(
            incident.threat_type,
            [],
        )

        if not templates:
            log.debug(
                "Немає playbook для threat_type=%s",
                incident.threat_type,
            )
            already_acted.add(incident.incident_id)
            continue

        created_count = 0

        for template in templates:
            minimum_severity = template.get(
                "min_severity"
            )

            if (
                minimum_severity
                and _SEV_ORDER.get(
                    incident.severity,
                    0,
                )
                < _SEV_ORDER.get(
                    minimum_severity,
                    0,
                )
            ):
                continue

            params = dict(
                template.get(
                    "params",
                    {},
                )
            )
            action_name = str(template["action"])
            target_component = str(
                template["target_component"]
            )

            actions.append(
                Action(
                    ts_utc=timestamp,
                    action=action_name,
                    target_component=target_component,
                    target_id=_extract_target_id(
                        incident,
                        target_component,
                    ),
                    params=params,
                    reason=(
                        f"{incident.incident_id}: "
                        f"{incident.threat_type}/"
                        f"{incident.severity}"
                    ),
                    correlation_id=incident.incident_id,
                    status="emitted",
                )
            )
            created_count += 1

        already_acted.add(incident.incident_id)

        log.info(
            "DECIDE: %s -> %d дій для %s/%s",
            incident.incident_id,
            created_count,
            incident.threat_type,
            incident.severity,
        )

    return actions


def emit_actions(
    actions: list[Action],
    path: str,
) -> None:
    """Дописує сформовані дії до JSONL-файла.

    Аргументи:
        actions: Дії, які необхідно зберегти.
        path: Шлях до вихідного JSONL-файла.
    """
    if not actions:
        return

    output_path = Path(path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "a",
        encoding="utf-8",
    ) as stream:
        for action in actions:
            stream.write(action.to_json())
            stream.write("\n")

        stream.flush()

    log.info(
        "Емітовано %d дій -> %s",
        len(actions),
        output_path,
    )


def write_actions_csv(
    actions: list[Action],
    path: str,
) -> None:
    """Атомарно записує CSV-зведення дій.

    Аргументи:
        actions: Дії, які необхідно додати до зведення.
        path: Шлях до вихідного CSV-файла.
    """
    lines = [Action.csv_header()]

    for action in actions:
        lines.append(action.to_csv_row())

    atomic_write(
        path,
        "\n".join(lines) + "\n",
    )

    log.info(
        "Записано CSV дій -> %s (%d рядків)",
        path,
        len(actions),
    )


def _extract_target_id(
    incident: Incident,
    target_component: str,
) -> str:
    """Визначає коректний ідентифікатор цільового компонента.

    Якщо уражений компонент інциденту збігається з цільовим
    компонентом playbook, використовується його ідентифікатор.
    Інакше повертається цільовий компонент playbook. Завдяки
    цьому DDoS-інцидент Gateway може коректно ізолювати API,
    а не помилково вказувати Gateway як ціль ізоляції.
    """
    components = [
        component.strip()
        for component in incident.component.split(";")
        if component.strip()
    ]

    for component in components:
        if component == target_component:
            return component

    return target_component


def emit_actions_to_sink(
    actions: list[Action],
    action_sink: ActionSink,
) -> list[str]:
    """Передає сформовані дії через адаптер ActionSink.

    Аргументи:
        actions: Дії, які необхідно передати.
        action_sink: Адаптер зовнішнього виконавця дій.

    Повертає:
        Ідентифікатори переданих дій.
    """
    if not actions:
        return []

    tracking_ids = action_sink.emit_batch(actions)

    log.info(
        "Емітовано %d дій через ActionSink",
        len(actions),
    )

    return tracking_ids


def decide_and_emit(
    incidents: list[Incident],
    already_acted: set[str],
    action_sink: ActionSink,
) -> list[Action]:
    """Формує дії за інцидентами та передає їх у ActionSink.

    Аргументи:
        incidents: Нові інциденти безпеки.
        already_acted: Ідентифікатори вже оброблених інцидентів.
        action_sink: Адаптер зовнішнього виконавця.

    Повертає:
        Список сформованих і переданих дій.
    """
    actions = decide(
        incidents,
        already_acted,
    )

    if actions:
        emit_actions_to_sink(
            actions,
            action_sink,
        )

    return actions
