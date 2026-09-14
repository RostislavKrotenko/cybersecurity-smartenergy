"""Двигун рішень: перетворення інцидентів на конкретні дії реагування.

Модуль працює за політиками: на основі threat_type, severity і ураженого
компонента він вибирає дії зі статичного playbook. Так логіка залишається
детермінованою й придатною для аудиту.

Для production-режиму цей mapping можна замінити зовнішнім playbook-сховищем
або SOAR API адаптером. ActionSink дозволяє підміняти backend виконання дій.
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

# threat_type -> список шаблонів дій реагування.

_PLAYBOOK: dict[str, list[dict[str, Any]]] = {
    "credential_attack": [
        {
            "action": "block_actor",
            "target_component": "auth",
            "params": {"duration_sec": 600},
        },
    ],
    "availability_attack": [
        {
            "action": "enable_rate_limit",
            "target_component": "gateway",
            "params": {"rps": 50, "burst": 100, "duration_sec": 300},
        },
        {
            "action": "isolate_component",
            "target_component": "api",
            "params": {"duration_sec": 60},
            "min_severity": "critical",
        },
    ],
    "integrity_attack": [
        {
            "action": "isolate_component",
            "target_component": "collector",
            "params": {"duration_sec": 120},
        },
    ],
    "outage": [
        {
            "action": "backup_db",
            "target_component": "db",
            "params": {},
        },
        {
            "action": "restore_db",
            "target_component": "db",
            "params": {"snapshot": "latest"},
        },
    ],
    "network_degraded": [
        {
            "action": "reset_network",
            "target_component": "network",
            "params": {},
        },
    ],
    "network_failure": [
        {
            "action": "degrade_network",
            "target_component": "network",
            "params": {
                "latency_ms": 280,
                "drop_rate": 0.25,
                "ttl_sec": 180,
            },
        },
    ],
}


def decide(
    incidents: list[Incident],
    already_acted: set[str],
) -> list[Action]:
    """Формує дії для нових інцидентів, які ще не були оброблені."""
    actions: list[Action] = []
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for inc in incidents:
        if inc.incident_id in already_acted:
            continue

        templates = _PLAYBOOK.get(inc.threat_type, [])
        if not templates:
            log.debug("Немає playbook-запису для threat_type=%s", inc.threat_type)
            continue

        for tmpl in templates:
            min_sev = tmpl.get("min_severity")
            if min_sev and _SEV_ORDER.get(inc.severity, 0) < _SEV_ORDER.get(min_sev, 0):
                continue

            params = dict(tmpl["params"])

            if tmpl["action"] == "block_actor":
                actor, ip = _extract_actor_ip(inc)
                if actor:
                    params["actor"] = actor
                if ip:
                    params["ip"] = ip
                if not actor and not ip:
                    params["ip"] = "0.0.0.0"

            if tmpl["action"] == "backup_db":
                params["name"] = f"snap_{inc.incident_id}"

            actions.append(
                Action(
                    ts_utc=now,
                    action=tmpl["action"],
                    target_component=tmpl["target_component"],
                    target_id=_extract_target_id(inc, tmpl["target_component"]),
                    params=params,
                    reason=f"{inc.incident_id}: {inc.threat_type}/{inc.severity}",
                    correlation_id=inc.incident_id,
                    status="emitted",
                )
            )

        already_acted.add(inc.incident_id)
        log.info(
            "DECIDE: %s -> %d actions for %s/%s",
            inc.incident_id,
            len(templates),
            inc.threat_type,
            inc.severity,
        )

    return actions


def emit_actions(actions: list[Action], path: str) -> None:
    """Дописує дії в actions.jsonl."""
    if not actions:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as fh:
        for a in actions:
            fh.write(a.to_json() + "\n")
        fh.flush()
    log.info("Емітовано %d дій -> %s", len(actions), path)


def write_actions_csv(actions: list[Action], path: str) -> None:
    """Записує дії в CSV файл для dashboard."""
    lines = [Action.csv_header()]
    for a in actions:
        lines.append(a.to_csv_row())
    atomic_write(path, "\n".join(lines) + "\n")
    log.info("Записано CSV дій -> %s (%d рядків)", path, len(actions))


def _extract_actor_ip(inc: Incident) -> tuple[str, str]:
    """Best-effort витяг actor/IP з опису інциденту."""
    desc = inc.description
    actor = ""
    ip = ""

    if "from " in desc:
        parts = desc.split("from ")
        if len(parts) > 1:
            ip_candidate = parts[1].split()[0].strip(" ,;")
            if "." in ip_candidate:
                ip = ip_candidate
    if " з " in desc:
        parts = desc.split(" з ")
        if len(parts) > 1:
            ip_candidate = parts[1].split()[0].strip(" ,;")
            if "." in ip_candidate:
                ip = ip_candidate
    if "by non-allowed" in desc or "неавторизованих" in desc:
        actor = "unknown"
    return actor, ip


def _extract_target_id(inc: Incident, target_component: str) -> str:
    """Витягує ідентифікатор цільового пристрою з інциденту."""
    components = inc.component.split(";")
    for c in components:
        if c.strip() == target_component:
            return c.strip()
    return components[0].strip() if components else target_component


def emit_actions_to_sink(
    actions: list[Action],
    action_sink: ActionSink,
) -> list[str]:
    """Емітить дії через ActionSink adapter."""
    if not actions:
        return []

    tracking_ids = action_sink.emit_batch(actions)
    log.info("Емітовано %d дій через ActionSink", len(actions))
    return tracking_ids


def decide_and_emit(
    incidents: list[Incident],
    already_acted: set[str],
    action_sink: ActionSink,
) -> list[Action]:
    """Формує дії за інцидентами та емітить їх через sink."""
    actions = decide(incidents, already_acted)
    if actions:
        emit_actions_to_sink(actions, action_sink)
    return actions
