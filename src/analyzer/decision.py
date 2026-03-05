"""Decision engine: map incidents to concrete actions (closed-loop controller).

The decision engine is purely policy-based: given an incident's threat_type,
severity, and affected component, it selects actions from a static mapping
(response playbook). This keeps the logic deterministic and auditable.

To port to production, replace this mapping with an external playbook store
or a SOAR API adapter.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.contracts.action import Action
from src.contracts.incident import Incident

log = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
#  Response playbook
# ═══════════════════════════════════════════════════════════════════════════

# threat_type -> list of action templates
# Each template is (action, target_component, params_factory)
# params_factory receives the incident and returns a dict.

_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

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
            "params": {"snapshot": "snapshot_init"},
        },
    ],
}


def decide(
    incidents: list[Incident],
    already_acted: set[str],
) -> list[Action]:
    """Produce actions for new incidents that haven't been acted upon.

    Args:
        incidents: Current active incidents.
        already_acted: Set of incident_ids already handled.

    Returns:
        List of new actions to emit.
    """
    actions: list[Action] = []
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for inc in incidents:
        if inc.incident_id in already_acted:
            continue

        templates = _PLAYBOOK.get(inc.threat_type, [])
        if not templates:
            log.debug("No playbook entry for threat_type=%s", inc.threat_type)
            continue

        for tmpl in templates:
            # Check minimum severity filter
            min_sev = tmpl.get("min_severity")
            if min_sev and _SEV_ORDER.get(inc.severity, 0) < _SEV_ORDER.get(min_sev, 0):
                continue

            params = dict(tmpl["params"])

            # Enrich params from incident context
            if tmpl["action"] == "block_actor":
                # Extract actor/ip from incident description
                actor, ip = _extract_actor_ip(inc)
                if actor:
                    params["actor"] = actor
                if ip:
                    params["ip"] = ip
                if not actor and not ip:
                    params["ip"] = "0.0.0.0"

            if tmpl["action"] == "backup_db":
                params["name"] = f"snap_{inc.incident_id}"

            actions.append(Action(
                ts_utc=now,
                action=tmpl["action"],
                target_component=tmpl["target_component"],
                target_id=_extract_target_id(inc, tmpl["target_component"]),
                params=params,
                reason=f"{inc.incident_id}: {inc.threat_type}/{inc.severity}",
                correlation_id=inc.incident_id,
                status="emitted",
            ))

        already_acted.add(inc.incident_id)
        log.info(
            "DECIDE: %s -> %d actions for %s/%s",
            inc.incident_id, len(templates), inc.threat_type, inc.severity,
        )

    return actions


def emit_actions(actions: list[Action], path: str) -> None:
    """Append actions to actions.jsonl (atomic append)."""
    if not actions:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as fh:
        for a in actions:
            fh.write(a.to_json() + "\n")
        fh.flush()
    log.info("Emitted %d actions -> %s", len(actions), path)


def write_actions_csv(actions: list[Action], path: str) -> None:
    """Write actions to a CSV file (atomic write for dashboard)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = [Action.csv_header()]
    for a in actions:
        lines.append(a.to_csv_row())
    content = "\n".join(lines) + "\n"

    fd, tmp = tempfile.mkstemp(
        dir=str(p.parent), prefix=f".{p.name}.", suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        import contextlib
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise

    log.info("Wrote actions CSV -> %s (%d rows)", path, len(actions))


# ── helpers ──────────────────────────────────────────────────────────────


def _extract_actor_ip(inc: Incident) -> tuple[str, str]:
    """Best-effort extraction of actor/ip from incident description."""
    desc = inc.description
    actor = ""
    ip = ""
    # Pattern: "from <ip>"
    if "from " in desc:
        parts = desc.split("from ")
        if len(parts) > 1:
            ip_candidate = parts[1].split()[0].strip(" ,;")
            if "." in ip_candidate:
                ip = ip_candidate
    # Pattern: "actor(s) on" or "for <actor>"
    if "by non-allowed" in desc:
        actor = "unknown"
    return actor, ip


def _extract_target_id(inc: Incident, target_component: str) -> str:
    """Extract a target device ID from the incident."""
    components = inc.component.split(";")
    for c in components:
        if c.strip() == target_component:
            return c.strip()
    return components[0].strip() if components else target_component
