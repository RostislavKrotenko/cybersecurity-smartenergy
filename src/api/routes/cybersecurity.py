"""Агрегований API для інтегрованого UI кіберзахисту."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Query

from src.api.cybersecurity_adapters import external_reads_enabled, read_external_adapter_states
from src.api.data_provider import get_provider
from src.api.models import CybersecuritySnapshotResponse
from src.contracts.interfaces import ComponentState

router = APIRouter(prefix="/cybersecurity", tags=["cybersecurity"])

CANONICAL_COMPONENTS = ("gateway", "api", "auth", "db", "network")
INTEGRATION_MODES = {"dry-run", "shadow", "active"}

COMPONENT_NAMES = {
    "gateway": "Gateway",
    "api": "API",
    "auth": "Auth",
    "db": "Database",
    "network": "Network",
}

COMPONENT_DESCRIPTIONS = {
    "gateway": "Стан gateway-шару та обмежень трафіку.",
    "api": "Стан API-компонента й ізоляції сервісів.",
    "auth": "Стан автентифікації та блокування акторів.",
    "db": "Стан бази даних і backup-дій.",
    "network": "Стан мережевої деградації та відновлення.",
}


def _utc_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _backend_public_port() -> int:
    try:
        return int(os.getenv("CYBERSECURITY_PUBLIC_PORT", "6049"))
    except ValueError:
        return 6049


def _integration_mode() -> str:
    mode = os.getenv("CYBERSECURITY_INTEGRATION_MODE", "shadow").strip().lower()
    if mode in INTEGRATION_MODES:
        return mode
    return "shadow"


def _build_backend_info(
    generated_at: str,
    api_snapshot: dict[str, Any],
    external_adapters: list[dict[str, Any]],
) -> dict[str, Any]:
    """Описує доступність API та окремо стан його інтеграцій."""
    component_status = str(api_snapshot.get("component", {}).get("status", "disconnected"))

    return {
        "status": "available",
        "integrationHealth": component_status,
        "integrationMode": _integration_mode(),
        "publicPort": _backend_public_port(),
        "apiBasePath": "/api",
        "snapshotEndpoint": "/api/cybersecurity/snapshot",
        "source": os.getenv("CYBERSECURITY_SNAPSHOT_SOURCE", "file-adapters"),
        "externalReadsEnabled": external_reads_enabled(),
        "externalSources": len(external_adapters),
        "generatedAt": generated_at,
    }


def _state_index(states: list[ComponentState]) -> dict[str, ComponentState]:
    return {str(state.component_id): state for state in states}


def _state_status(state: ComponentState | None) -> str:
    """Повертає підтверджений стан, не маскуючи відсутність даних як healthy."""
    if state is None:
        return "unknown"

    status = str(state.status or "unknown").strip().lower()
    details = state.details if isinstance(state.details, dict) else {}

    if status == "healthy" and not details:
        return "unknown"

    return status


def _external_component_status(
    component_id: str,
    external_adapters: list[dict[str, Any]],
) -> str | None:
    """Агрегує фактичні HTTP/TCP перевірки для одного компонента."""
    statuses = [
        str(adapter.get("status", "unavailable")).lower()
        for adapter in external_adapters
        if str(adapter.get("source", {}).get("component", "")) == component_id
    ]

    if not statuses:
        return None
    if all(status == "ready" for status in statuses):
        return "healthy"
    if all(status == "unavailable" for status in statuses):
        return "down"
    return "degraded"


def _effective_component_status(
    component_id: str,
    state: ComponentState | None,
    external_adapters: list[dict[str, Any]],
) -> str:
    """Поєднує активний стан захисту з актуальними read-only probes."""
    state_status = _state_status(state)

    if state_status not in {"healthy", "unknown"}:
        return state_status

    external_status = _external_component_status(
        component_id,
        external_adapters,
    )
    if external_status is not None:
        return external_status

    return state_status


def _health_status(status: str) -> str:
    normalized = status.lower()
    if normalized == "healthy":
        return "online"
    if normalized in {"down", "disconnected", "unavailable", "failed"}:
        return "offline"
    if normalized == "unknown":
        return "unchecked"
    return "degraded"


def _adapter_status(status: str) -> str:
    normalized = status.lower()
    if normalized == "healthy":
        return "ready"
    if normalized in {"down", "disconnected", "unavailable", "failed"}:
        return "unavailable"
    if normalized == "unknown":
        return "stale"
    return "partial"


def _network_status(status: str) -> str:
    normalized = status.lower()
    if normalized == "healthy":
        return "connected"
    if normalized in {"down", "disconnected", "unavailable", "failed"}:
        return "unavailable"
    if normalized == "unknown":
        return "silent"
    return "partial"


def _signal_level(status: str) -> str:
    normalized = status.lower()
    if normalized in {"isolated", "down", "disconnected", "failed", "unavailable"}:
        return "critical"
    if normalized in {"degraded", "blocking", "rate_limited", "partial"}:
        return "warning"
    return "normal"


def _status_label(status: str) -> str:
    labels = {
        "healthy": "компонент працює штатно",
        "degraded": "компонент працює з деградацією",
        "isolated": "компонент ізольовано",
        "blocking": "активне блокування акторів",
        "rate_limited": "активне обмеження трафіку",
        "disconnected": "компонент відключено",
        "down": "компонент не працює",
        "unknown": "стан компонента невідомий",
    }
    return labels.get(status.lower(), f"стан компонента: {status}")


def _details_text(details: dict[str, Any]) -> str:
    if not details:
        return "Деталі відсутні"
    return ", ".join(f"{key}: {value}" for key, value in details.items())


def _service_result(
    component_id: str,
    state: ComponentState | None,
    generated_at: str,
    external_adapters: list[dict[str, Any]],
) -> dict[str, Any]:
    """Формує результат компонента з урахуванням реальних probes."""
    status = _effective_component_status(
        component_id,
        state,
        external_adapters,
    )
    health = _health_status(status)
    name = COMPONENT_NAMES.get(component_id, component_id)
    details = state.details if state and isinstance(state.details, dict) else {}

    return {
        "service": {
            "id": component_id,
            "name": name,
            "owner": "Cybersecurity backend",
            "port": _backend_public_port(),
            "protocol": "http",
            "url": f"/api/state/components/{component_id}",
            "method": "GET",
            "timeoutMs": 10000,
            "critical": True,
            "description": COMPONENT_DESCRIPTIONS.get(component_id, ""),
        },
        "status": health,
        "checkedAt": generated_at,
        "latencyMs": None,
        "statusCode": 200 if health != "unchecked" else None,
        "detail": f"{_status_label(status)}. {_details_text(details)}",
        "corsLimited": False,
    }


def _build_api_snapshot(
    states: list[ComponentState],
    generated_at: str,
    external_adapters: list[dict[str, Any]],
) -> dict[str, Any]:
    """Будує зведення інтеграцій API лише з підтверджених станів."""
    indexed = _state_index(states)
    results = [
        _service_result(
            component_id,
            indexed.get(component_id),
            generated_at,
            external_adapters,
        )
        for component_id in CANONICAL_COMPONENTS
    ]
    summary = {
        "total": len(results),
        "online": sum(1 for item in results if item["status"] == "online"),
        "degraded": sum(1 for item in results if item["status"] == "degraded"),
        "offline": sum(1 for item in results if item["status"] == "offline"),
        "unchecked": sum(1 for item in results if item["status"] == "unchecked"),
        "criticalOffline": sum(
            1
            for item in results
            if item["status"] == "offline" and item["service"]["critical"]
        ),
    }

    if summary["criticalOffline"] > 0:
        component_status = "disconnected"
    elif summary["degraded"] > 0 or summary["unchecked"] > 0:
        component_status = "degraded"
    else:
        component_status = "healthy"

    return {
        "generatedAt": generated_at,
        "component": {
            "component_id": "api",
            "component_type": "cybersecurity_backend",
            "status": component_status,
            "details": summary,
            "last_updated": generated_at,
        },
        "results": results,
    }


def _metrics_from_state(
    state: ComponentState | None,
) -> list[dict[str, Any]]:
    status = _state_status(state)
    details = state.details if state and isinstance(state.details, dict) else {}
    metrics = [
        {
            "label": "Статус",
            "value": status,
            "level": _signal_level(status),
        }
    ]

    for key, value in details.items():
        metrics.append(
            {
                "label": str(key),
                "value": value,
                "level": _signal_level(status),
            }
        )

    return metrics


def _signals_from_state(
    component_id: str,
    state: ComponentState | None,
) -> list[dict[str, str]]:
    status = _state_status(state)
    level = _signal_level(status)
    name = COMPONENT_NAMES.get(component_id, component_id)

    if level == "normal":
        return [
            {
                "level": "normal",
                "title": f"{name}: штатний стан",
                "description": (
                    "Backend не бачить активної деградації "
                    "для цього компонента."
                ),
            }
        ]

    return [
        {
            "level": level,
            "title": f"{name}: {_status_label(status)}",
            "description": (
                "Стан отримано з backend-шару кіберзахисту; "
                "UI не звертається до чужого сервісу напряму."
            ),
        }
    ]


def _raw_state_preview(
    component_id: str,
    state: ComponentState | None,
) -> dict[str, Any] | None:
    if state is None:
        return None

    return {
        "component_id": component_id,
        "component_type": state.component_type,
        "status": state.status,
        "details": state.details,
        "last_updated": state.last_updated,
    }


def _build_read_only_snapshot(
    states: list[ComponentState],
    generated_at: str,
    external_adapters: list[dict[str, Any]],
) -> dict[str, Any]:
    indexed = _state_index(states)
    adapters = []

    for component_id in CANONICAL_COMPONENTS:
        state = indexed.get(component_id)
        status = _state_status(state)
        adapters.append(
            {
                "source": {
                    "id": component_id,
                    "name": COMPONENT_NAMES.get(component_id, component_id),
                    "owner": "Cybersecurity backend",
                    "port": _backend_public_port(),
                    "endpoint": f"/api/state/components/{component_id}",
                    "timeoutMs": 10000,
                    "description": COMPONENT_DESCRIPTIONS.get(
                        component_id,
                        "",
                    ),
                },
                "status": _adapter_status(status),
                "checkedAt": (
                    state.last_updated
                    if state and state.last_updated
                    else generated_at
                ),
                "latencyMs": None,
                "statusCode": 200 if state else None,
                "metrics": _metrics_from_state(state),
                "signals": _signals_from_state(component_id, state),
                "rawPreview": _raw_state_preview(component_id, state),
            }
        )

    adapters.extend(
        sorted(
            external_adapters,
            key=lambda item: str(
                item.get("source", {}).get("id", "")
            ),
        )
    )

    statuses = [item["status"] for item in adapters]
    signals = [
        signal
        for item in adapters
        for signal in item["signals"]
    ]

    return {
        "generatedAt": generated_at,
        "summary": {
            "total": len(adapters),
            "ready": statuses.count("ready"),
            "partial": statuses.count("partial"),
            "stale": statuses.count("stale"),
            "unavailable": statuses.count("unavailable"),
            "warningSignals": sum(
                1 for signal in signals
                if signal["level"] == "warning"
            ),
            "criticalSignals": sum(
                1 for signal in signals
                if signal["level"] == "critical"
            ),
        },
        "adapters": adapters,
    }


def _network_status_from_adapter(status: str) -> str:
    if status == "ready":
        return "connected"
    if status == "partial":
        return "partial"
    if status == "stale":
        return "silent"
    return "unavailable"


def _network_source_from_adapter(
    adapter: dict[str, Any],
) -> dict[str, Any]:
    source = adapter.get("source", {})

    return {
        "source": {
            "id": str(source.get("id", "external-network")),
            "name": str(
                source.get("name", "External network source")
            ),
            "owner": str(
                source.get(
                    "owner",
                    "Зовнішній сервіс SmartEnergy",
                )
            ),
            "protocol": str(source.get("protocol", "http")),
            "endpoint": str(source.get("endpoint", "")),
            "port": int(source.get("port", 0) or 0),
            "timeoutMs": int(source.get("timeoutMs", 0) or 0),
            "description": str(source.get("description", "")),
        },
        "status": _network_status_from_adapter(
            str(adapter.get("status", "unavailable"))
        ),
        "checkedAt": adapter.get("checkedAt"),
        "latencyMs": adapter.get("latencyMs"),
        "metrics": adapter.get("metrics", []),
        "signals": adapter.get("signals", []),
        "rawPreview": adapter.get("rawPreview"),
        **(
            {"error": adapter["error"]}
            if adapter.get("error")
            else {}
        ),
    }


def _build_network_snapshot(
    states: list[ComponentState],
    generated_at: str,
    external_adapters: list[dict[str, Any]],
) -> dict[str, Any]:
    indexed = _state_index(states)
    network_state = indexed.get("network")
    status = _state_status(network_state)
    source = {
        "source": {
            "id": "backend-network",
            "name": "Network через cybersecurity backend",
            "owner": "Cybersecurity backend",
            "protocol": "http",
            "endpoint": "/api/state/components/network",
            "port": _backend_public_port(),
            "timeoutMs": 10000,
            "description": COMPONENT_DESCRIPTIONS["network"],
        },
        "status": _network_status(status),
        "checkedAt": (
            network_state.last_updated
            if network_state and network_state.last_updated
            else generated_at
        ),
        "latencyMs": None,
        "metrics": _metrics_from_state(network_state),
        "signals": _signals_from_state("network", network_state),
        "rawPreview": _raw_state_preview("network", network_state),
    }

    external_network_sources = [
        _network_source_from_adapter(adapter)
        for adapter in external_adapters
        if adapter.get("source", {}).get("component") == "network"
    ]
    sources = [source, *external_network_sources]
    signals = [
        signal
        for item in sources
        for signal in item["signals"]
    ]
    statuses = [item["status"] for item in sources]

    return {
        "generatedAt": generated_at,
        "summary": {
            "total": len(sources),
            "connected": statuses.count("connected"),
            "partial": statuses.count("partial"),
            "silent": statuses.count("silent"),
            "unavailable": statuses.count("unavailable"),
            "warningSignals": sum(
                1 for signal in signals
                if signal["level"] == "warning"
            ),
            "criticalSignals": sum(
                1 for signal in signals
                if signal["level"] == "critical"
            ),
        },
        "sources": sources,
    }


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _build_metrics_snapshot(
    raw_metrics: list[dict[str, Any]],
    raw_overall: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    availability_values = [
        _number(item.get("availability_pct"))
        for item in raw_metrics
        if item.get("availability_pct") is not None
    ]
    avg_availability = _number(
        raw_overall.get("avg_availability_pct")
    )

    if avg_availability == 0 and availability_values:
        avg_availability = round(
            sum(availability_values) / len(availability_values),
            2,
        )

    total_incidents = int(
        _number(raw_overall.get("total_incidents"))
    )
    if total_incidents == 0:
        total_incidents = int(
            sum(
                _number(
                    item.get("incident_count")
                    or item.get("incidents_total")
                )
                for item in raw_metrics
            )
        )

    return {
        "generatedAt": generated_at,
        "summary": {
            "policies": len(raw_metrics),
            "avgAvailabilityPct": avg_availability,
            "avgMttdMin": _number(
                raw_overall.get("avg_mttd_min")
            ),
            "avgMttrMin": _number(
                raw_overall.get("avg_mttr_min")
            ),
            "totalIncidents": total_incidents,
            "totalActions": int(
                _number(raw_overall.get("total_actions"))
            ),
        },
        "byPolicy": raw_metrics,
    }


def _incident_severity(value: Any) -> str:
    severity = str(value or "").lower()
    if severity in {"critical", "high"}:
        return "critical"
    return "warning"


def _incident_timestamp(
    incident: dict[str, Any],
    generated_at: str,
) -> str:
    return str(
        incident.get("detect_ts")
        or incident.get("start_ts")
        or generated_at
    )


def _build_incident_item(
    incident: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    incident_id = str(
        incident.get("incident_id")
        or incident.get("id")
        or "incident"
    )
    component = str(
        incident.get("component") or "unknown"
    )
    category = str(
        incident.get("category")
        or incident.get("threat_type")
        or "security"
    )
    policy = str(incident.get("policy") or "unknown")
    description = str(
        incident.get("description")
        or f"{category} на компоненті {component}"
    )

    evidence = [
        f"Політика: {policy}",
        f"Категорія: {category}",
        f"Компонент: {component}",
    ]

    if incident.get("event_count") is not None:
        evidence.append(
            f"Подій: {incident.get('event_count')}"
        )
    if incident.get("mttd_sec") is not None:
        evidence.append(
            f"MTTD: {incident.get('mttd_sec')} с"
        )
    if incident.get("mttr_sec") is not None:
        evidence.append(
            f"MTTR: {incident.get('mttr_sec')} с"
        )

    return {
        "id": incident_id,
        "ruleId": f"{policy}:{category}",
        "severity": _incident_severity(
            incident.get("severity")
        ),
        "title": f"{component.upper()}: {category}",
        "description": description,
        "affectedComponents": [component],
        "evidence": evidence,
        "createdAt": _incident_timestamp(
            incident,
            generated_at,
        ),
    }


def _latest_by_timestamp(
    items: list[dict[str, Any]],
    key: str,
    limit: int,
) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: str(item.get(key) or ""),
        reverse=True,
    )[:limit]


def _decision(
    *,
    decision_id: str,
    priority: str,
    title: str,
    description: str,
    reason: str,
    target_components: list[str],
    related_incident_ids: list[str],
    execution_mode: str,
) -> dict[str, Any]:
    return {
        "id": decision_id,
        "priority": priority,
        "title": title,
        "description": description,
        "reason": reason,
        "targetComponents": target_components,
        "relatedIncidentIds": related_incident_ids,
        "executionMode": execution_mode,
    }


def _adapter_component(
    adapter: dict[str, Any],
) -> str:
    return str(
        adapter.get("source", {}).get(
            "component",
            "unknown",
        )
    )


def _build_decisions(
    incidents: list[dict[str, Any]],
    states: list[ComponentState],
    adapters: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    indexed = _state_index(states)
    incident_ids = [
        str(item.get("id"))
        for item in incidents
    ]
    decisions: list[dict[str, Any]] = []
    integration_mode = _integration_mode()

    unavailable_adapters = [
        item
        for item in adapters
        if item.get("status") == "unavailable"
    ]
    ready_adapters = [
        item
        for item in adapters
        if item.get("status") in {"ready", "partial"}
    ]

    if any(
        item["severity"] == "critical"
        for item in incidents
    ):
        decisions.append(
            _decision(
                decision_id="backend-protected-degradation",
                priority="high",
                title="Підтримати контрольовану деградацію",
                description=(
                    "Backend зафіксував критичні інциденти; "
                    "автоматичні зовнішні команди мають "
                    "проходити через dispatcher."
                ),
                reason=(
                    "Є критичні інциденти "
                    "у snapshot backend-а."
                ),
                target_components=list(
                    CANONICAL_COMPONENTS
                ),
                related_incident_ids=incident_ids,
                execution_mode="manual",
            )
        )

    if external_reads_enabled() and unavailable_adapters:
        decisions.append(
            _decision(
                decision_id="backend-restore-readonly-sources",
                priority="high",
                title="Відновити read-only джерела",
                description=(
                    "Частина зовнішніх джерел SmartEnergy "
                    "недоступна для backend-а кіберзахисту."
                ),
                reason=(
                    f"Недоступно джерел: "
                    f"{len(unavailable_adapters)}."
                ),
                target_components=sorted(
                    {
                        _adapter_component(item)
                        for item in unavailable_adapters
                    }
                ),
                related_incident_ids=incident_ids,
                execution_mode="manual",
            )
        )

    if (
        external_reads_enabled()
        and adapters
        and len(ready_adapters)
        < max(1, len(adapters) // 2)
    ):
        decisions.append(
            _decision(
                decision_id="backend-data-quorum-lost",
                priority="high",
                title=(
                    "Заблокувати автодії через "
                    "недостатній кворум даних"
                ),
                description=(
                    "Backend не має достатньо незалежних "
                    "джерел, щоб безпечно формувати "
                    "автоматичні команди."
                ),
                reason=(
                    f"Доступно {len(ready_adapters)} "
                    f"із {len(adapters)} зовнішніх джерел."
                ),
                target_components=sorted(
                    {
                        _adapter_component(item)
                        for item in adapters
                    }
                ),
                related_incident_ids=incident_ids,
                execution_mode="blocked",
            )
        )

    api_status = _state_status(indexed.get("api"))
    if api_status == "isolated":
        decisions.append(
            _decision(
                decision_id="backend-review-api-isolation",
                priority="high",
                title="Перевірити ізоляцію API",
                description=(
                    "API уже перебуває в ізоляції; потрібне "
                    "ручне підтвердження перед зняттям "
                    "обмеження."
                ),
                reason="Стан компонента api: isolated.",
                target_components=["api"],
                related_incident_ids=incident_ids,
                execution_mode="manual",
            )
        )

    auth_status = _state_status(indexed.get("auth"))
    if auth_status == "blocking":
        decisions.append(
            _decision(
                decision_id="backend-watch-auth-blocking",
                priority="medium",
                title="Контролювати блокування акторів",
                description=(
                    "Auth-шар уже блокує підозрілих акторів; "
                    "UI показує цей стан без прямих команд "
                    "у чужий сервіс."
                ),
                reason="Стан компонента auth: blocking.",
                target_components=["auth"],
                related_incident_ids=incident_ids,
                execution_mode="read_only",
            )
        )

    db_state = indexed.get("db")
    db_details = (
        db_state.details
        if db_state
        and isinstance(db_state.details, dict)
        else {}
    )
    if db_details:
        decisions.append(
            _decision(
                decision_id="backend-confirm-db-snapshot",
                priority="low",
                title="Підтвердити стан резервування БД",
                description=(
                    "Backend має дані про стан БД; наступний "
                    "крок — замінити файлове джерело на "
                    "MongoDB або InfluxDB адаптер."
                ),
                reason=_details_text(db_details),
                target_components=["db"],
                related_incident_ids=[],
                execution_mode="read_only",
            )
        )

    if integration_mode != "active":
        decisions.append(
            _decision(
                decision_id="backend-active-actions-disabled",
                priority="medium",
                title=(
                    "Не виконувати зовнішні команди "
                    "автоматично"
                ),
                description=(
                    "Backend працює не в active режимі, "
                    "тому зовнішні керувальні дії лишаються "
                    "рекомендаціями або unsupported."
                ),
                reason=(
                    f"Поточний режим інтеграції: "
                    f"{integration_mode}."
                ),
                target_components=list(
                    CANONICAL_COMPONENTS
                ),
                related_incident_ids=incident_ids,
                execution_mode="blocked",
            )
        )

    if not decisions:
        decisions.append(
            _decision(
                decision_id="backend-continue-monitoring",
                priority="low",
                title="Продовжити моніторинг",
                description=(
                    "Критичних умов для ручної реакції "
                    "не виявлено."
                ),
                reason=(
                    "Snapshot backend-а доступний і не "
                    "містить критичних сигналів."
                ),
                target_components=list(
                    CANONICAL_COMPONENTS
                ),
                related_incident_ids=[],
                execution_mode="read_only",
            )
        )

    return decisions


def _build_incidents_snapshot(
    raw_incidents: list[dict[str, Any]],
    states: list[ComponentState],
    adapters: list[dict[str, Any]],
    generated_at: str,
    limit: int,
) -> dict[str, Any]:
    latest = _latest_by_timestamp(
        raw_incidents,
        "detect_ts",
        limit,
    )
    incidents = [
        _build_incident_item(item, generated_at)
        for item in latest
    ]
    decisions = _build_decisions(
        incidents,
        states,
        adapters,
    )

    return {
        "generatedAt": generated_at,
        "summary": {
            "totalIncidents": len(incidents),
            "criticalIncidents": sum(
                1
                for item in incidents
                if item["severity"] == "critical"
            ),
            "warningIncidents": sum(
                1
                for item in incidents
                if item["severity"] == "warning"
            ),
            "totalDecisions": len(decisions),
            "highPriorityDecisions": sum(
                1
                for item in decisions
                if item["priority"] == "high"
            ),
            "blockedDecisions": sum(
                1
                for item in decisions
                if item["executionMode"] == "blocked"
            ),
        },
        "incidents": incidents,
        "decisions": decisions,
    }


def _dispatch_mode(
    action: dict[str, Any],
) -> str:
    status = str(action.get("status") or "").lower()

    if status == "applied":
        return "applied"
    if status in {"failed", "unsupported"}:
        return "unsupported"
    return "recommended"


def _dispatch_mode_from_decision(
    decision: dict[str, Any],
) -> str:
    execution_mode = str(
        decision.get("executionMode", "manual")
    )

    if execution_mode == "read_only":
        return "applied"
    if execution_mode == "blocked":
        return "unsupported"
    return "recommended"


def _dispatch_title(mode: str) -> str:
    if mode == "applied":
        return "applied: дію застосовано backend-ом"
    if mode == "unsupported":
        return "unsupported: дію не виконано"
    return "recommended: дію передано як рекомендацію"


def _dispatch_title_from_decision(mode: str) -> str:
    if mode == "applied":
        return "applied: локальний режим застосовано"
    if mode == "unsupported":
        return "unsupported: автодія недоступна"
    return "recommended: потрібне ручне підтвердження"


def _build_decision_dispatch_record(
    decision: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    decision_id = str(
        decision.get("id") or "decision"
    )
    mode = _dispatch_mode_from_decision(decision)

    return {
        "id": f"dispatch-{decision_id}",
        "decisionId": decision_id,
        "mode": mode,
        "title": _dispatch_title_from_decision(mode),
        "description": str(
            decision.get("description")
            or decision.get("title")
            or ""
        ),
        "targetComponents": decision.get(
            "targetComponents",
            [],
        ),
        "reason": str(
            decision.get("reason")
            or "Причину не вказано."
        ),
        "createdAt": generated_at,
    }


def _build_dispatch_record(
    action: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    action_id = str(
        action.get("action_id") or "action"
    )
    action_type = str(
        action.get("action") or "unknown"
    )
    target_component = str(
        action.get("target_component") or "unknown"
    )
    target_id = str(
        action.get("target_id") or ""
    )
    mode = _dispatch_mode(action)

    target_suffix = (
        f"/{target_id}"
        if target_id
        else ""
    )

    return {
        "id": f"dispatch-{action_id}",
        "decisionId": str(
            action.get("correlation_id")
            or action_id
        ),
        "mode": mode,
        "title": _dispatch_title(mode),
        "description": (
            f"{action_type} -> "
            f"{target_component}{target_suffix}"
        ),
        "targetComponents": [target_component],
        "reason": str(
            action.get("reason")
            or "Причину не вказано."
        ),
        "createdAt": str(
            action.get("ts_utc")
            or generated_at
        ),
    }


def _build_actions_snapshot(
    raw_actions: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    generated_at: str,
    limit: int,
) -> dict[str, Any]:
    latest = _latest_by_timestamp(
        raw_actions,
        "ts_utc",
        limit,
    )
    decision_actions = [
        _build_decision_dispatch_record(
            decision,
            generated_at,
        )
        for decision in decisions
    ]
    history_actions = [
        _build_dispatch_record(
            action,
            generated_at,
        )
        for action in latest
    ]
    actions = [
        *decision_actions,
        *history_actions,
    ][:limit]

    return {
        "generatedAt": generated_at,
        "summary": {
            "total": len(actions),
            "applied": sum(
                1
                for item in actions
                if item["mode"] == "applied"
            ),
            "recommended": sum(
                1
                for item in actions
                if item["mode"] == "recommended"
            ),
            "unsupported": sum(
                1
                for item in actions
                if item["mode"] == "unsupported"
            ),
        },
        "actions": actions,
    }


@router.get(
    "/snapshot",
    response_model=CybersecuritySnapshotResponse,
)
def get_cybersecurity_snapshot(
    incident_limit: int = Query(
        20,
        ge=1,
        le=200,
        description="Кількість інцидентів у snapshot",
    ),
    action_limit: int = Query(
        20,
        ge=1,
        le=200,
        description="Кількість dispatcher-записів у snapshot",
    ),
) -> CybersecuritySnapshotResponse:
    """Повертає агрегований стан кіберзахисту для інтегрованого React UI."""
    provider = get_provider()
    generated_at = _utc_now()
    states = provider.get_state()
    incidents = provider.get_incidents(
        max(incident_limit, 1000)
    )
    actions = provider.get_actions(
        max(action_limit, 1000)
    )
    raw_metrics = provider.get_metrics()
    raw_overall = provider.get_overall_metrics()
    external_adapters = read_external_adapter_states(
        generated_at
    )

    api_snapshot = _build_api_snapshot(
        states,
        generated_at,
        external_adapters,
    )
    incidents_snapshot = _build_incidents_snapshot(
        incidents,
        states,
        external_adapters,
        generated_at,
        incident_limit,
    )

    return CybersecuritySnapshotResponse(
        generated_at=generated_at,
        backend=_build_backend_info(
            generated_at,
            api_snapshot,
            external_adapters,
        ),
        api=api_snapshot,
        read_only=_build_read_only_snapshot(
            states,
            generated_at,
            external_adapters,
        ),
        network=_build_network_snapshot(
            states,
            generated_at,
            external_adapters,
        ),
        metrics=_build_metrics_snapshot(
            raw_metrics,
            raw_overall,
            generated_at,
        ),
        incidents=incidents_snapshot,
        actions=_build_actions_snapshot(
            actions,
            incidents_snapshot["decisions"],
            generated_at,
            action_limit,
        ),
    )
