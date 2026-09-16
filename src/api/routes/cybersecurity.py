"""Агрегований API для інтегрованого UI кіберзахисту."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query

from src.api.cybersecurity_adapters import external_reads_enabled, read_external_adapter_states
from src.api.data_provider import get_provider
from src.api.models import CybersecuritySnapshotResponse
from src.contracts.interfaces import ComponentState

router = APIRouter(prefix="/cybersecurity", tags=["cybersecurity"])

CANONICAL_COMPONENTS = ("gateway", "api")
INTEGRATION_MODES = {"dry-run", "shadow", "active"}
ANALYZED_TELEMETRY_KEYS = frozenset({"voltage", "power_kw"})
THREAT_PRESENTATION = {
    "availability_attack": ("RULE-DDOS-001", "DDoS/API flood"),
    "integrity_attack": ("RULE-SPOOF-001", "Аномалія MQTT-телеметрії"),
    "outage": ("RULE-OUT-001", "Недоступність захищеного контуру"),
}
ACTIVE_ACTION_TYPES = frozenset(
    {
        "enable_rate_limit",
        "disable_rate_limit",
        "block_actor",
        "unblock_actor",
        "isolate_component",
        "release_isolation",
    }
)
ACTIVE_POLICY_METRIC_FIELDS = (
    "policy",
    "availability_pct",
    "total_downtime_hr",
    "mean_mttd_min",
    "mean_mttr_min",
    "incidents_total",
    "incidents_critical",
    "incidents_high",
    "incidents_medium",
    "incidents_low",
    "by_availability_attack",
    "by_integrity_attack",
    "by_outage",
)

COMPONENT_NAMES = {
    "gateway": "Gateway",
    "api": "API",
}

COMPONENT_DESCRIPTIONS = {
    "gateway": "Стан gateway-шару та обмежень трафіку.",
    "api": "Стан API-компонента й ізоляції сервісів.",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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

    if component_id == "api":
        return "healthy"

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
        "criticalOffline": sum(1 for item in results if item["status"] == "offline" and item["service"]["critical"]),
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


def _metrics_from_state(state: ComponentState | None) -> list[dict[str, Any]]:
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


def _signals_from_state(component_id: str, state: ComponentState | None) -> list[dict[str, str]]:
    status = _state_status(state)
    level = _signal_level(status)
    name = COMPONENT_NAMES.get(component_id, component_id)

    if level == "normal":
        return [
            {
                "level": "normal",
                "title": f"{name}: штатний стан",
                "description": "Backend не бачить активної деградації для цього компонента.",
            }
        ]

    return [
        {
            "level": level,
            "title": f"{name}: {_status_label(status)}",
            "description": "Стан отримано з backend-шару кіберзахисту; UI не звертається до чужого сервісу напряму.",
        }
    ]


def _raw_state_preview(component_id: str, state: ComponentState | None) -> dict[str, Any] | None:
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
                    "description": COMPONENT_DESCRIPTIONS.get(component_id, ""),
                },
                "status": _adapter_status(status),
                "checkedAt": state.last_updated if state and state.last_updated else generated_at,
                "latencyMs": None,
                "statusCode": 200 if state else None,
                "metrics": _metrics_from_state(state),
                "signals": _signals_from_state(component_id, state),
                "rawPreview": _raw_state_preview(component_id, state),
            }
        )

    adapters.extend(sorted(external_adapters, key=lambda item: str(item.get("source", {}).get("id", ""))))

    statuses = [item["status"] for item in adapters]
    signals = [signal for item in adapters for signal in item["signals"]]

    return {
        "generatedAt": generated_at,
        "summary": {
            "total": len(adapters),
            "ready": statuses.count("ready"),
            "partial": statuses.count("partial"),
            "stale": statuses.count("stale"),
            "unavailable": statuses.count("unavailable"),
            "warningSignals": sum(1 for signal in signals if signal["level"] == "warning"),
            "criticalSignals": sum(1 for signal in signals if signal["level"] == "critical"),
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


def _network_source_from_adapter(adapter: dict[str, Any]) -> dict[str, Any]:
    source = adapter.get("source", {})
    return {
        "source": {
            "id": str(source.get("id", "external-network")),
            "name": str(source.get("name", "External network source")),
            "owner": str(source.get("owner", "Зовнішній сервіс SmartEnergy")),
            "protocol": str(source.get("protocol", "http")),
            "endpoint": str(source.get("endpoint", "")),
            "port": int(source.get("port", 0) or 0),
            "timeoutMs": int(source.get("timeoutMs", 0) or 0),
            "description": str(source.get("description", "")),
        },
        "status": _network_status_from_adapter(str(adapter.get("status", "unavailable"))),
        "checkedAt": adapter.get("checkedAt"),
        "latencyMs": adapter.get("latencyMs"),
        "metrics": adapter.get("metrics", []),
        "signals": adapter.get("signals", []),
        "rawPreview": adapter.get("rawPreview"),
        **({"error": adapter["error"]} if adapter.get("error") else {}),
    }


def _build_network_snapshot(
    _states: list[ComponentState],
    generated_at: str,
    external_adapters: list[dict[str, Any]],
) -> dict[str, Any]:
    """Повертає лише фактичні TCP-перевірки мережевих endpoint."""
    sources = [
        _network_source_from_adapter(adapter)
        for adapter in external_adapters
        if adapter.get("source", {}).get("component") == "network"
    ]
    signals = [signal for item in sources for signal in item["signals"]]
    statuses = [item["status"] for item in sources]

    return {
        "generatedAt": generated_at,
        "summary": {
            "total": len(sources),
            "connected": statuses.count("connected"),
            "partial": statuses.count("partial"),
            "silent": statuses.count("silent"),
            "unavailable": statuses.count("unavailable"),
            "warningSignals": sum(1 for signal in signals if signal["level"] == "warning"),
            "criticalSignals": sum(1 for signal in signals if signal["level"] == "critical"),
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
    active_metrics = [
        {
            key: item[key]
            for key in ACTIVE_POLICY_METRIC_FIELDS
            if key in item
        }
        for item in raw_metrics
    ]
    availability_values = [_number(item.get("availability_pct")) for item in raw_metrics if item.get("availability_pct") is not None]
    avg_availability = _number(raw_overall.get("avg_availability_pct"))
    if avg_availability == 0 and availability_values:
        avg_availability = round(sum(availability_values) / len(availability_values), 2)

    total_incidents = int(_number(raw_overall.get("total_incidents")))
    if total_incidents == 0:
        total_incidents = int(sum(_number(item.get("incident_count") or item.get("incidents_total")) for item in raw_metrics))

    return {
        "generatedAt": generated_at,
        "summary": {
            "policies": len(raw_metrics),
            "avgAvailabilityPct": avg_availability,
            "avgMttdMin": _number(raw_overall.get("avg_mttd_min")),
            "avgMttrMin": _number(raw_overall.get("avg_mttr_min")),
            "totalIncidents": total_incidents,
            "totalActions": int(_number(raw_overall.get("total_actions"))),
        },
        "byPolicy": active_metrics,
    }


def _telemetry_path() -> Path:
    """Повертає шлях до нормалізованих подій Collector."""
    return Path(
        os.getenv(
            "CYBERSECURITY_EVENTS_PATH",
            "/work/data/integration/collected_events.jsonl",
        )
    )


def _tail_json_objects(
    path: Path,
    *,
    line_limit: int = 300,
    byte_limit: int = 512_000,
) -> list[dict[str, Any]]:
    """Безпечно читає останні JSON-об'єкти без завантаження всього файла."""
    if not path.is_file():
        return []

    try:
        with path.open("rb") as stream:
            stream.seek(0, 2)
            file_size = stream.tell()
            start = max(0, file_size - byte_limit)
            stream.seek(start)

            if start:
                stream.readline()

            lines = stream.read().splitlines()[-line_limit:]
    except OSError:
        return []

    objects: list[dict[str, Any]] = []
    for line in lines:
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue

        if isinstance(value, dict):
            objects.append(value)

    return objects


def _build_telemetry_snapshot(
    generated_at: str,
    limit: int = 12,
) -> dict[str, Any]:
    """Формує near-real-time зріз фактичної MQTT-телеметрії."""
    mqtt_events: list[dict[str, Any]] = []

    for event in reversed(_tail_json_objects(_telemetry_path())):
        tags = str(event.get("tags", "")).lower()
        if event.get("event") != "telemetry_read" or "mqtt" not in tags:
            continue

        key = str(event.get("key", ""))
        mqtt_events.append(
            {
                "timestamp": str(event.get("timestamp", generated_at)),
                "source": str(event.get("source", "mqtt")),
                "component": str(event.get("component", "edge")),
                "key": key,
                "value": str(event.get("value", "")),
                "unit": str(event.get("unit", "")),
                "analyzed": key in ANALYZED_TELEMETRY_KEYS,
            }
        )

        if len(mqtt_events) >= limit:
            break

    analyzed_count = sum(1 for event in mqtt_events if event["analyzed"])

    return {
        "generatedAt": generated_at,
        "status": "streaming" if mqtt_events else "waiting",
        "mode": "near-real-time",
        "topic": "sensor/data",
        "analyzedKeys": sorted(ANALYZED_TELEMETRY_KEYS),
        "summary": {
            "visible": len(mqtt_events),
            "analyzed": analyzed_count,
            "collectedOnly": len(mqtt_events) - analyzed_count,
        },
        "events": mqtt_events,
    }


def _incident_severity(value: Any) -> str:
    severity = str(value or "").lower()
    if severity in {"critical", "high"}:
        return "critical"
    return "warning"


def _incident_timestamp(incident: dict[str, Any], generated_at: str) -> str:
    return str(incident.get("detect_ts") or incident.get("start_ts") or generated_at)


def _build_incident_item(incident: dict[str, Any], generated_at: str) -> dict[str, Any]:
    incident_id = str(incident.get("incident_id") or incident.get("id") or "incident")
    component = str(incident.get("component") or "unknown")
    category = str(incident.get("category") or incident.get("threat_type") or "security")
    policy = str(incident.get("policy") or "unknown")
    description = str(incident.get("description") or f"{category} на компоненті {component}")
    rule_id, title = THREAT_PRESENTATION.get(
        category,
        (f"{policy}:{category}", "Подія кіберзахисту"),
    )
    affected_components = [
        item.strip()
        for item in component.split(";")
        if item.strip()
    ] or ["unknown"]

    evidence = [
        f"Політика: {policy}",
        f"Категорія: {category}",
        f"Компонент: {component}",
    ]

    if incident.get("event_count") is not None:
        evidence.append(f"Подій: {incident.get('event_count')}")
    if incident.get("mttd_sec") is not None:
        evidence.append(f"MTTD: {incident.get('mttd_sec')} с")
    if incident.get("mttr_sec") is not None:
        evidence.append(f"MTTR: {incident.get('mttr_sec')} с")

    return {
        "id": incident_id,
        "ruleId": rule_id,
        "severity": _incident_severity(incident.get("severity")),
        "title": title,
        "description": description,
        "affectedComponents": affected_components,
        "evidence": evidence,
        "createdAt": _incident_timestamp(incident, generated_at),
    }


def _latest_by_timestamp(items: list[dict[str, Any]], key: str, limit: int) -> list[dict[str, Any]]:
    return sorted(items, key=lambda item: str(item.get(key) or ""), reverse=True)[:limit]


def _build_incidents_snapshot(
    raw_incidents: list[dict[str, Any]],
    generated_at: str,
    limit: int,
) -> dict[str, Any]:
    active_incidents = [
        incident
        for incident in raw_incidents
        if _is_active_incident(incident)
    ]
    latest = _latest_by_timestamp(active_incidents, "detect_ts", limit)
    incidents = [_build_incident_item(item, generated_at) for item in latest]

    return {
        "generatedAt": generated_at,
        "summary": {
            "totalIncidents": len(incidents),
            "criticalIncidents": sum(1 for item in incidents if item["severity"] == "critical"),
            "warningIncidents": sum(1 for item in incidents if item["severity"] == "warning"),
        },
        "incidents": incidents,
    }


def _is_active_incident(incident: dict[str, Any]) -> bool:
    """Відсіює історичні інциденти, яких немає в активному контурі."""
    category = str(
        incident.get("category")
        or incident.get("threat_type")
        or ""
    ).lower()
    components = {
        component.strip().lower()
        for component in str(incident.get("component") or "").split(";")
        if component.strip()
    }

    if category == "availability_attack":
        return not components or "gateway" in components
    if category == "integrity_attack":
        return "edge" in components
    if category == "outage":
        return not components or bool(components & {"gateway", "api", "iot-gateway"})
    return False


def _dispatch_mode(action: dict[str, Any]) -> str:
    status = str(action.get("status") or "").lower()
    if status in {"applied", "success"}:
        return "applied"
    if status == "failed":
        return "failed"
    if status == "unsupported":
        return "unsupported"
    return "recommended"


def _dispatch_title(mode: str) -> str:
    if mode == "applied":
        return "Дію застосовано"
    if mode == "failed":
        return "Помилка виконання"
    if mode == "unsupported":
        return "Дія не підтримується"
    return "Дію сформовано"


def _build_dispatch_record(action: dict[str, Any], generated_at: str) -> dict[str, Any]:
    action_id = str(action.get("action_id") or "action")
    action_type = str(action.get("action") or "unknown")
    target_component = str(action.get("target_component") or "unknown")
    target_id = str(action.get("target_id") or "")
    mode = _dispatch_mode(action)

    return {
        "id": f"dispatch-{action_id}",
        "decisionId": str(action.get("correlation_id") or action_id),
        "mode": mode,
        "title": _dispatch_title(mode),
        "description": f"{action_type} -> {target_component}{f'/{target_id}' if target_id else ''}",
        "targetComponents": [target_component],
        "reason": str(action.get("reason") or "Причину не вказано."),
        "createdAt": str(action.get("ts_utc") or generated_at),
    }


def _build_actions_snapshot(
    raw_actions: list[dict[str, Any]],
    generated_at: str,
    limit: int,
) -> dict[str, Any]:
    active_actions = [
        action
        for action in raw_actions
        if str(action.get("action") or "").lower() in ACTIVE_ACTION_TYPES
    ]
    latest = _latest_by_timestamp(active_actions, "ts_utc", limit)
    actions = [_build_dispatch_record(action, generated_at) for action in latest]

    return {
        "generatedAt": generated_at,
        "summary": {
            "total": len(actions),
            "applied": sum(1 for item in actions if item["mode"] == "applied"),
            "recommended": sum(1 for item in actions if item["mode"] == "recommended"),
            "failed": sum(1 for item in actions if item["mode"] == "failed"),
            "unsupported": sum(1 for item in actions if item["mode"] == "unsupported"),
        },
        "actions": actions,
    }


@router.get("/snapshot", response_model=CybersecuritySnapshotResponse)
def get_cybersecurity_snapshot(
    incident_limit: int = Query(20, ge=1, le=200, description="Кількість інцидентів у snapshot"),
    action_limit: int = Query(20, ge=1, le=200, description="Кількість dispatcher-записів у snapshot"),
) -> CybersecuritySnapshotResponse:
    """Повертає агрегований стан кіберзахисту для інтегрованого React UI."""
    provider = get_provider()
    generated_at = _utc_now()
    states = provider.get_state()
    incidents = provider.get_incidents(max(incident_limit, 1000))
    actions = provider.get_actions(max(action_limit, 1000))
    raw_metrics = provider.get_metrics()
    raw_overall = provider.get_overall_metrics()
    external_adapters = read_external_adapter_states(generated_at)
    api_snapshot = _build_api_snapshot(
        states,
        generated_at,
        external_adapters,
    )
    incidents_snapshot = _build_incidents_snapshot(
        incidents,
        generated_at,
        incident_limit,
    )

    return CybersecuritySnapshotResponse(
        generated_at=generated_at,
        backend=_build_backend_info(generated_at, api_snapshot, external_adapters),
        api=api_snapshot,
        read_only=_build_read_only_snapshot(states, generated_at, external_adapters),
        network=_build_network_snapshot(states, generated_at, external_adapters),
        metrics=_build_metrics_snapshot(raw_metrics, raw_overall, generated_at),
        telemetry=_build_telemetry_snapshot(generated_at),
        incidents=incidents_snapshot,
        actions=_build_actions_snapshot(actions, generated_at, action_limit),
    )
