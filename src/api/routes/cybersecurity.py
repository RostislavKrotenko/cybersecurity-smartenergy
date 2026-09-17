"""Агрегований API для інтегрованого UI кіберзахисту."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from time import monotonic
from typing import Any

from fastapi import APIRouter, Query

from src.api.cybersecurity_adapters import (
    external_reads_enabled,
    read_active_gateway_states,
    read_external_adapter_states,
)
from src.api.data_provider import get_provider
from src.api.models import CybersecuritySnapshotResponse
from src.contracts.interfaces import ComponentState

router = APIRouter(prefix="/cybersecurity", tags=["cybersecurity"])

CANONICAL_COMPONENTS: tuple[str, ...] = ()
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

SNAPSHOT_CACHE_TTL_SECONDS = 2.0
MQTT_INCIDENT_ACTIVE_SECONDS = 60.0
_snapshot_cache: dict[
    tuple[int, int],
    tuple[float, CybersecuritySnapshotResponse],
] = {}
_snapshot_cache_lock = Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_utc(value: Any) -> datetime | None:
    """Безпечно перетворює ISO-8601 timestamp на UTC datetime."""

    raw_value = str(value or "").strip()
    if not raw_value:
        return None

    try:
        parsed = datetime.fromisoformat(raw_value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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
    """Описує окремо захисний контур і зовнішню доступність."""
    component_status = str(api_snapshot.get("component", {}).get("status", "disconnected"))
    external_statuses = {
        str(adapter.get("status", "unavailable"))
        for adapter in external_adapters
    }

    if not external_statuses:
        external_health = "not_configured"
    elif external_statuses == {"ready"}:
        external_health = "available"
    elif "unavailable" in external_statuses:
        external_health = "degraded"
    else:
        external_health = "partial"

    return {
        "status": "available",
        "coreProtectionStatus": component_status,
        "externalAvailabilityStatus": external_health,
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
    _states: list[ComponentState],
    generated_at: str,
    _external_adapters: list[dict[str, Any]],
    active_gateways: list[dict[str, Any]],
) -> dict[str, Any]:
    """Будує зведення лише активних захисних Gateway."""
    results = list(active_gateways)
    summary = {
        "total": len(results),
        "online": sum(1 for item in results if item["status"] == "online"),
        "degraded": sum(1 for item in results if item["status"] == "degraded"),
        "offline": sum(1 for item in results if item["status"] == "offline"),
        "unchecked": sum(1 for item in results if item["status"] == "unchecked"),
        "criticalOffline": sum(1 for item in results if item["status"] == "offline" and item["service"]["critical"]),
    }

    if not results:
        component_status = "unknown"
    elif summary["criticalOffline"] > 0:
        component_status = "disconnected"
    elif summary["degraded"] > 0 or summary["unchecked"] > 0:
        component_status = "degraded"
    else:
        component_status = "healthy"

    return {
        "generatedAt": generated_at,
        "component": {
            "component_id": "protection",
            "component_type": "active_gateway_contour",
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
    _states: list[ComponentState],
    generated_at: str,
    external_adapters: list[dict[str, Any]],
) -> dict[str, Any]:
    """Повертає лише read-only перевірки зовнішніх компонентів."""
    adapters = sorted(
        external_adapters,
        key=lambda item: str(item.get("source", {}).get("id", "")),
    )

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
    """Формує чесне порівняння останнього непорожнього експерименту."""
    has_experiment_data = any(
        int(_number(item.get("incidents_total") or item.get("incident_count"))) > 0
        for item in raw_metrics
    )
    active_metrics: list[dict[str, Any]] = []

    for item in raw_metrics:
        incident_count = int(
            _number(item.get("incidents_total") or item.get("incident_count"))
        )
        detected = incident_count > 0
        metric = {
            key: item[key]
            for key in ACTIVE_POLICY_METRIC_FIELDS
            if key in item
        }
        metric["detected"] = detected
        metric["status"] = (
            "detected"
            if detected
            else "not_detected"
            if has_experiment_data
            else "no_data"
        )

        if not detected:
            for field in (
                "availability_pct",
                "total_downtime_hr",
                "mean_mttd_min",
                "mean_mttr_min",
            ):
                if field in metric:
                    metric[field] = None

        active_metrics.append(metric)

    detected_metrics = [
        item
        for item in raw_metrics
        if int(_number(item.get("incidents_total") or item.get("incident_count"))) > 0
    ]

    def _mean(field: str) -> float | None:
        """Обчислює середнє лише для політик, що виявили сценарій."""
        values = [
            _number(item.get(field))
            for item in detected_metrics
            if item.get(field) is not None
        ]
        if not values:
            return None
        return round(sum(values) / len(values), 2)

    total_incidents = int(
        sum(
            _number(item.get("incidents_total") or item.get("incident_count"))
            for item in detected_metrics
        )
    )

    return {
        "generatedAt": generated_at,
        "status": "ready" if has_experiment_data else "no_data",
        "summary": {
            "policies": len(raw_metrics),
            "detectedByPolicies": len(detected_metrics),
            "avgAvailabilityPct": _mean("availability_pct"),
            "avgMttdMin": _mean("mean_mttd_min"),
            "avgMttrMin": _mean("mean_mttr_min"),
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


def _quarantine_path() -> Path:
    """Повертає шлях до журналу MQTT-карантину."""

    return Path(
        os.getenv(
            "CYBERSECURITY_MQTT_QUARANTINE_PATH",
            "/work/data/integration/quarantine/mqtt-events.jsonl",
        )
    )


def _actions_path() -> Path:
    """Повертає шлях до команд, сформованих Analyzer."""

    return Path(
        os.getenv(
            "CYBERSECURITY_ACTIONS_PATH",
            "/work/data/integration/actions.jsonl",
        )
    )


def _action_acks_path() -> Path:
    """Повертає шлях до підтверджень, записаних Control."""

    return Path(
        os.getenv(
            "CYBERSECURITY_ACTION_ACKS_PATH",
            "/work/data/integration/actions_applied.jsonl",
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


def _merge_live_actions(
    reported_actions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Об'єднує звіт Analyzer з реальними командами та ACK Control.

    ``actions.csv`` може бути відсутнім у контейнері API або належати
    окремому експериментальному output-volume. JSONL-файли інтеграційного
    контуру є спільним журналом фактичних команд і результатів виконання.
    """

    by_id: dict[str, dict[str, Any]] = {}

    for action in reported_actions:
        action_id = str(action.get("action_id") or "").strip()
        if action_id:
            by_id[action_id] = dict(action)

    emitted_actions = _tail_json_objects(
        _actions_path(),
        line_limit=2000,
        byte_limit=2_000_000,
    )
    for action in emitted_actions:
        action_id = str(action.get("action_id") or "").strip()
        if not action_id:
            continue
        existing = by_id.get(action_id, {})
        by_id[action_id] = {**existing, **action}

    service_by_correlation: dict[str, str] = {}
    for action in by_id.values():
        correlation_id = str(action.get("correlation_id") or "").strip()
        service_id = _action_service_id(action)
        if correlation_id and service_id:
            service_by_correlation[correlation_id] = service_id

    for ack in _tail_json_objects(
        _action_acks_path(),
        line_limit=2000,
        byte_limit=2_000_000,
    ):
        action_id = str(ack.get("action_id") or "").strip()
        if not action_id:
            continue

        existing = by_id.get(action_id, {})
        correlation_id = str(
            ack.get("correlation_id")
            or existing.get("correlation_id")
            or action_id
        ).strip()
        service_id = str(
            ack.get("service_id")
            or ack.get("serviceId")
            or _action_service_id(existing)
            or service_by_correlation.get(correlation_id)
            or ""
        ).strip()
        params = existing.get("params")
        if not isinstance(params, dict):
            params = {}
        if service_id:
            params = {**params, "gateway_service_id": service_id}

        result = str(ack.get("result") or "failed").lower()
        by_id[action_id] = {
            **existing,
            "action_id": action_id,
            "ts_utc": str(
                ack.get("applied_ts_utc")
                or existing.get("ts_utc")
                or _utc_now()
            ),
            "action": str(
                ack.get("action")
                or existing.get("action")
                or "unknown"
            ),
            "target_component": str(
                ack.get("target_component")
                or existing.get("target_component")
                or "unknown"
            ),
            "target_id": str(
                existing.get("target_id")
                or service_id
            ),
            "params": params,
            "reason": str(
                existing.get("reason")
                or ack.get("error")
                or "Автоматична дія Control"
            ),
            "correlation_id": correlation_id,
            "status": "applied" if result == "success" else result,
        }

    return list(by_id.values())


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

    quarantine_events: list[dict[str, Any]] = []

    for record in reversed(
        _tail_json_objects(
            _quarantine_path(),
            line_limit=1000,
        )
    ):
        raw_event = record.get("event")
        if not isinstance(raw_event, dict):
            continue

        quarantine_events.append(
            {
                "quarantinedAt": str(
                    record.get("quarantinedAt", generated_at)
                ),
                "reasons": [
                    str(reason)
                    for reason in record.get("reasons", [])
                ],
                "timestamp": str(
                    raw_event.get("timestamp", generated_at)
                ),
                "source": str(raw_event.get("source", "mqtt")),
                "component": str(raw_event.get("component", "edge")),
                "key": str(raw_event.get("key", "")),
                "value": str(raw_event.get("value", "")),
                "unit": str(raw_event.get("unit", "")),
            }
        )

        if len(quarantine_events) >= 8:
            break

    active_window_seconds = max(
        1.0,
        _number(
            os.getenv("CYBERSECURITY_MQTT_INCIDENT_ACTIVE_SEC"),
            MQTT_INCIDENT_ACTIVE_SECONDS,
        ),
    )
    now = _parse_utc(generated_at) or datetime.now(timezone.utc)
    active_quarantine_events = [
        event
        for event in quarantine_events
        if (
            (quarantined_at := _parse_utc(event.get("quarantinedAt")))
            is not None
            and now - quarantined_at <= timedelta(seconds=active_window_seconds)
        )
    ]
    quarantine_status = (
        "active"
        if active_quarantine_events
        else "history"
        if quarantine_events
        else "empty"
    )

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
            "quarantined": len(quarantine_events),
        },
        "events": mqtt_events,
        "quarantine": {
            "status": quarantine_status,
            "visible": len(quarantine_events),
            "active": len(active_quarantine_events),
            "activeWindowSec": active_window_seconds,
            "lastQuarantinedAt": (
                quarantine_events[0]["quarantinedAt"]
                if quarantine_events
                else None
            ),
            "events": quarantine_events,
        },
    }


def _incident_severity(value: Any) -> str:
    severity = str(value or "").lower()
    if severity in {"critical", "high"}:
        return "critical"
    return "warning"


def _incident_timestamp(incident: dict[str, Any], generated_at: str) -> str:
    return str(incident.get("detect_ts") or incident.get("start_ts") or generated_at)


def _service_id_from_source(value: Any) -> str:
    """Витягує serviceId із канонічного джерела Gateway."""

    prefix = "cybersecurity-gateway:"
    for raw_source in str(value or "").split(";"):
        source = raw_source.strip()
        if source.startswith(prefix):
            return source.removeprefix(prefix).strip()
    return ""


def _build_incident_item(
    incident: dict[str, Any],
    generated_at: str,
    *,
    status: str,
    service_id: str | None,
) -> dict[str, Any]:
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

    if service_id:
        evidence.append(f"Захищений сервіс: {service_id}")

    return {
        "id": incident_id,
        "ruleId": rule_id,
        "severity": _incident_severity(incident.get("severity")),
        "title": title,
        "description": description,
        "affectedComponents": affected_components,
        "serviceId": service_id or None,
        "source": str(incident.get("source") or "") or None,
        "status": status,
        "policies": [policy],
        "incidentIds": [incident_id],
        "evidence": evidence,
        "createdAt": _incident_timestamp(incident, generated_at),
    }


def _latest_by_timestamp(items: list[dict[str, Any]], key: str, limit: int) -> list[dict[str, Any]]:
    return sorted(items, key=lambda item: str(item.get(key) or ""), reverse=True)[:limit]


def _build_incidents_snapshot(
    raw_incidents: list[dict[str, Any]],
    active_gateways: list[dict[str, Any]],
    telemetry_snapshot: dict[str, Any],
    generated_at: str,
    limit: int,
) -> dict[str, Any]:
    """Розділяє активні й завершені інциденти за фактичним станом."""

    active_items: list[dict[str, Any]] = []
    resolved_items: list[dict[str, Any]] = []

    for incident in raw_incidents:
        service_id = _incident_service_id(incident, active_gateways)
        is_active = _is_active_incident(
            incident,
            active_gateways=active_gateways,
            telemetry_snapshot=telemetry_snapshot,
            generated_at=generated_at,
            service_id=service_id,
        )
        item = _build_incident_item(
            incident,
            generated_at,
            status="active" if is_active else "resolved",
            service_id=service_id,
        )
        (active_items if is_active else resolved_items).append(item)

    incidents = _coalesce_incident_items(active_items, limit)
    recently_resolved = _coalesce_incident_items(resolved_items, limit)

    return {
        "generatedAt": generated_at,
        "summary": {
            "totalIncidents": len(incidents),
            "activeIncidents": len(incidents),
            "recentlyResolved": len(recently_resolved),
            "criticalIncidents": sum(1 for item in incidents if item["severity"] == "critical"),
            "warningIncidents": sum(1 for item in incidents if item["severity"] == "warning"),
        },
        "incidents": incidents,
        "recentlyResolved": recently_resolved,
    }


def _coalesce_incident_items(
    items: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    """Об'єднує один сценарій, виявлений кількома політиками."""

    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in sorted(
        items,
        key=lambda value: str(value.get("createdAt") or ""),
        reverse=True,
    ):
        key = (
            str(item.get("ruleId") or ""),
            str(item.get("serviceId") or item.get("source") or ""),
            ";".join(str(value) for value in item.get("affectedComponents", [])),
        )
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = item
            continue

        existing["policies"] = sorted(
            set(existing.get("policies", []))
            | set(item.get("policies", []))
        )
        existing["incidentIds"].extend(item.get("incidentIds", []))
        existing["evidence"] = list(
            dict.fromkeys(
                [*existing.get("evidence", []), *item.get("evidence", [])]
            )
        )

    return list(grouped.values())[:limit]


def _normalized_source_tokens(value: Any) -> set[str]:
    """Нормалізує serviceId і технічні назви health-check джерел."""

    normalized = str(value or "").lower()
    for separator in (":", "_", "/", "."):
        normalized = normalized.replace(separator, "-")

    ignored = {"cybersecurity", "gateway", "health", "source", "service"}
    return {
        token
        for token in normalized.split("-")
        if token and token not in ignored
    }


def _incident_service_id(
    incident: dict[str, Any],
    active_gateways: list[dict[str, Any]],
) -> str | None:
    """Зіставляє інцидент із конкретним активним Gateway."""

    explicit = _service_id_from_source(incident.get("source"))
    if explicit:
        return explicit

    source_tokens = _normalized_source_tokens(incident.get("source"))
    matches: list[str] = []
    for gateway in active_gateways:
        service_id = str(gateway.get("service", {}).get("id") or "").strip()
        if service_id and source_tokens & _normalized_source_tokens(service_id):
            matches.append(service_id)

    if len(matches) == 1:
        return matches[0]
    return None


def _gateway_for_service(
    active_gateways: list[dict[str, Any]],
    service_id: str | None,
) -> list[dict[str, Any]]:
    """Повертає цільовий Gateway або весь контур без явної прив'язки."""

    if not service_id:
        return active_gateways
    return [
        gateway
        for gateway in active_gateways
        if str(gateway.get("service", {}).get("id") or "") == service_id
    ]


def _gateway_has_mitigation(gateway: dict[str, Any]) -> bool:
    """Перевіряє фактичне активне стримування на одному Gateway."""

    if gateway.get("status") == "offline":
        return True
    mitigation = gateway.get("mitigation") or {}
    return any(bool(value) for value in mitigation.values())


def _gateway_has_outage(gateway: dict[str, Any]) -> bool:
    """Перевіряє недоступність або незавершене відновлення upstream."""

    if gateway.get("status") == "offline":
        return True

    state = gateway.get("gatewayState") or {}
    circuit = state.get("circuit") or {}
    isolation = state.get("isolation") or {}
    return (
        bool(isolation.get("enabled"))
        or str(circuit.get("mode")) != "closed"
        or int(circuit.get("failureCount", 0) or 0) > 0
    )


def _mqtt_incident_is_active(
    incident: dict[str, Any],
    telemetry_snapshot: dict[str, Any],
    generated_at: str,
) -> bool:
    """Перевіряє наявність свіжої аномалії того самого MQTT-джерела."""

    quarantine = telemetry_snapshot.get("quarantine") or {}
    active_window = _number(
        quarantine.get("activeWindowSec"),
        MQTT_INCIDENT_ACTIVE_SECONDS,
    )
    now = _parse_utc(generated_at) or datetime.now(timezone.utc)
    incident_sources = {
        source.strip()
        for source in str(incident.get("source") or "").split(";")
        if source.strip()
    }

    for event in quarantine.get("events", []):
        quarantined_at = _parse_utc(event.get("quarantinedAt"))
        if quarantined_at is None:
            continue
        if now - quarantined_at > timedelta(seconds=active_window):
            continue
        if not incident_sources or str(event.get("source") or "") in incident_sources:
            return True
    return False


def _is_active_incident(
    incident: dict[str, Any],
    *,
    active_gateways: list[dict[str, Any]],
    telemetry_snapshot: dict[str, Any],
    generated_at: str,
    service_id: str | None,
) -> bool:
    """Визначає live-стан інциденту за реальною ознакою загрози."""
    category = str(
        incident.get("category")
        or incident.get("threat_type")
        or ""
    ).lower()
    gateways = _gateway_for_service(active_gateways, service_id)

    if category == "availability_attack":
        return any(_gateway_has_mitigation(gateway) for gateway in gateways)
    if category == "integrity_attack":
        return _mqtt_incident_is_active(
            incident,
            telemetry_snapshot,
            generated_at,
        )
    if category == "outage":
        return any(_gateway_has_outage(gateway) for gateway in gateways)
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
    service_id = _action_service_id(action)

    return {
        "id": f"dispatch-{action_id}",
        "decisionId": str(action.get("correlation_id") or action_id),
        "mode": mode,
        "title": _dispatch_title(mode),
        "description": f"{action_type} -> {target_component}{f'/{target_id}' if target_id else ''}",
        "targetComponents": [target_component],
        "serviceId": service_id,
        "reason": str(action.get("reason") or "Причину не вказано."),
        "createdAt": str(action.get("ts_utc") or generated_at),
    }


def _build_actions_snapshot(
    raw_actions: list[dict[str, Any]],
    generated_at: str,
    limit: int,
) -> dict[str, Any]:
    active_actions = [action for action in raw_actions if _is_active_action(action)]
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


def _is_active_action(action: dict[str, Any]) -> bool:
    """Відсіює дії за межами активного Gateway-контуру."""

    action_type = str(action.get("action") or "").lower()
    if action_type not in ACTIVE_ACTION_TYPES:
        return False

    target_component = str(
        action.get("target_component") or ""
    ).lower()
    reason = str(action.get("reason") or "").lower()

    if target_component == "auth" or "credential_attack" in reason:
        return False

    if action_type in {"block_actor", "unblock_actor"}:
        return (
            target_component == "gateway"
            and _action_service_id(action) is not None
        )

    return (
        target_component in {"gateway", "api"}
        and _action_service_id(action) is not None
    )


def _action_service_id(action: dict[str, Any]) -> str | None:
    """Повертає явний serviceId цільового Gateway для дії."""

    params = action.get("params")
    if isinstance(params, dict):
        explicit_service_id = str(
            params.get("gateway_service_id")
            or params.get("service_id")
            or ""
        ).strip()
        if explicit_service_id:
            return explicit_service_id

    action_type = str(action.get("action") or "").lower()
    if action_type in {"block_actor", "unblock_actor"}:
        return None

    target_id = str(action.get("target_id") or "").strip()
    if target_id in {"", "gateway", "api"}:
        return None

    return target_id


def _create_cybersecurity_snapshot(
    incident_limit: int,
    action_limit: int,
) -> CybersecuritySnapshotResponse:
    """Збирає один актуальний snapshot кіберзахисту з усіх джерел."""

    provider = get_provider()
    generated_at = _utc_now()
    states = provider.get_state()
    incidents = provider.get_incidents(max(incident_limit, 1000))
    actions = _merge_live_actions(
        provider.get_actions(max(action_limit, 1000))
    )
    raw_metrics = provider.get_metrics()
    raw_overall = provider.get_overall_metrics()
    raw_overall["total_actions"] = float(
        sum(1 for action in actions if _is_active_action(action))
    )
    external_adapters = read_external_adapter_states(generated_at)
    active_gateways = read_active_gateway_states(generated_at)
    api_snapshot = _build_api_snapshot(
        states,
        generated_at,
        external_adapters,
        active_gateways,
    )
    telemetry_snapshot = _build_telemetry_snapshot(generated_at)
    incidents_snapshot = _build_incidents_snapshot(
        incidents,
        active_gateways,
        telemetry_snapshot,
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
        telemetry=telemetry_snapshot,
        incidents=incidents_snapshot,
        actions=_build_actions_snapshot(actions, generated_at, action_limit),
    )


@router.get("/snapshot", response_model=CybersecuritySnapshotResponse)
def get_cybersecurity_snapshot(
    incident_limit: int = Query(20, ge=1, le=200, description="Кількість інцидентів у snapshot"),
    action_limit: int = Query(20, ge=1, le=200, description="Кількість dispatcher-записів у snapshot"),
) -> CybersecuritySnapshotResponse:
    """Повертає агрегований стан і не дублює одночасні зовнішні перевірки."""

    cache_key = (incident_limit, action_limit)
    with _snapshot_cache_lock:
        cached = _snapshot_cache.get(cache_key)
        now = monotonic()
        if cached and now - cached[0] < SNAPSHOT_CACHE_TTL_SECONDS:
            return cached[1]

        snapshot = _create_cybersecurity_snapshot(incident_limit, action_limit)
        if len(_snapshot_cache) >= 8 and cache_key not in _snapshot_cache:
            _snapshot_cache.clear()
        _snapshot_cache[cache_key] = (monotonic(), snapshot)
        return snapshot
