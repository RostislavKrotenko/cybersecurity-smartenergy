"""Read-only адаптери для підключених сервісів SmartEnergy."""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ExternalReadTarget:
    """Опис одного read-only джерела для snapshot кіберзахисту."""

    id: str
    name: str
    component: str
    protocol: str
    endpoint: str
    port: int
    description: str
    url: str = ""
    host: str = ""


def external_reads_enabled() -> bool:
    """Повертає, чи увімкнені read-only звернення до зовнішніх сервісів."""
    value = os.getenv("CYBERSECURITY_EXTERNAL_READS", "false").strip().lower()
    return value in {"1", "true", "yes", "on"}


def adapter_timeout_sec() -> float:
    """Повертає timeout одного read-only адаптера."""
    try:
        return max(0.2, float(os.getenv("CYBERSECURITY_ADAPTER_TIMEOUT_SEC", "1.2")))
    except ValueError:
        return 1.2


def _env(name: str, default: str) -> str:
    return os.getenv(name, default).strip()


def _target_list() -> list[ExternalReadTarget]:
    return [
        ExternalReadTarget(
            id="gateway-telemetry",
            name="Телеметрія Gateway",
            component="gateway",
            protocol="http",
            endpoint=_env("CYBERSECURITY_GATEWAY_URL", "http://backend-kravchenko:8000/api/v1/telemetry/latest?limit=50"),
            port=int(_env("CYBERSECURITY_GATEWAY_PORT", "6006")),
            description="Read-only перегляд телеметрії захищеного backend.",
            url=_env("CYBERSECURITY_GATEWAY_URL", "http://backend-kravchenko:8000/api/v1/telemetry/latest?limit=50"),
        ),
        ExternalReadTarget(
            id="bms-state",
            name="BMS батареї",
            component="api",
            protocol="http",
            endpoint=_env("CYBERSECURITY_BMS_URL", "http://backend-service:8000/api/data"),
            port=int(_env("CYBERSECURITY_BMS_PORT", "6005")),
            description="Read-only стан батарейного BMS.",
            url=_env("CYBERSECURITY_BMS_URL", "http://backend-service:8000/api/data"),
        ),
        ExternalReadTarget(
            id="inverter-settings",
            name="Гібридний інвертор",
            component="api",
            protocol="http",
            endpoint=_env("CYBERSECURITY_INVERTER_URL", "http://backend_dosmukhamedov:6050/api/settings"),
            port=int(_env("CYBERSECURITY_INVERTER_PORT", "6050")),
            description="Read-only доступність і налаштування інвертора.",
            url=_env("CYBERSECURITY_INVERTER_URL", "http://backend_dosmukhamedov:6050/api/settings"),
        ),
        ExternalReadTarget(
            id="troian-advisor",
            name="Сервіс функціональної стійкості",
            component="api",
            protocol="http",
            endpoint=_env("CYBERSECURITY_TROIAN_URL", "http://backend_troian:8085/api/equipment"),
            port=int(_env("CYBERSECURITY_TROIAN_PORT", "6028")),
            description="Read-only доступність API рекомендацій.",
            url=_env("CYBERSECURITY_TROIAN_URL", "http://backend_troian:8085/api/equipment"),
        ),
        ExternalReadTarget(
            id="history-api",
            name="API історичних даних",
            component="db",
            protocol="http",
            endpoint=_env("CYBERSECURITY_HISTORY_URL", "http://history-api:6032/api/status"),
            port=int(_env("CYBERSECURITY_HISTORY_PORT", "6032")),
            description="Read-only доступність API історичних даних.",
            url=_env("CYBERSECURITY_HISTORY_URL", "http://history-api:6032/api/status"),
        ),
        ExternalReadTarget(
            id="influxdb-health",
            name="InfluxDB",
            component="db",
            protocol="http",
            endpoint=_env("CYBERSECURITY_INFLUX_URL", "http://influxdb:8086/health"),
            port=int(_env("CYBERSECURITY_INFLUX_PORT", "6029")),
            description="Health endpoint без читання часових рядів.",
            url=_env("CYBERSECURITY_INFLUX_URL", "http://influxdb:8086/health"),
        ),
        ExternalReadTarget(
            id="mongodb-socket",
            name="MongoDB",
            component="db",
            protocol="tcp",
            endpoint=f"{_env('CYBERSECURITY_MONGO_HOST', 'mongodb')}:{_env('CYBERSECURITY_MONGO_PORT', '27017')}",
            port=int(_env("CYBERSECURITY_MONGO_PORT", "27017")),
            description="TCP-перевірка доступності без читання даних.",
            host=_env("CYBERSECURITY_MONGO_HOST", "mongodb"),
        ),
        ExternalReadTarget(
            id="mqtt-broker",
            name="MQTT broker",
            component="network",
            protocol="tcp",
            endpoint=f"{_env('CYBERSECURITY_MQTT_HOST', 'mosquitto')}:{_env('CYBERSECURITY_MQTT_WS_PORT', '9001')}",
            port=int(_env("CYBERSECURITY_MQTT_PUBLIC_PORT", "6031")),
            description="TCP-перевірка доступності MQTT WebSocket.",
            host=_env("CYBERSECURITY_MQTT_HOST", "mosquitto"),
        ),
        ExternalReadTarget(
            id="functional-stability-ws",
            name="WebSocket функціональної стійкості",
            component="network",
            protocol="tcp",
            endpoint=f"{_env('CYBERSECURITY_STABILITY_HOST', 'functional-stability-shevchenko')}:{_env('CYBERSECURITY_STABILITY_PORT', '8000')}/ws",
            port=int(_env("CYBERSECURITY_STABILITY_PUBLIC_PORT", "6040")),
            description="TCP-перевірка доступності WebSocket endpoint.",
            host=_env("CYBERSECURITY_STABILITY_HOST", "functional-stability-shevchenko"),
        ),
    ]


def read_external_adapter_states(generated_at: str) -> list[dict[str, Any]]:
    """Зчитує всі увімкнені зовнішні read-only джерела."""
    if not external_reads_enabled():
        return []

    targets = _target_list()
    timeout = adapter_timeout_sec()
    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as executor:
        futures = [executor.submit(_read_target, target, generated_at, timeout) for target in targets]
        return [future.result() for future in as_completed(futures)]


def _read_target(target: ExternalReadTarget, generated_at: str, timeout: float) -> dict[str, Any]:
    if target.protocol == "http":
        return _read_http_target(target, generated_at, timeout)
    return _read_tcp_target(target, generated_at, timeout)


def _source(target: ExternalReadTarget, timeout: float) -> dict[str, Any]:
    return {
        "id": target.id,
        "name": target.name,
        "owner": "Зовнішній сервіс SmartEnergy",
        "component": target.component,
        "protocol": target.protocol,
        "port": target.port,
        "endpoint": target.endpoint,
        "timeoutMs": int(timeout * 1000),
        "description": target.description,
    }


def _read_http_target(target: ExternalReadTarget, generated_at: str, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    request = urllib.request.Request(target.url, headers={"Accept": "application/json"})

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(64_000)
            latency_ms = round((time.perf_counter() - started) * 1000)
            raw_preview = _decode_preview(body)
            status_code = int(response.status)
            status = "ready" if 200 <= status_code < 300 else "partial"

            return _adapter_state(
                target=target,
                generated_at=generated_at,
                timeout=timeout,
                status=status,
                latency_ms=latency_ms,
                status_code=status_code,
                metrics=_http_metrics(status_code, body, raw_preview),
                raw_preview=raw_preview,
            )
    except urllib.error.HTTPError as exc:
        latency_ms = round((time.perf_counter() - started) * 1000)
        return _adapter_state(
            target=target,
            generated_at=generated_at,
            timeout=timeout,
            status="partial",
            latency_ms=latency_ms,
            status_code=exc.code,
            metrics=[_metric("HTTP статус", exc.code, "warning")],
            raw_preview={"error": str(exc)},
            error=f"HTTP {exc.code}: {exc.reason}",
        )
    except Exception as exc:
        latency_ms = round((time.perf_counter() - started) * 1000)
        return _adapter_state(
            target=target,
            generated_at=generated_at,
            timeout=timeout,
            status="unavailable",
            latency_ms=latency_ms,
            status_code=None,
            metrics=[_metric("Доступність", "немає", "critical")],
            raw_preview=None,
            error=str(exc),
        )


def _read_tcp_target(target: ExternalReadTarget, generated_at: str, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    port = _target_internal_port(target)

    try:
        with socket.create_connection((target.host, port), timeout=timeout):
            latency_ms = round((time.perf_counter() - started) * 1000)
            return _adapter_state(
                target=target,
                generated_at=generated_at,
                timeout=timeout,
                status="ready",
                latency_ms=latency_ms,
                status_code=None,
                metrics=[_metric("TCP порт", port, "normal"), _metric("Доступність", "підключено", "normal")],
                raw_preview={"host": target.host, "port": port, "protocol": target.protocol},
            )
    except Exception as exc:
        latency_ms = round((time.perf_counter() - started) * 1000)
        return _adapter_state(
            target=target,
            generated_at=generated_at,
            timeout=timeout,
            status="unavailable",
            latency_ms=latency_ms,
            status_code=None,
            metrics=[_metric("TCP порт", port, "critical"), _metric("Доступність", "немає", "critical")],
            raw_preview={"host": target.host, "port": port, "protocol": target.protocol},
            error=str(exc),
        )


def _target_internal_port(target: ExternalReadTarget) -> int:
    if target.id == "mqtt-broker":
        return int(_env("CYBERSECURITY_MQTT_WS_PORT", "9001"))
    if target.id == "functional-stability-ws":
        return int(_env("CYBERSECURITY_STABILITY_PORT", "8000"))
    return target.port


def _adapter_state(
    *,
    target: ExternalReadTarget,
    generated_at: str,
    timeout: float,
    status: str,
    latency_ms: int,
    status_code: int | None,
    metrics: list[dict[str, Any]],
    raw_preview: dict[str, Any] | list[Any] | None,
    error: str | None = None,
) -> dict[str, Any]:
    state = {
        "source": _source(target, timeout),
        "status": status,
        "checkedAt": generated_at,
        "latencyMs": latency_ms,
        "statusCode": status_code,
        "metrics": metrics,
        "signals": [_signal(target, status, error)],
        "rawPreview": raw_preview,
    }
    if error:
        state["error"] = error
    return state


def _signal(target: ExternalReadTarget, status: str, error: str | None) -> dict[str, str]:
    if status == "ready":
        return {
            "level": "normal",
            "title": f"{target.name}: read-only джерело доступне",
            "description": "Backend успішно отримав дані або встановив read-only підключення.",
        }
    if status == "partial":
        return {
            "level": "warning",
            "title": f"{target.name}: відповідь обмежена",
            "description": error or "Джерело відповіло, але не в повністю штатному форматі.",
        }
    return {
        "level": "critical",
        "title": f"{target.name}: read-only джерело недоступне",
        "description": error or "Backend не зміг отримати дані у межах timeout.",
    }


def _http_metrics(status_code: int, body: bytes, raw_preview: dict[str, Any] | list[Any] | None) -> list[dict[str, Any]]:
    level = "normal" if 200 <= status_code < 300 else "warning"
    metrics = [
        _metric("HTTP статус", status_code, level),
        _metric("Розмір відповіді", len(body), "normal", "байт"),
    ]

    if isinstance(raw_preview, list):
        metrics.append(_metric("Елементів", len(raw_preview), "normal"))
    elif isinstance(raw_preview, dict):
        metrics.append(_metric("Полів", len(raw_preview), "normal"))

    return metrics


def _metric(label: str, value: Any, level: str, unit: str | None = None) -> dict[str, Any]:
    metric = {"label": label, "value": value, "level": level}
    if unit:
        metric["unit"] = unit
    return metric


def _decode_preview(body: bytes) -> dict[str, Any] | list[Any] | None:
    if not body:
        return None

    text = body.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"text": text[:1000]}

    return _trim_preview(parsed)


def _trim_preview(value: Any) -> dict[str, Any] | list[Any] | Any:
    if isinstance(value, dict):
        return {str(key): _trim_preview(item) for key, item in list(value.items())[:12]}
    if isinstance(value, list):
        return [_trim_preview(item) for item in value[:5]]
    return value
