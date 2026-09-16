"""Read-only адаптери для підключених сервісів SmartEnergy."""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
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
    connect_port: int | None = None


@dataclass(frozen=True)
class ActiveGatewayTarget:
    """Опис одного активного захисного Gateway для UI snapshot."""

    service_id: str
    name: str
    state_url: str
    public_port: int
    upstream_name: str


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


def _active_gateway_targets() -> list[ActiveGatewayTarget]:
    """Читає список Gateway з формату serviceId|name|url|port|upstream."""

    raw_value = _env(
        "CYBERSECURITY_ACTIVE_GATEWAYS",
        (
            "iot-gateway|Smart Energy API Gateway|"
            "http://cybersecurity-gateway:8080/_cybersecurity/state|"
            "6006|Smart Energy API"
        ),
    )
    targets: list[ActiveGatewayTarget] = []

    for raw_target in raw_value.split(";"):
        raw_target = raw_target.strip()
        if not raw_target:
            continue

        parts = [part.strip() for part in raw_target.split("|", maxsplit=4)]
        if len(parts) != 5 or not all(parts):
            continue

        service_id, name, state_url, raw_port, upstream_name = parts

        try:
            public_port = int(raw_port)
        except ValueError:
            continue

        if not state_url.startswith(("http://", "https://")):
            continue

        targets.append(
            ActiveGatewayTarget(
                service_id=service_id,
                name=name,
                state_url=state_url,
                public_port=public_port,
                upstream_name=upstream_name,
            )
        )

    return targets


def read_active_gateway_states(generated_at: str) -> list[dict[str, Any]]:
    """Повертає окремий фактичний стан кожного захисного Gateway."""

    targets = _active_gateway_targets()
    if not targets:
        return []

    timeout = adapter_timeout_sec()
    with ThreadPoolExecutor(max_workers=min(4, len(targets))) as executor:
        reader = partial(
            _read_active_gateway,
            generated_at=generated_at,
            timeout=timeout,
        )
        return list(executor.map(reader, targets))


def _read_active_gateway(
    target: ActiveGatewayTarget,
    generated_at: str,
    timeout: float,
) -> dict[str, Any]:
    """Читає публічний state endpoint одного Gateway."""

    started = time.perf_counter()
    request = urllib.request.Request(
        target.state_url,
        headers={"Accept": "application/json"},
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(128_000)
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Gateway повернув не JSON-об'єкт")

            latency_ms = round((time.perf_counter() - started) * 1000)
            status = _gateway_status(payload)

            return _gateway_result(
                target=target,
                generated_at=generated_at,
                status=status,
                latency_ms=latency_ms,
                status_code=int(response.status),
                payload=payload,
            )
    except Exception as error:
        latency_ms = round((time.perf_counter() - started) * 1000)
        return _gateway_result(
            target=target,
            generated_at=generated_at,
            status="offline",
            latency_ms=latency_ms,
            status_code=None,
            payload=None,
            error=str(error),
        )


def _gateway_status(payload: dict[str, Any]) -> str:
    """Визначає UI-статус Gateway за його фактичним станом."""

    isolation = payload.get("isolation") or {}
    circuit = payload.get("circuit") or {}
    rate_limit = payload.get("rateLimit") or {}

    if bool(isolation.get("enabled")) or str(circuit.get("mode")) == "open":
        return "degraded"

    if int(payload.get("blockedCount", 0) or 0) > 0:
        return "degraded"

    if str(rate_limit.get("actionId") or "").strip():
        return "degraded"

    return "online"


def _gateway_result(
    *,
    target: ActiveGatewayTarget,
    generated_at: str,
    status: str,
    latency_ms: int,
    status_code: int | None,
    payload: dict[str, Any] | None,
    error: str = "",
) -> dict[str, Any]:
    """Формує сумісну з UI картку одного Gateway."""

    state = payload or {}
    rate_limit = state.get("rateLimit") or {}
    circuit = state.get("circuit") or {}
    isolation = state.get("isolation") or {}

    if error:
        detail = f"Gateway недоступний: {error}"
    else:
        detail = (
            f"upstream: {target.upstream_name}; "
            f"rate: {rate_limit.get('ratePerSecond', '—')}/с; "
            f"burst: {rate_limit.get('burstCapacity', '—')}; "
            f"blocked: {state.get('blockedCount', 0)}; "
            f"circuit: {circuit.get('mode', 'unknown')}; "
            f"isolation: {'on' if isolation.get('enabled') else 'off'}"
        )

    return {
        "service": {
            "id": target.service_id,
            "name": target.name,
            "owner": "Cybersecurity Gateway",
            "port": target.public_port,
            "protocol": "http",
            "url": target.state_url,
            "method": "GET",
            "timeoutMs": int(adapter_timeout_sec() * 1000),
            "critical": True,
            "description": (
                f"Активний захист HTTP-контуру {target.upstream_name}."
            ),
        },
        "status": status,
        "checkedAt": generated_at,
        "latencyMs": latency_ms,
        "statusCode": status_code,
        "detail": detail,
        "corsLimited": False,
        "gatewayState": payload,
    }


def _target_list() -> list[ExternalReadTarget]:
    gateway_url = _env(
        "CYBERSECURITY_GATEWAY_URL",
        "http://backend-kravchenko:8000/api/v1/telemetry/latest?limit=50",
    )
    bms_url = _env("CYBERSECURITY_BMS_URL", "http://backend-service:8000/api/data")
    inverter_url = _env(
        "CYBERSECURITY_INVERTER_URL",
        "http://backend_dosmukhamedov:6050/api/settings",
    )
    stability_url = _env(
        "CYBERSECURITY_TROIAN_URL",
        "http://backend_troian:8085/api/equipment",
    )
    history_url = _env("CYBERSECURITY_HISTORY_URL", "http://history-api:6032/api/status")
    influx_url = _env("CYBERSECURITY_INFLUX_URL", "http://influxdb:8086/health")
    mongo_host = _env("CYBERSECURITY_MONGO_HOST", "mongodb")
    mongo_port = int(_env("CYBERSECURITY_MONGO_PORT", "27017"))
    mqtt_host = _env("CYBERSECURITY_MQTT_HOST", "mosquitto")
    mqtt_port = int(_env("CYBERSECURITY_MQTT_WS_PORT", "9001"))
    websocket_host = _env("CYBERSECURITY_STABILITY_HOST", "functional-stability-shevchenko")
    websocket_port = int(_env("CYBERSECURITY_STABILITY_PORT", "8000"))

    return [
        ExternalReadTarget(
            id="gateway-telemetry",
            name="Телеметрія Gateway",
            component="gateway",
            protocol="http",
            endpoint=gateway_url,
            port=int(_env("CYBERSECURITY_GATEWAY_PORT", "6006")),
            description="Надає актуальні енергетичні показники із захищеного backend.",
            url=gateway_url,
        ),
        ExternalReadTarget(
            id="bms-state",
            name="BMS батареї",
            component="api",
            protocol="http",
            endpoint=bms_url,
            port=int(_env("CYBERSECURITY_BMS_PORT", "6005")),
            description="Показує заряд, напругу, струм і температуру батареї.",
            url=bms_url,
        ),
        ExternalReadTarget(
            id="inverter-settings",
            name="Гібридний інвертор",
            component="api",
            protocol="http",
            endpoint=inverter_url,
            port=int(_env("CYBERSECURITY_INVERTER_PORT", "6050")),
            description="Надає поточний режим роботи й налаштування інвертора.",
            url=inverter_url,
        ),
        ExternalReadTarget(
            id="troian-advisor",
            name="Сервіс функціональної стійкості",
            component="api",
            protocol="http",
            endpoint=stability_url,
            port=int(_env("CYBERSECURITY_TROIAN_PORT", "6028")),
            description="Надає дані про обладнання для оцінювання функціональної стійкості.",
            url=stability_url,
        ),
        ExternalReadTarget(
            id="history-api",
            name="API історичних даних",
            component="db",
            protocol="http",
            endpoint=history_url,
            port=int(_env("CYBERSECURITY_HISTORY_PORT", "6032")),
            description="Надає збережені раніше вимірювання енергетичної системи.",
            url=history_url,
        ),
        ExternalReadTarget(
            id="influxdb-health",
            name="InfluxDB",
            component="db",
            protocol="http",
            endpoint=influx_url,
            port=int(_env("CYBERSECURITY_INFLUX_PORT", "6029")),
            description="Зберігає часові ряди енергетичних вимірювань.",
            url=influx_url,
        ),
        ExternalReadTarget(
            id="mongodb-socket",
            name="MongoDB",
            component="db",
            protocol="tcp",
            endpoint=f"{mongo_host}:{mongo_port}",
            port=mongo_port,
            description="Зберігає дані сервісів Smart Energy у документному форматі.",
            host=mongo_host,
            connect_port=mongo_port,
        ),
        ExternalReadTarget(
            id="mqtt-broker",
            name="MQTT broker",
            component="network",
            protocol="tcp",
            endpoint=f"{mqtt_host}:{mqtt_port}",
            port=int(_env("CYBERSECURITY_MQTT_PUBLIC_PORT", "6031")),
            description="Передає телеметрію між пристроями та сервісами через MQTT.",
            host=mqtt_host,
            connect_port=mqtt_port,
        ),
        ExternalReadTarget(
            id="functional-stability-ws",
            name="WebSocket функціональної стійкості",
            component="network",
            protocol="tcp",
            endpoint=f"{websocket_host}:{websocket_port}/ws",
            port=int(_env("CYBERSECURITY_STABILITY_PUBLIC_PORT", "6040")),
            description="Передає в реальному часі оновлення функціональної стійкості.",
            host=websocket_host,
            connect_port=websocket_port,
        ),
    ]


def read_external_adapter_states(generated_at: str) -> list[dict[str, Any]]:
    """Зчитує всі увімкнені зовнішні read-only джерела."""
    if not external_reads_enabled():
        return []

    targets = _target_list()
    timeout = adapter_timeout_sec()
    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as executor:
        reader = partial(_read_target, generated_at=generated_at, timeout=timeout)
        return list(executor.map(reader, targets))


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
    return target.connect_port or target.port


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
