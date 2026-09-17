"""FastAPI-застосунок активного захисного шлюзу SmartEnergy."""

from __future__ import annotations

import hmac
import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from .circuit_breaker import CircuitBreaker
from .config import GatewaySettings
from .control_models import (
    BlockControlRequest,
    ControlActionResponse,
    IsolationControlRequest,
    RateLimitControlRequest,
    ReleaseIsolationControlRequest,
    UnblockControlRequest,
)
from .event_emitter import SecurityEventEmitter
from .metrics import GatewayMetrics
from .proxy_utils import (
    build_request_headers,
    build_response_headers,
    build_upstream_url,
    cache_key,
    matches_prefix,
    normalize_request_id,
    request_may_use_cache,
    resolve_client_identity,
    response_may_be_cached,
)
from .rate_limiter import TokenBucketRateLimiter
from .response_cache import LastKnownGoodCache
from .state_store import GatewayStateStore
from .violation_tracker import ViolationTracker

log = logging.getLogger(__name__)

PROXY_METHODS = [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
]


@dataclass(slots=True)
class GatewayRuntime:
    """Об’єднує всі виконувані компоненти одного gateway."""

    settings: GatewaySettings
    state_store: GatewayStateStore
    request_limiter: TokenBucketRateLimiter
    command_limiter: TokenBucketRateLimiter
    violation_tracker: ViolationTracker
    circuit_breaker: CircuitBreaker
    response_cache: LastKnownGoodCache
    event_emitter: SecurityEventEmitter
    metrics: GatewayMetrics
    http_client: httpx.AsyncClient | None = None


def create_runtime(settings: GatewaySettings) -> GatewayRuntime:
    """Створює виконувані компоненти на основі конфігурації."""

    state_store = GatewayStateStore(
        path=settings.state_path,
        service_id=settings.service_id,
        default_rate_per_second=settings.rate_per_second,
        default_burst_capacity=settings.burst_capacity,
    )
    persisted_rate_limit = state_store.get_rate_limit()

    request_limiter = TokenBucketRateLimiter(
        rate_per_second=persisted_rate_limit.rate_per_second,
        burst_capacity=persisted_rate_limit.burst_capacity,
    )
    command_limiter = TokenBucketRateLimiter(
        rate_per_second=settings.command_rate_per_minute / 60.0,
        burst_capacity=max(1, min(5, settings.command_rate_per_minute)),
    )
    circuit_breaker = CircuitBreaker(
        failure_threshold=settings.circuit_failure_threshold,
        recovery_timeout_sec=settings.circuit_recovery_timeout_sec,
    )

    persisted_isolation = state_store.get_isolation()
    if persisted_isolation.enabled:
        circuit_breaker.isolate(persisted_isolation.reason)

    return GatewayRuntime(
        settings=settings,
        state_store=state_store,
        request_limiter=request_limiter,
        command_limiter=command_limiter,
        violation_tracker=ViolationTracker(
            threshold=settings.violation_threshold,
            window_sec=settings.violation_window_sec,
        ),
        circuit_breaker=circuit_breaker,
        response_cache=LastKnownGoodCache(
            ttl_sec=settings.stale_cache_ttl_sec,
            max_body_bytes=settings.stale_cache_max_body_bytes,
        ),
        event_emitter=SecurityEventEmitter(
            path=settings.event_log_path,
            source=f"cybersecurity-gateway:{settings.service_id}",
            component=settings.component,
        ),
        metrics=GatewayMetrics(),
    )


def create_app(settings: GatewaySettings | None = None) -> FastAPI:
    """Створює налаштований FastAPI-застосунок gateway."""

    effective_settings = settings or GatewaySettings.from_env()
    runtime = create_runtime(effective_settings)

    timeout = httpx.Timeout(
        connect=effective_settings.upstream_timeout_sec,
        read=effective_settings.upstream_timeout_sec,
        write=effective_settings.upstream_timeout_sec,
        pool=effective_settings.upstream_timeout_sec,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        """Керує життєвим циклом HTTP-клієнта upstream."""

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            runtime.http_client = client
            yield
            runtime.http_client = None

    application = FastAPI(
        title=f"Cybersecurity Gateway: {effective_settings.service_id}",
        version="0.2.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.state.gateway_runtime = runtime

    async def require_control_token(
        x_control_token: str | None = Header(
            default=None,
            alias="X-Cybersecurity-Control-Token",
        ),
    ) -> None:
        """Перевіряє секрет внутрішнього API керування."""

        configured_token = effective_settings.control_token

        if not configured_token:
            raise HTTPException(
                status_code=503,
                detail="Внутрішнє керування gateway вимкнено",
            )

        supplied_token = x_control_token or ""

        if not hmac.compare_digest(configured_token, supplied_token):
            raise HTTPException(
                status_code=401,
                detail="Некоректний control token",
            )

    @application.get("/_cybersecurity/healthz", include_in_schema=False)
    async def healthz() -> dict[str, object]:
        """Підтверджує, що процес gateway працює."""
        return {
            "status": "ok",
            "serviceId": effective_settings.service_id,
        }

    @application.get("/_cybersecurity/readyz", include_in_schema=False)
    async def readyz() -> JSONResponse:
        """Повертає готовність gateway приймати запити."""
        ready = runtime.http_client is not None
        status_code = 200 if ready else 503

        return JSONResponse(
            status_code=status_code,
            content={
                "status": "ready" if ready else "not_ready",
                "serviceId": effective_settings.service_id,
                "circuit": runtime.circuit_breaker.snapshot(),
            },
        )

    @application.get("/_cybersecurity/state", include_in_schema=False)
    async def public_state() -> dict[str, object]:
        """Повертає санітизований публічний стан gateway."""
        persisted = runtime.state_store.snapshot()

        return {
            "serviceId": effective_settings.service_id,
            "upstreamConfigured": True,
            "blockedCount": persisted["blockedCount"],
            "isolation": persisted["isolation"],
            "rateLimit": persisted["rateLimit"],
            "baselineRateLimit": {
                "enabled": True,
                "ratePerSecond": effective_settings.rate_per_second,
                "burstCapacity": effective_settings.burst_capacity,
            },
            "circuit": runtime.circuit_breaker.snapshot(),
            "cache": runtime.response_cache.snapshot(),
            "metrics": runtime.metrics.snapshot(),
        }

    @application.get(
        "/_cybersecurity/control/state",
        dependencies=[Depends(require_control_token)],
        include_in_schema=False,
    )
    async def control_state() -> dict[str, object]:
        """Повертає повний внутрішній стан gateway."""
        return {
            "serviceId": effective_settings.service_id,
            "upstreamUrl": effective_settings.normalized_upstream_url,
            "persistentState": runtime.state_store.snapshot(),
            "rateLimiter": runtime.request_limiter.snapshot(),
            "commandLimiter": runtime.command_limiter.snapshot(),
            "violations": runtime.violation_tracker.snapshot(),
            "circuit": runtime.circuit_breaker.snapshot(),
            "cache": runtime.response_cache.snapshot(),
            "metrics": runtime.metrics.snapshot(),
        }

    @application.post(
        "/_cybersecurity/control/block",
        response_model=ControlActionResponse,
        response_model_by_alias=True,
        dependencies=[Depends(require_control_token)],
        include_in_schema=False,
    )
    async def block_identity(command: BlockControlRequest) -> ControlActionResponse:
        """Застосовує тимчасове блокування клієнта."""
        state = runtime.state_store.block(
            command.identity,
            ttl_sec=command.ttl_sec,
            reason=command.reason,
            action_id=command.action_id,
        )
        runtime.violation_tracker.reset(command.identity)
        runtime.request_limiter.reset(command.identity)
        runtime.command_limiter.reset(command.identity)
        runtime.metrics.record_action("block_actor", "applied")

        runtime.event_emitter.emit_safely(
            event="auth_failure",
            key="blocked_identity",
            value=command.identity,
            severity="high",
            actor=command.identity,
            ip=command.identity,
            correlation_id=command.action_id,
            tags=("gateway", "action", "blocking"),
            details={
                "reason": command.reason,
                "ttlSec": command.ttl_sec,
            },
        )

        return ControlActionResponse(
            actionId=command.action_id,
            action="block_actor",
            applied=True,
            target=command.identity,
            state={
                "blocked": state.blocked,
                "reason": state.reason,
                "retryAfterSec": state.retry_after_sec,
            },
        )

    @application.post(
        "/_cybersecurity/control/unblock",
        response_model=ControlActionResponse,
        response_model_by_alias=True,
        dependencies=[Depends(require_control_token)],
        include_in_schema=False,
    )
    async def unblock_identity(command: UnblockControlRequest) -> ControlActionResponse:
        """Знімає блокування клієнта."""
        existed = runtime.state_store.unblock(command.identity)
        runtime.violation_tracker.reset(command.identity)
        runtime.request_limiter.reset(command.identity)
        runtime.command_limiter.reset(command.identity)
        runtime.metrics.record_action("unblock_actor", "applied")

        runtime.event_emitter.emit_safely(
            event="service_status",
            key="unblocked_identity",
            value=command.identity,
            severity="low",
            actor=command.identity,
            ip=command.identity,
            correlation_id=command.action_id,
            tags=("gateway", "action", "unblocking"),
            details={
                "reason": command.reason,
                "previouslyBlocked": existed,
            },
        )

        return ControlActionResponse(
            actionId=command.action_id,
            action="unblock_actor",
            applied=True,
            target=command.identity,
            state={
                "blocked": False,
                "previouslyBlocked": existed,
            },
        )

    @application.post(
        "/_cybersecurity/control/rate-limit",
        response_model=ControlActionResponse,
        response_model_by_alias=True,
        dependencies=[Depends(require_control_token)],
        include_in_schema=False,
    )
    async def configure_rate_limit(
        command: RateLimitControlRequest,
    ) -> ControlActionResponse:
        """Застосовує нові параметри rate limiting."""
        state = runtime.state_store.set_rate_limit(
            enabled=command.enabled,
            rate_per_second=command.rate_per_second,
            burst_capacity=command.burst_capacity,
            action_id=command.action_id,
        )
        runtime.request_limiter.configure(
            rate_per_second=command.rate_per_second,
            burst_capacity=command.burst_capacity,
        )
        runtime.metrics.record_action(
            "enable_rate_limit" if command.enabled else "disable_rate_limit",
            "applied",
        )

        runtime.event_emitter.emit_safely(
            event="service_status",
            key="rate_limit_enabled",
            value=command.enabled,
            severity="medium" if command.enabled else "low",
            correlation_id=command.action_id,
            tags=("gateway", "action", "rate-limit"),
            details={
                "reason": command.reason,
                "ratePerSecond": command.rate_per_second,
                "burstCapacity": command.burst_capacity,
            },
        )

        return ControlActionResponse(
            actionId=command.action_id,
            action="enable_rate_limit" if command.enabled else "disable_rate_limit",
            applied=True,
            target=effective_settings.service_id,
            state={
                "enabled": state.enabled,
                "ratePerSecond": state.rate_per_second,
                "burstCapacity": state.burst_capacity,
            },
        )

    @application.post(
        "/_cybersecurity/control/isolate",
        response_model=ControlActionResponse,
        response_model_by_alias=True,
        dependencies=[Depends(require_control_token)],
        include_in_schema=False,
    )
    async def isolate_upstream(command: IsolationControlRequest) -> ControlActionResponse:
        """Примусово ізолює upstream-компонент."""
        state = runtime.state_store.set_isolation(
            enabled=True,
            reason=command.reason,
            action_id=command.action_id,
        )
        runtime.circuit_breaker.isolate(command.reason)
        runtime.metrics.record_action("isolate_component", "applied")

        runtime.event_emitter.emit_safely(
            event="service_status",
            key="isolation",
            value="enabled",
            severity="high",
            correlation_id=command.action_id,
            tags=("gateway", "action", "isolation"),
            details={"reason": command.reason},
        )

        return ControlActionResponse(
            actionId=command.action_id,
            action="isolate_component",
            applied=True,
            target=effective_settings.service_id,
            state={
                "enabled": state.enabled,
                "reason": state.reason,
                "circuit": runtime.circuit_breaker.snapshot(),
            },
        )

    @application.post(
        "/_cybersecurity/control/release-isolation",
        response_model=ControlActionResponse,
        response_model_by_alias=True,
        dependencies=[Depends(require_control_token)],
        include_in_schema=False,
    )
    async def release_isolation(
        command: ReleaseIsolationControlRequest,
    ) -> ControlActionResponse:
        """Знімає ручну ізоляцію upstream-компонента."""
        state = runtime.state_store.set_isolation(
            enabled=False,
            reason=command.reason,
            action_id=command.action_id,
        )
        runtime.circuit_breaker.release_isolation()
        runtime.metrics.record_action("release_isolation", "applied")

        runtime.event_emitter.emit_safely(
            event="service_status",
            key="isolation",
            value="disabled",
            severity="low",
            correlation_id=command.action_id,
            tags=("gateway", "action", "isolation"),
            details={"reason": command.reason},
        )

        return ControlActionResponse(
            actionId=command.action_id,
            action="release_isolation",
            applied=True,
            target=effective_settings.service_id,
            state={
                "enabled": state.enabled,
                "circuit": runtime.circuit_breaker.snapshot(),
            },
        )

    @application.post(
        "/_cybersecurity/control/cache/clear",
        response_model=ControlActionResponse,
        response_model_by_alias=True,
        dependencies=[Depends(require_control_token)],
        include_in_schema=False,
    )
    async def clear_cache(
        command: ReleaseIsolationControlRequest,
    ) -> ControlActionResponse:
        """Очищає кеш останніх коректних відповідей."""
        runtime.response_cache.invalidate()
        runtime.metrics.record_action("clear_cache", "applied")

        return ControlActionResponse(
            actionId=command.action_id,
            action="clear_cache",
            applied=True,
            target=effective_settings.service_id,
            state=runtime.response_cache.snapshot(),
        )

    @application.api_route(
        "/{path:path}",
        methods=PROXY_METHODS,
        include_in_schema=False,
    )
    async def proxy_request(request: Request, path: str) -> Response:
        """Перевіряє політики та проксіює дозволений HTTP-запит."""
        started_at = time.perf_counter()
        normalized_path = f"/{path}" if path else "/"

        if normalized_path.startswith("/_cybersecurity"):
            return _json_error(
                status_code=404,
                code="gateway_endpoint_not_found",
                message="Службовий endpoint не знайдено",
                correlation_id=_new_correlation_id(request),
            )

        correlation_id = _new_correlation_id(request)
        identity = resolve_client_identity(
            request,
            effective_settings.client_ip_header,
        )
        query = request.url.query
        request_cache_key = cache_key(normalized_path, query)
        cache_allowed = request_may_use_cache(
            request,
            path=normalized_path,
            cacheable_prefixes=effective_settings.cacheable_get_prefixes,
        )

        blocked = runtime.state_store.is_blocked(identity)
        if blocked.blocked:
            latency_ms = _elapsed_ms(started_at)
            runtime.metrics.record_request(
                outcome="blocked",
                status_code=403,
                latency_ms=latency_ms,
            )
            runtime.event_emitter.emit_safely(
                event="auth_failure",
                key="blocked_request",
                value=normalized_path,
                severity="high",
                actor=identity,
                ip=identity,
                correlation_id=correlation_id,
                tags=("gateway", "blocked"),
                details={
                    "reason": blocked.reason,
                    "method": request.method,
                },
            )

            return _json_error(
                status_code=403,
                code="client_blocked",
                message="Клієнта тимчасово заблоковано",
                correlation_id=correlation_id,
                retry_after_sec=blocked.retry_after_sec,
            )

        persisted_rate_limit = runtime.state_store.get_rate_limit()

        if persisted_rate_limit.enabled:
            rate_result = runtime.request_limiter.allow(identity)

            if not rate_result.allowed:
                return _handle_policy_violation(
                    runtime=runtime,
                    identity=identity,
                    correlation_id=correlation_id,
                    path=normalized_path,
                    method=request.method,
                    reason="Перевищено загальний ліміт запитів",
                    retry_after_sec=rate_result.retry_after_sec,
                    started_at=started_at,
                    event_name="rate_exceeded",
                )

        is_protected_write = request.method.upper() in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        } and matches_prefix(
            normalized_path,
            effective_settings.protected_write_prefixes,
        )

        if is_protected_write:
            command_result = runtime.command_limiter.allow(identity)

            if not command_result.allowed:
                return _handle_policy_violation(
                    runtime=runtime,
                    identity=identity,
                    correlation_id=correlation_id,
                    path=normalized_path,
                    method=request.method,
                    reason="Перевищено ліміт керувальних команд",
                    retry_after_sec=command_result.retry_after_sec,
                    started_at=started_at,
                    event_name="cmd_exec",
                )

        circuit_decision = runtime.circuit_breaker.before_request()

        if not circuit_decision.allowed:
            if cache_allowed:
                cached_response = _serve_cached_response(
                    runtime=runtime,
                    key=request_cache_key,
                    correlation_id=correlation_id,
                    identity=identity,
                    reason=circuit_decision.reason,
                    started_at=started_at,
                )
                if cached_response is not None:
                    return cached_response

            runtime.metrics.record_request(
                outcome="circuit_open",
                status_code=503,
                latency_ms=_elapsed_ms(started_at),
            )
            runtime.event_emitter.emit_safely(
                event="service_status",
                key="circuit",
                value=circuit_decision.mode.value,
                severity="high",
                actor=identity,
                ip=identity,
                correlation_id=correlation_id,
                tags=("gateway", "circuit-breaker"),
                details={
                    "reason": circuit_decision.reason,
                    "path": normalized_path,
                },
            )

            return _json_error(
                status_code=503,
                code="upstream_isolated",
                message=circuit_decision.reason,
                correlation_id=correlation_id,
                retry_after_sec=circuit_decision.retry_after_sec,
            )

        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                declared_length = 0

            if declared_length > effective_settings.max_request_body_bytes:
                runtime.circuit_breaker.record_success()
                return _reject_large_body(
                    runtime=runtime,
                    identity=identity,
                    correlation_id=correlation_id,
                    path=normalized_path,
                    started_at=started_at,
                    body_size=declared_length,
                )

        body = await request.body()

        if len(body) > effective_settings.max_request_body_bytes:
            runtime.circuit_breaker.record_success()
            return _reject_large_body(
                runtime=runtime,
                identity=identity,
                correlation_id=correlation_id,
                path=normalized_path,
                started_at=started_at,
                body_size=len(body),
            )

        client = runtime.http_client
        if client is None:
            runtime.circuit_breaker.record_failure()
            runtime.metrics.record_request(
                outcome="internal_error",
                status_code=503,
                latency_ms=_elapsed_ms(started_at),
                request_bytes=len(body),
            )

            return _json_error(
                status_code=503,
                code="gateway_not_ready",
                message="HTTP-клієнт gateway ще не готовий",
                correlation_id=correlation_id,
            )

        upstream_url = build_upstream_url(
            effective_settings.normalized_upstream_url,
            normalized_path,
            query,
        )
        upstream_headers = build_request_headers(
            request,
            client_identity=identity,
            correlation_id=correlation_id,
        )

        try:
            upstream_response = await client.request(
                method=request.method,
                url=upstream_url,
                headers=upstream_headers,
                content=body,
            )
        except httpx.TimeoutException:
            runtime.circuit_breaker.record_failure()
            return _handle_upstream_exception(
                runtime=runtime,
                cache_allowed=cache_allowed,
                request_cache_key=request_cache_key,
                identity=identity,
                correlation_id=correlation_id,
                normalized_path=normalized_path,
                started_at=started_at,
                request_bytes=len(body),
                status_code=504,
                code="upstream_timeout",
                message="Перевищено час очікування upstream",
            )
        except httpx.RequestError as exc:
            runtime.circuit_breaker.record_failure()
            log.warning(
                "Помилка з’єднання з upstream %s: %s",
                effective_settings.service_id,
                exc,
            )
            return _handle_upstream_exception(
                runtime=runtime,
                cache_allowed=cache_allowed,
                request_cache_key=request_cache_key,
                identity=identity,
                correlation_id=correlation_id,
                normalized_path=normalized_path,
                started_at=started_at,
                request_bytes=len(body),
                status_code=502,
                code="upstream_unavailable",
                message="Не вдалося з’єднатися з upstream",
            )

        response_body = upstream_response.content
        status_code = upstream_response.status_code
        latency_ms = _elapsed_ms(started_at)

        if status_code >= 500:
            runtime.circuit_breaker.record_failure()

            if cache_allowed:
                cached_response = _serve_cached_response(
                    runtime=runtime,
                    key=request_cache_key,
                    correlation_id=correlation_id,
                    identity=identity,
                    reason=f"Upstream повернув HTTP {status_code}",
                    started_at=started_at,
                    request_bytes=len(body),
                )
                if cached_response is not None:
                    return cached_response

            outcome = "upstream_error"
            severity = "high"
            event_name = "service_status"
        else:
            runtime.circuit_breaker.record_success()

            if 400 <= status_code < 500:
                outcome = "client_error"
                severity = "medium" if status_code in {401, 403, 429} else "low"
                event_name = (
                    "auth_failure" if status_code in {401, 403} else "http_request"
                )
            else:
                outcome = "success"
                severity = "low"
                event_name = "http_request"

            if cache_allowed and response_may_be_cached(upstream_response.headers):
                runtime.response_cache.put(
                    request_cache_key,
                    status_code=status_code,
                    headers=upstream_response.headers,
                    body=response_body,
                )

        runtime.metrics.record_request(
            outcome=outcome,
            status_code=status_code,
            latency_ms=latency_ms,
            request_bytes=len(body),
            response_bytes=len(response_body),
        )
        runtime.event_emitter.emit_safely(
            event=event_name,
            key=request.method.upper(),
            value=status_code,
            severity=severity,
            actor=identity,
            ip=identity,
            correlation_id=correlation_id,
            tags=("gateway", "http"),
            details={
                "path": normalized_path,
                "latencyMs": latency_ms,
                "responseBytes": len(response_body),
            },
        )

        response_headers = build_response_headers(
            upstream_response.headers,
            correlation_id=correlation_id,
            service_id=effective_settings.service_id,
        )

        return Response(
            content=response_body,
            status_code=status_code,
            headers=response_headers,
        )

    return application


def _new_correlation_id(request: Request) -> str:
    raw_value = request.headers.get("x-request-id", "")
    fallback = f"gw-{uuid.uuid4().hex}"

    return normalize_request_id(raw_value, fallback)


def _elapsed_ms(started_at: float) -> float:
    return round((time.perf_counter() - started_at) * 1000, 4)


def _json_error(
    *,
    status_code: int,
    code: str,
    message: str,
    correlation_id: str,
    retry_after_sec: float = 0.0,
) -> JSONResponse:
    headers = {
        "X-Request-ID": correlation_id,
        "X-Cybersecurity-Result": code,
    }

    if retry_after_sec > 0:
        headers["Retry-After"] = str(max(1, int(retry_after_sec + 0.999)))

    return JSONResponse(
        status_code=status_code,
        headers=headers,
        content={
            "error": code,
            "message": message,
            "correlationId": correlation_id,
            "retryAfterSec": round(max(0.0, retry_after_sec), 4),
        },
    )


def _handle_policy_violation(
    *,
    runtime: GatewayRuntime,
    identity: str,
    correlation_id: str,
    path: str,
    method: str,
    reason: str,
    retry_after_sec: float,
    started_at: float,
    event_name: str,
) -> JSONResponse:
    violation_count, should_block = runtime.violation_tracker.record(identity)

    if should_block:
        action_id = f"auto-block-{uuid.uuid4().hex}"

        block = runtime.state_store.block(
            identity,
            ttl_sec=runtime.settings.block_ttl_sec,
            reason=reason,
            action_id=action_id,
        )
        runtime.violation_tracker.reset(identity)
        runtime.request_limiter.reset(identity)
        runtime.command_limiter.reset(identity)
        runtime.metrics.record_action("block_actor", "applied")
        runtime.metrics.record_request(
            outcome="blocked",
            status_code=403,
            latency_ms=_elapsed_ms(started_at),
        )
        runtime.event_emitter.emit_safely(
            event=event_name,
            key="automatic_block",
            value=violation_count,
            severity="high",
            actor=identity,
            ip=identity,
            correlation_id=action_id,
            tags=("gateway", "automatic-action", "blocking"),
            details={
                "path": path,
                "method": method,
                "reason": reason,
                "ttlSec": runtime.settings.block_ttl_sec,
            },
        )

        return _json_error(
            status_code=403,
            code="client_automatically_blocked",
            message="Клієнта автоматично заблоковано",
            correlation_id=correlation_id,
            retry_after_sec=block.retry_after_sec,
        )

    runtime.metrics.record_request(
        outcome="rate_limited",
        status_code=429,
        latency_ms=_elapsed_ms(started_at),
    )
    runtime.event_emitter.emit_safely(
        event=event_name,
        key="rate_limit",
        value=violation_count,
        severity="medium",
        actor=identity,
        ip=identity,
        correlation_id=correlation_id,
        tags=("gateway", "rate-limit"),
        details={
            "path": path,
            "method": method,
            "reason": reason,
        },
    )

    return _json_error(
        status_code=429,
        code="rate_limit_exceeded",
        message=reason,
        correlation_id=correlation_id,
        retry_after_sec=retry_after_sec,
    )


def _reject_large_body(
    *,
    runtime: GatewayRuntime,
    identity: str,
    correlation_id: str,
    path: str,
    started_at: float,
    body_size: int,
) -> JSONResponse:
    violation_count, should_block = runtime.violation_tracker.record(identity)

    runtime.metrics.record_request(
        outcome="body_rejected",
        status_code=413,
        latency_ms=_elapsed_ms(started_at),
        request_bytes=body_size,
    )
    runtime.event_emitter.emit_safely(
        event="cmd_exec",
        key="request_body_bytes",
        value=body_size,
        severity="high",
        actor=identity,
        ip=identity,
        correlation_id=correlation_id,
        tags=("gateway", "payload", "rejected"),
        details={
            "path": path,
            "limitBytes": runtime.settings.max_request_body_bytes,
            "violationCount": violation_count,
        },
    )

    if should_block:
        action_id = f"auto-block-{uuid.uuid4().hex}"
        runtime.state_store.block(
            identity,
            ttl_sec=runtime.settings.block_ttl_sec,
            reason="Повторне перевищення розміру HTTP-запиту",
            action_id=action_id,
        )
        runtime.violation_tracker.reset(identity)
        runtime.metrics.record_action("block_actor", "applied")

    return _json_error(
        status_code=413,
        code="request_body_too_large",
        message="Розмір HTTP-запиту перевищує дозволений ліміт",
        correlation_id=correlation_id,
    )


def _handle_upstream_exception(
    *,
    runtime: GatewayRuntime,
    cache_allowed: bool,
    request_cache_key: str,
    identity: str,
    correlation_id: str,
    normalized_path: str,
    started_at: float,
    request_bytes: int,
    status_code: int,
    code: str,
    message: str,
) -> Response:
    if cache_allowed:
        cached_response = _serve_cached_response(
            runtime=runtime,
            key=request_cache_key,
            correlation_id=correlation_id,
            identity=identity,
            reason=message,
            started_at=started_at,
            request_bytes=request_bytes,
        )
        if cached_response is not None:
            return cached_response

    runtime.metrics.record_request(
        outcome="upstream_error",
        status_code=status_code,
        latency_ms=_elapsed_ms(started_at),
        request_bytes=request_bytes,
    )
    runtime.event_emitter.emit_safely(
        event="service_status",
        key="upstream",
        value=code,
        severity="high",
        actor=identity,
        ip=identity,
        correlation_id=correlation_id,
        tags=("gateway", "upstream", "failure"),
        details={
            "path": normalized_path,
            "message": message,
        },
    )

    return _json_error(
        status_code=status_code,
        code=code,
        message=message,
        correlation_id=correlation_id,
    )


def _serve_cached_response(
    *,
    runtime: GatewayRuntime,
    key: str,
    correlation_id: str,
    identity: str,
    reason: str,
    started_at: float,
    request_bytes: int = 0,
) -> Response | None:
    cached = runtime.response_cache.get(key)
    if cached is None:
        return None

    headers = dict(cached.headers)
    headers["X-Request-ID"] = correlation_id
    headers["X-Cybersecurity-Gateway"] = runtime.settings.service_id
    headers["X-Cybersecurity-Stale"] = "true"
    headers["X-Cybersecurity-Cache-Age"] = f"{cached.age_sec:.3f}"
    headers["Warning"] = '110 - "Відповідь є застарілою"'

    runtime.metrics.record_request(
        outcome="stale_cache",
        status_code=cached.status_code,
        latency_ms=_elapsed_ms(started_at),
        request_bytes=request_bytes,
        response_bytes=len(cached.body),
    )
    runtime.event_emitter.emit_safely(
        event="service_status",
        key="controlled_degradation",
        value="stale_cache",
        severity="medium",
        actor=identity,
        ip=identity,
        correlation_id=correlation_id,
        tags=("gateway", "cache", "degraded"),
        details={
            "reason": reason,
            "cacheAgeSec": cached.age_sec,
        },
    )

    return Response(
        content=cached.body,
        status_code=cached.status_code,
        headers=headers,
    )


app = create_app()
