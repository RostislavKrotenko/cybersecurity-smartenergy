"""HTTP-клієнт для керування захисним Gateway."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from src.control.models import (
    ActionAck,
    ActionStatus,
    ActionType,
    SecurityAction,
)


CONTROL_PATHS: dict[ActionType, str] = {
    ActionType.BLOCK_SOURCE: "/_cybersecurity/control/block",
    ActionType.UNBLOCK_SOURCE: "/_cybersecurity/control/unblock",
    ActionType.ISOLATE_SERVICE: "/_cybersecurity/control/isolate",
    ActionType.RESTORE_SERVICE: (
        "/_cybersecurity/control/release-isolation"
    ),
    ActionType.SET_RATE_LIMIT: (
        "/_cybersecurity/control/rate-limit"
    ),
}


class GatewayControl(Protocol):
    """Контракт керування захисним Gateway."""

    async def execute(
        self,
        action: SecurityAction,
    ) -> ActionAck:
        """Передає команду до Gateway."""

        ...

    async def close(self) -> None:
        """Звільняє ресурси клієнта."""

        ...


@dataclass(frozen=True, slots=True)
class GatewayControlSettings:
    """Налаштування клієнта керувального API Gateway."""

    base_url: str
    token: str
    timeout_seconds: float = 5.0

    @classmethod
    def from_env(cls) -> "GatewayControlSettings":
        """Створює налаштування зі змінних середовища."""

        base_url = os.getenv(
            "GATEWAY_CONTROL_URL",
            "http://gateway:8080",
        ).strip().rstrip("/")

        token = os.getenv(
            "GATEWAY_CONTROL_TOKEN",
            "",
        ).strip()

        if not token:
            raise ValueError(
                "Змінна GATEWAY_CONTROL_TOKEN є обов'язковою"
            )

        try:
            timeout_seconds = float(
                os.getenv(
                    "GATEWAY_CONTROL_TIMEOUT_SECONDS",
                    "5",
                )
            )
        except ValueError as error:
            raise ValueError(
                "GATEWAY_CONTROL_TIMEOUT_SECONDS має бути числом"
            ) from error

        if timeout_seconds <= 0:
            raise ValueError(
                "GATEWAY_CONTROL_TIMEOUT_SECONDS має бути більше нуля"
            )

        return cls(
            base_url=base_url,
            token=token,
            timeout_seconds=timeout_seconds,
        )


class HttpGatewayControl:
    """Виконує керувальні дії через HTTP API Gateway."""

    def __init__(
        self,
        settings: GatewayControlSettings,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Ініціалізує HTTP-клієнт."""

        self._settings = settings
        self._owns_client = client is None

        self._client = client or httpx.AsyncClient(
            base_url=settings.base_url,
            timeout=settings.timeout_seconds,
            follow_redirects=False,
        )

    async def execute(
        self,
        action: SecurityAction,
    ) -> ActionAck:
        """Виконує одну керувальну дію."""

        try:
            path = CONTROL_PATHS[action.action_type]
            payload = self._build_payload(action)
        except (KeyError, TypeError, ValueError) as error:
            return self._create_ack(
                action=action,
                status=ActionStatus.REJECTED,
                message=str(error),
            )

        try:
            response = await self._client.post(
                path,
                json=payload,
                headers={
                    "X-Cybersecurity-Control-Token": (
                        self._settings.token
                    ),
                    "Idempotency-Key": action.action_id,
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as error:
            return self._create_ack(
                action=action,
                status=ActionStatus.FAILED,
                message=f"Gateway недоступний: {error}",
                retryable=True,
            )

        response_body = self._read_response(response)

        if 200 <= response.status_code < 300:
            return self._create_ack(
                action=action,
                status=ActionStatus.APPLIED,
                message="Gateway успішно застосував дію",
                http_status=response.status_code,
                gateway_response=response_body,
            )

        if response.status_code == 409:
            return self._create_ack(
                action=action,
                status=ActionStatus.APPLIED,
                message="Команду вже було виконано",
                duplicate=True,
                http_status=response.status_code,
                gateway_response=response_body,
            )

        retryable = response.status_code >= 500

        return self._create_ack(
            action=action,
            status=(
                ActionStatus.FAILED
                if retryable
                else ActionStatus.REJECTED
            ),
            message=(
                "Gateway відхилив команду: "
                f"HTTP {response.status_code}"
            ),
            retryable=retryable,
            http_status=response.status_code,
            gateway_response=response_body,
        )

    async def close(self) -> None:
        """Закриває внутрішній HTTP-клієнт."""

        if self._owns_client:
            await self._client.aclose()

    @staticmethod
    def _build_payload(
        action: SecurityAction,
    ) -> dict[str, Any]:
        """Формує тіло запиту відповідно до API Gateway."""

        if action.action_type == ActionType.BLOCK_SOURCE:
            return {
                "action_id": action.action_id,
                "identity": action.target,
                "ttl_sec": action.ttl_seconds or 120.0,
                "reason": action.reason,
            }

        if action.action_type == ActionType.UNBLOCK_SOURCE:
            return {
                "action_id": action.action_id,
                "identity": action.target,
                "reason": action.reason,
            }

        if action.action_type == ActionType.ISOLATE_SERVICE:
            return {
                "action_id": action.action_id,
                "reason": action.reason,
            }

        if action.action_type == ActionType.RESTORE_SERVICE:
            return {
                "action_id": action.action_id,
                "reason": action.reason,
            }

        if action.action_type == ActionType.SET_RATE_LIMIT:
            rate = action.parameters.get(
                "rate_per_second",
                action.parameters.get("ratePerSecond"),
            )
            burst = action.parameters.get(
                "burst_capacity",
                action.parameters.get("burstCapacity"),
            )

            if rate is None:
                raise ValueError(
                    "Не вказано параметр rate_per_second"
                )

            if burst is None:
                raise ValueError(
                    "Не вказано параметр burst_capacity"
                )

            return {
                "action_id": action.action_id,
                "enabled": action.parameters.get(
                    "enabled",
                    True,
                ),
                "rate_per_second": rate,
                "burst_capacity": burst,
                "reason": action.reason,
            }

        raise ValueError(
            f"Непідтримуваний тип дії: {action.action_type}"
        )

    @staticmethod
    def _read_response(
        response: httpx.Response,
    ) -> dict[str, Any]:
        """Читає JSON-відповідь без ризику помилки декодування."""

        try:
            value = response.json()
        except ValueError:
            return {
                "text": response.text[:2000],
            }

        if isinstance(value, dict):
            return value

        return {
            "value": value,
        }

    @staticmethod
    def _create_ack(
        *,
        action: SecurityAction,
        status: ActionStatus,
        message: str,
        retryable: bool = False,
        duplicate: bool = False,
        http_status: int | None = None,
        gateway_response: dict[str, Any] | None = None,
    ) -> ActionAck:
        """Створює уніфіковане підтвердження команди."""

        return ActionAck(
            action_id=action.action_id,
            action_type=action.action_type,
            status=status,
            target=action.target,
            service_id=action.service_id,
            message=message,
            retryable=retryable,
            duplicate=duplicate,
            http_status=http_status,
            gateway_response=gateway_response,
        )