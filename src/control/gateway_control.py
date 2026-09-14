"""HTTP-клієнт для передавання керувальних команд до захисного Gateway."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

import httpx

from src.control.models import (
    ActionAck,
    ActionStatus,
    ActionType,
    SecurityAction,
)


class GatewayControl(Protocol):
    """Контракт засобу, який виконує керувальні дії через Gateway."""

    async def execute(self, action: SecurityAction) -> ActionAck:
        """Передає команду до Gateway і повертає підтвердження."""

        ...

    async def close(self) -> None:
        """Звільняє мережеві ресурси клієнта."""

        ...


@dataclass(frozen=True, slots=True)
class GatewayControlSettings:
    """Налаштування з'єднання з керувальним API Gateway."""

    base_url: str
    token: str
    timeout_seconds: float = 5.0
    block_path: str = "/_cybersecurity/control/block"
    unblock_path: str = "/_cybersecurity/control/unblock"
    isolate_path: str = "/_cybersecurity/control/isolate"
    restore_path: str = "/_cybersecurity/control/release"
    rate_limit_path: str = "/_cybersecurity/control/rate-limit"

    @classmethod
    def from_env(cls) -> "GatewayControlSettings":
        """Створює налаштування зі змінних середовища."""

        timeout_seconds = float(
            os.getenv("GATEWAY_CONTROL_TIMEOUT_SECONDS", "5")
        )

        if timeout_seconds <= 0:
            raise ValueError(
                "GATEWAY_CONTROL_TIMEOUT_SECONDS має бути більше нуля"
            )

        base_url = os.getenv(
            "GATEWAY_CONTROL_URL",
            "[gateway](http://gateway:8080)",
        ).rstrip("/")

        token = os.getenv("GATEWAY_CONTROL_TOKEN", "").strip()
        if not token:
            raise ValueError(
                "Змінна GATEWAY_CONTROL_TOKEN є обов'язковою"
            )

        return cls(
            base_url=base_url,
            token=token,
            timeout_seconds=timeout_seconds,
            block_path=os.getenv(
                "GATEWAY_BLOCK_PATH",
                "/_cybersecurity/control/block",
            ),
            unblock_path=os.getenv(
                "GATEWAY_UNBLOCK_PATH",
                "/_cybersecurity/control/unblock",
            ),
            isolate_path=os.getenv(
                "GATEWAY_ISOLATE_PATH",
                "/_cybersecurity/control/isolate",
            ),
            restore_path=os.getenv(
                "GATEWAY_RESTORE_PATH",
                "/_cybersecurity/control/release",
            ),
            rate_limit_path=os.getenv(
                "GATEWAY_RATE_LIMIT_PATH",
                "/_cybersecurity/control/rate-limit",
            ),
        )

    def path_for(self, action_type: ActionType) -> str:
        """Повертає шлях API для відповідного типу команди."""

        paths = {
            ActionType.BLOCK_SOURCE: self.block_path,
            ActionType.UNBLOCK_SOURCE: self.unblock_path,
            ActionType.ISOLATE_SERVICE: self.isolate_path,
            ActionType.RESTORE_SERVICE: self.restore_path,
            ActionType.SET_RATE_LIMIT: self.rate_limit_path,
        }
        return paths[action_type]


class HttpGatewayControl:
    """Виконує керувальні дії через захищений HTTP API Gateway."""

    def __init__(
        self,
        settings: GatewayControlSettings,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Створює HTTP-клієнт або використовує переданий клієнт."""

        self._settings = settings
        self._owns_client = client is None

        self._client = client or httpx.AsyncClient(
            base_url=settings.base_url,
            timeout=httpx.Timeout(settings.timeout_seconds),
            follow_redirects=False,
        )

    async def execute(self, action: SecurityAction) -> ActionAck:
        """Передає одну команду до Gateway."""

        path = self._settings.path_for(action.action_type)
        body = self._build_request_body(action)

        headers = {
            "X-Control-Token": self._settings.token,
            "Authorization": f"Bearer {self._settings.token}",
            "Idempotency-Key": action.action_id,
            "Accept": "application/json",
        }

        try:
            response = await self._client.post(
                path,
                json=body,
                headers=headers,
            )
        except (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.WriteTimeout,
            httpx.RemoteProtocolError,
        ) as error:
            return ActionAck(
                actionId=action.action_id,
                actionType=action.action_type,
                status=ActionStatus.FAILED,
                target=action.target,
                serviceId=action.service_id,
                message=f"Gateway недоступний: {error}",
                retryable=True,
            )

        response_body = self._read_response_body(response)

        if 200 <= response.status_code < 300:
            return ActionAck(
                actionId=action.action_id,
                actionType=action.action_type,
                status=ActionStatus.APPLIED,
                target=action.target,
                serviceId=action.service_id,
                message="Gateway успішно застосував керувальну дію",
                retryable=False,
                httpStatus=response.status_code,
                gatewayResponse=response_body,
            )

        if response.status_code == 409:
            return ActionAck(
                actionId=action.action_id,
                actionType=action.action_type,
                status=ActionStatus.APPLIED,
                target=action.target,
                serviceId=action.service_id,
                message="Gateway уже виконав команду з таким actionId",
                retryable=False,
                duplicate=True,
                httpStatus=response.status_code,
                gatewayResponse=response_body,
            )

        retryable = response.status_code >= 500

        return ActionAck(
            actionId=action.action_id,
            actionType=action.action_type,
            status=(
                ActionStatus.FAILED
                if retryable
                else ActionStatus.REJECTED
            ),
            target=action.target,
            serviceId=action.service_id,
            message=(
                "Gateway не зміг застосувати керувальну дію: "
                f"HTTP {response.status_code}"
            ),
            retryable=retryable,
            httpStatus=response.status_code,
            gatewayResponse=response_body,
        )

    async def close(self) -> None:
        """Закриває HTTP-клієнт, якщо він був створений цим об'єктом."""

        if self._owns_client:
            await self._client.aclose()

    @staticmethod
    def _read_response_body(
        response: httpx.Response,
    ) -> dict[str, Any]:
        """Безпечно перетворює відповідь Gateway на словник."""

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
    def _build_request_body(
        action: SecurityAction,
    ) -> Mapping[str, Any]:
        """Формує тіло HTTP-запиту для конкретної керувальної дії."""

        custom_body = action.parameters.get("requestBody")
        if isinstance(custom_body, dict):
            return custom_body

        if action.action_type is ActionType.BLOCK_SOURCE:
            body: dict[str, Any] = {
                "source": action.target,
                "reason": action.reason,
            }
            if action.ttl_seconds is not None:
                body["durationSeconds"] = action.ttl_seconds
            return body

        if action.action_type is ActionType.UNBLOCK_SOURCE:
            return {
                "source": action.target,
                "reason": action.reason,
            }

        if action.action_type is ActionType.ISOLATE_SERVICE:
            body = {
                "serviceId": action.target,
                "reason": action.reason,
            }
            if action.ttl_seconds is not None:
                body["durationSeconds"] = action.ttl_seconds
            return body

        if action.action_type is ActionType.RESTORE_SERVICE:
            return {
                "serviceId": action.target,
                "reason": action.reason,
            }

        if action.action_type is ActionType.SET_RATE_LIMIT:
            requests_per_second = action.parameters.get(
                "requestsPerSecond"
            )
            burst = action.parameters.get("burst")

            if requests_per_second is None:
                raise ValueError(
                    "Для set_rate_limit потрібен параметр "
                    "requestsPerSecond"
                )

            if burst is None:
                raise ValueError(
                    "Для set_rate_limit потрібен параметр burst"
                )

            body = {
                "source": action.target,
                "requestsPerSecond": requests_per_second,
                "burst": burst,
                "reason": action.reason,
            }

            if action.ttl_seconds is not None:
                body["durationSeconds"] = action.ttl_seconds

            return body

        raise ValueError(
            f"Непідтримуваний тип дії: {action.action_type}"
        )