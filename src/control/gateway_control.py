"""HTTP-клієнт для передавання керувальних команд до захисного Gateway."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, Protocol
from urllib.parse import urlparse

import httpx

from src.control.models import (
    ActionAck,
    ActionStatus,
    ActionType,
    SecurityAction,
)


class GatewayControl(Protocol):
    """Контракт засобу виконання керувальних дій через Gateway."""

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
    default_block_ttl_seconds: float = 120.0

    block_path: str = "/_cybersecurity/control/block"
    unblock_path: str = "/_cybersecurity/control/unblock"
    isolate_path: str = "/_cybersecurity/control/isolate"
    restore_path: str = (
        "/_cybersecurity/control/release-isolation"
    )
    rate_limit_path: str = (
        "/_cybersecurity/control/rate-limit"
    )

    def __post_init__(self) -> None:
        """Перевіряє коректність параметрів керувального клієнта."""

        parsed_url = urlparse(self.base_url)

        if parsed_url.scheme not in {"http", "https"}:
            raise ValueError(
                "GATEWAY_CONTROL_URL має використовувати http або https"
            )

        if not parsed_url.hostname:
            raise ValueError(
                "GATEWAY_CONTROL_URL не містить hostname"
            )

        if len(self.token) < 16:
            raise ValueError(
                "GATEWAY_CONTROL_TOKEN має містити щонайменше "
                "16 символів"
            )

        if self.timeout_seconds <= 0:
            raise ValueError(
                "timeout_seconds має бути більше нуля"
            )

        if not 0 < self.default_block_ttl_seconds <= 86_400:
            raise ValueError(
                "default_block_ttl_seconds має бути в межах "
                "від 0 до 86400"
            )

        paths = (
            self.block_path,
            self.unblock_path,
            self.isolate_path,
            self.restore_path,
            self.rate_limit_path,
        )

        for path in paths:
            if not path.startswith("/"):
                raise ValueError(
                    f"Шлях Gateway має починатися з '/': {path}"
                )

    @classmethod
    def from_env(cls) -> "GatewayControlSettings":
        """Створює налаштування зі змінних середовища."""

        timeout_seconds = cls._read_float_env(
            "GATEWAY_CONTROL_TIMEOUT_SECONDS",
            5.0,
        )
        default_block_ttl_seconds = cls._read_float_env(
            "GATEWAY_DEFAULT_BLOCK_TTL_SECONDS",
            120.0,
        )

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

        return cls(
            base_url=base_url,
            token=token,
            timeout_seconds=timeout_seconds,
            default_block_ttl_seconds=(
                default_block_ttl_seconds
            ),
            block_path=os.getenv(
                "GATEWAY_BLOCK_PATH",
                "/_cybersecurity/control/block",
            ).strip(),
            unblock_path=os.getenv(
                "GATEWAY_UNBLOCK_PATH",
                "/_cybersecurity/control/unblock",
            ).strip(),
            isolate_path=os.getenv(
                "GATEWAY_ISOLATE_PATH",
                "/_cybersecurity/control/isolate",
            ).strip(),
            restore_path=os.getenv(
                "GATEWAY_RESTORE_PATH",
                "/_cybersecurity/control/release-isolation",
            ).strip(),
            rate_limit_path=os.getenv(
                "GATEWAY_RATE_LIMIT_PATH",
                "/_cybersecurity/control/rate-limit",
            ).strip(),
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

        try:
            return paths[action_type]
        except KeyError as error:
            raise ValueError(
                f"Непідтримуваний тип дії: {action_type}"
            ) from error

    @staticmethod
    def _read_float_env(
        name: str,
        default: float,
    ) -> float:
        """Читає числове значення зі змінної середовища."""

        raw_value = os.getenv(name)

        if raw_value is None or not raw_value.strip():
            return default

        try:
            return float(raw_value)
        except ValueError as error:
            raise ValueError(
                f"{name} має містити число"
            ) from error


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

    async def execute(
        self,
        action: SecurityAction,
    ) -> ActionAck:
        """Передає одну перевірену команду до Gateway."""

        try:
            path = self._settings.path_for(
                action.action_type
            )
            body = self._build_request_body(action)
        except ValueError as error:
            return ActionAck(
                action_id=action.action_id,
                action_type=action.action_type,
                status=ActionStatus.REJECTED,
                target=action.target,
                service_id=action.service_id,
                message=str(error),
                retryable=False,
            )

        headers = {
            "X-Cybersecurity-Control-Token": (
                self._settings.token
            ),
            "Idempotency-Key": action.action_id,
            "Accept": "application/json",
        }

        try:
            response = await self._client.post(
                path,
                json=body,
                headers=headers,
            )
        except httpx.HTTPError as error:
            return ActionAck(
                action_id=action.action_id,
                action_type=action.action_type,
                status=ActionStatus.FAILED,
                target=action.target,
                service_id=action.service_id,
                message=f"Gateway недоступний: {error}",
                retryable=True,
            )

        response_body = self._read_response_body(response)

        if 200 <= response.status_code < 300:
            applied = response_body.get("applied", True)

            if applied is False:
                return ActionAck(
                    action_id=action.action_id,
                    action_type=action.action_type,
                    status=ActionStatus.REJECTED,
                    target=action.target,
                    service_id=action.service_id,
                    message=(
                        "Gateway прийняв запит, але не застосував дію"
                    ),
                    retryable=False,
                    http_status=response.status_code,
                    gateway_response=response_body,
                )

            return ActionAck(
                action_id=action.action_id,
                action_type=action.action_type,
                status=ActionStatus.APPLIED,
                target=action.target,
                service_id=action.service_id,
                message=(
                    "Gateway успішно застосував керувальну дію"
                ),
                retryable=False,
                http_status=response.status_code,
                gateway_response=response_body,
            )

        if response.status_code == 409:
            return ActionAck(
                action_id=action.action_id,
                action_type=action.action_type,
                status=ActionStatus.APPLIED,
                target=action.target,
                service_id=action.service_id,
                message=(
                    "Gateway уже виконав команду з таким actionId"
                ),
                retryable=False,
                duplicate=True,
                http_status=response.status_code,
                gateway_response=response_body,
            )

        retryable = response.status_code >= 500

        return ActionAck(
            action_id=action.action_id,
            action_type=action.action_type,
            status=(
                ActionStatus.FAILED
                if retryable
                else ActionStatus.REJECTED
            ),
            target=action.target,
            service_id=action.service_id,
            message=(
                "Gateway не зміг застосувати керувальну дію: "
                f"HTTP {response.status_code}"
            ),
            retryable=retryable,
            http_status=response.status_code,
            gateway_response=response_body,
        )

    async def close(self) -> None:
        """Закриває клієнт, якщо він був створений цим об'єктом."""

        if self._owns_client:
            await self._client.aclose()

    def _build_request_body(
        self,
        action: SecurityAction,
    ) -> Mapping[str, Any]:
        """Формує тіло запиту відповідно до моделей Gateway."""

        if action.action_type == ActionType.BLOCK_SOURCE:
            ttl_seconds = (
                action.ttl_seconds
                if action.ttl_seconds is not None
                else self._settings.default_block_ttl_seconds
            )

            if not 0 < ttl_seconds <= 86_400:
                raise ValueError(
                    "Тривалість блокування має бути в межах "
                    "від 0 до 86400 секунд"
                )

            return {
                "action_id": action.action_id,
                "identity": action.target,
                "ttl_sec": ttl_seconds,
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
            enabled = action.parameters.get(
                "enabled",
                True,
            )

            if not isinstance(enabled, bool):
                raise ValueError(
                    "Параметр enabled має бути логічним значенням"
                )

            rate_per_second = self._read_number_parameter(
                action.parameters,
                "rate_per_second",
                "ratePerSecond",
                "requestsPerSecond",
            )
            burst_capacity = self._read_integer_parameter(
                action.parameters,
                "burst_capacity",
                "burstCapacity",
                "burst",
            )

            if not 0 < rate_per_second <= 10_000:
                raise ValueError(
                    "rate_per_second має бути в межах "
                    "від 0 до 10000"
                )

            if not 1 <= burst_capacity <= 100_000:
                raise ValueError(
                    "burst_capacity має бути в межах "
                    "від 1 до 100000"
                )

            return {
                "action_id": action.action_id,
                "enabled": enabled,
                "rate_per_second": rate_per_second,
                "burst_capacity": burst_capacity,
                "reason": action.reason,
            }

        raise ValueError(
            f"Непідтримуваний тип дії: {action.action_type}"
        )

    @staticmethod
    def _read_number_parameter(
        parameters: Mapping[str, Any],
        *names: str,
    ) -> float:
        """Читає обов'язковий числовий параметр команди."""

        value: Any = None

        for name in names:
            if name in parameters:
                value = parameters[name]
                break

        if value is None:
            raise ValueError(
                f"Відсутній параметр {names[0]}"
            )

        if isinstance(value, bool):
            raise ValueError(
                f"Параметр {names[0]} має бути числом"
            )

        try:
            return float(value)
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"Параметр {names[0]} має бути числом"
            ) from error

    @staticmethod
    def _read_integer_parameter(
        parameters: Mapping[str, Any],
        *names: str,
    ) -> int:
        """Читає обов'язковий цілий параметр команди."""

        value: Any = None

        for name in names:
            if name in parameters:
                value = parameters[name]
                break

        if value is None:
            raise ValueError(
                f"Відсутній параметр {names[0]}"
            )

        if isinstance(value, bool):
            raise ValueError(
                f"Параметр {names[0]} має бути цілим числом"
            )

        try:
            converted = int(value)
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"Параметр {names[0]} має бути цілим числом"
            ) from error

        if isinstance(value, float) and not value.is_integer():
            raise ValueError(
                f"Параметр {names[0]} має бути цілим числом"
            )

        return converted

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