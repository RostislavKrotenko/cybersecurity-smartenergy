"""Маршрутизація універсальних Action-контрактів до інтерфейсів компонентів.

Аналізатор емітить транспортно-нейтральні Action-об'єкти. ActionRouter зберігає
цей контракт стабільним, але дозволяє підключати різні виконавці для gateway,
API, auth, database та network.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.contracts.action import Action
from src.contracts.interfaces import (
    ActionExecutor,
    ActionResult,
    ActionStatus,
    ApiControl,
    AuthControl,
    DatabaseControl,
    GatewayControl,
    NetworkControl,
)


@dataclass(slots=True)
class ComponentControls:
    """Опційні реалізації керування для кожного канонічного компонента."""

    gateway: GatewayControl | None = None
    api: ApiControl | None = None
    auth: AuthControl | None = None
    db: DatabaseControl | None = None
    network: NetworkControl | None = None


class ActionRouter(ActionExecutor):
    """Передає Action-об'єкти тому компоненту, який може їх виконати."""

    def __init__(self, controls: ComponentControls):
        self.controls = controls

    def execute(self, action: Action) -> ActionResult:
        params = action.params or {}
        action_type = action.action

        if action_type == "enable_rate_limit":
            control = self.controls.gateway
            if control is None:
                return self._unsupported(action, "керування gateway не налаштоване")
            return control.enable_rate_limit(
                action_id=action.action_id,
                correlation_id=action.correlation_id,
                rps=int(params.get("rps", 100)),
                burst=int(params.get("burst", 200)),
                duration_sec=int(params.get("duration_sec", 300)),
            )

        if action_type == "disable_rate_limit":
            control = self.controls.gateway
            if control is None:
                return self._unsupported(action, "керування gateway не налаштоване")
            return control.disable_rate_limit(
                action_id=action.action_id,
                correlation_id=action.correlation_id,
            )

        if action_type == "isolate_component":
            control = self.controls.api
            if control is None:
                return self._unsupported(action, "керування api не налаштоване")
            return control.isolate_component(
                action_id=action.action_id,
                correlation_id=action.correlation_id,
                component_id=action.target_component,
                target_id=action.target_id or action.target_component,
                duration_sec=int(params.get("duration_sec", 120)),
            )

        if action_type == "release_isolation":
            control = self.controls.api
            if control is None:
                return self._unsupported(action, "керування api не налаштоване")
            return control.release_isolation(
                action_id=action.action_id,
                correlation_id=action.correlation_id,
                component_id=action.target_component,
                target_id=action.target_id or action.target_component,
            )

        if action_type == "block_actor":
            control = self.controls.auth
            if control is None:
                return self._unsupported(action, "керування auth не налаштоване")
            return control.block_actor(
                action_id=action.action_id,
                correlation_id=action.correlation_id,
                actor=str(params.get("actor", "")),
                ip=str(params.get("ip", "")),
                duration_sec=int(params.get("duration_sec", 600)),
            )

        if action_type == "unblock_actor":
            control = self.controls.auth
            if control is None:
                return self._unsupported(action, "керування auth не налаштоване")
            return control.unblock_actor(
                action_id=action.action_id,
                correlation_id=action.correlation_id,
                actor=str(params.get("actor", "")),
                ip=str(params.get("ip", "")),
            )

        if action_type == "backup_db":
            control = self.controls.db
            if control is None:
                return self._unsupported(action, "керування database не налаштоване")
            return control.backup(
                action_id=action.action_id,
                correlation_id=action.correlation_id,
                name=str(params.get("name", "")),
            )

        if action_type == "restore_db":
            control = self.controls.db
            if control is None:
                return self._unsupported(action, "керування database не налаштоване")
            return control.restore(
                action_id=action.action_id,
                correlation_id=action.correlation_id,
                snapshot=str(params.get("snapshot", "")),
            )

        if action_type == "corrupt_db":
            control = self.controls.db
            if control is None:
                return self._unsupported(action, "керування database не налаштоване")
            return control.corrupt(action_id=action.action_id, correlation_id=action.correlation_id)

        if action_type == "degrade_network":
            control = self.controls.network
            if control is None:
                return self._unsupported(action, "керування network не налаштоване")
            return control.degrade_network(
                action_id=action.action_id,
                correlation_id=action.correlation_id,
                latency_ms=int(params.get("latency_ms", 200)),
                drop_rate=float(params.get("drop_rate", 0.1)),
                ttl_sec=int(params.get("ttl_sec", 120)),
                disconnected=bool(params.get("disconnected", False)),
            )

        if action_type == "reset_network":
            control = self.controls.network
            if control is None:
                return self._unsupported(action, "керування network не налаштоване")
            return control.reset_network(
                action_id=action.action_id,
                correlation_id=action.correlation_id,
            )

        return self._unsupported(action, f"невідомий тип дії: {action_type}")

    def supports_action(self, action_type: str) -> bool:
        if action_type in {
            "enable_rate_limit",
            "disable_rate_limit",
        }:
            return self.controls.gateway is not None
        if action_type in {"isolate_component", "release_isolation"}:
            return self.controls.api is not None
        if action_type in {"block_actor", "unblock_actor"}:
            return self.controls.auth is not None
        if action_type in {"backup_db", "restore_db", "corrupt_db"}:
            return self.controls.db is not None
        if action_type in {"degrade_network", "reset_network"}:
            return self.controls.network is not None
        return False

    def get_component_status(self, component_id: str) -> dict[str, Any]:
        """ActionRouter не зберігає стан; статус повертають провайдери стану."""
        return {"component_id": component_id, "status": "unknown"}

    @staticmethod
    def _unsupported(action: Action, error: str) -> ActionResult:
        return ActionResult(
            success=False,
            action_id=action.action_id,
            status=ActionStatus.FAILED,
            error=error,
        )
