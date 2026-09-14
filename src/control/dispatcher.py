"""Диспетчер керувальних команд системи кіберзахисту."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any

from pydantic import ValidationError

from src.control.gateway_control import GatewayControl
from src.control.idempotency import IdempotencyStore
from src.control.models import (
    ActionAck,
    ActionStatus,
    SecurityAction,
)


class ActionDispatcher:
    """Перевіряє ідемпотентність та передає команди до Gateway."""

    def __init__(
        self,
        gateway_control: GatewayControl,
        idempotency_store: IdempotencyStore,
        max_concurrency: int = 4,
    ) -> None:
        """Створює диспетчер з обмеженням паралельного виконання."""

        if max_concurrency <= 0:
            raise ValueError("max_concurrency має бути більше нуля")

        self._gateway_control = gateway_control
        self._idempotency_store = idempotency_store
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def dispatch(
        self,
        action: SecurityAction | dict[str, Any],
    ) -> ActionAck:
        """Виконує одну команду не більше одного разу."""

        validated_action = self._validate_action(action)
        claim = self._idempotency_store.claim(
            validated_action.action_id
        )

        if claim.cached_ack is not None:
            return claim.[cached_ack.as](http://cached_ack.as)_duplicate()

        if [claim.in](http://claim.in)_progress:
            return [ActionAck.in](http://ActionAck.in)_progress(validated_action)

        async with self._semaphore:
            try:
                ack = await self._gateway_control.execute(
                    validated_action
                )
            except Exception as error:
                ack = ActionAck(
                    actionId=validated_action.action_id,
                    actionType=validated_action.action_type,
                    status=ActionStatus.FAILED,
                    target=validated_action.target,
                    serviceId=validated_action.service_id,
                    message=(
                        "Непередбачена помилка під час виконання "
                        f"команди: {error}"
                    ),
                    retryable=True,
                )

            self._idempotency_store.complete(ack)
            return ack

    async def dispatch_many(
        self,
        actions: Iterable[SecurityAction | dict[str, Any]],
    ) -> list[ActionAck]:
        """Виконує набір команд з обмеженою паралельністю."""

        tasks = [
            asyncio.create_task(self.dispatch(action))
            for action in actions
        ]

        if not tasks:
            return []

        return list(await asyncio.gather(*tasks))

    async def close(self) -> None:
        """Закриває ресурси засобу керування Gateway."""

        await self._gateway_control.close()

    @staticmethod
    def _validate_action(
        action: SecurityAction | dict[str, Any],
    ) -> SecurityAction:
        """Перетворює вхідне значення на перевірену модель команди."""

        if isinstance(action, SecurityAction):
            return action

        try:
            return SecurityAction.model_validate(action)
        except ValidationError as error:
            raise ValueError(
                f"Некоректна керувальна команда: {error}"
            ) from error