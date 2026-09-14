"""Моделі команд внутрішнього API керування захисним шлюзом."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StrictControlModel(BaseModel):
    """Базова модель, яка забороняє невідомі поля."""

    model_config = ConfigDict(extra="forbid")


class BlockControlRequest(StrictControlModel):
    """Команда тимчасового блокування клієнта."""

    action_id: str = Field(min_length=1, max_length=128)
    identity: str = Field(min_length=1, max_length=256)
    ttl_sec: float = Field(gt=0, le=86_400)
    reason: str = Field(min_length=1, max_length=1000)


class UnblockControlRequest(StrictControlModel):
    """Команда зняття блокування клієнта."""

    action_id: str = Field(min_length=1, max_length=128)
    identity: str = Field(min_length=1, max_length=256)
    reason: str = Field(default="", max_length=1000)


class RateLimitControlRequest(StrictControlModel):
    """Команда зміни параметрів обмеження частоти."""

    action_id: str = Field(min_length=1, max_length=128)
    enabled: bool = True
    rate_per_second: float = Field(gt=0, le=10_000)
    burst_capacity: int = Field(ge=1, le=100_000)
    reason: str = Field(default="", max_length=1000)


class IsolationControlRequest(StrictControlModel):
    """Команда ручної ізоляції upstream-компонента."""

    action_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=1000)


class ReleaseIsolationControlRequest(StrictControlModel):
    """Команда зняття ручної ізоляції upstream-компонента."""

    action_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(default="", max_length=1000)


class ControlActionResponse(BaseModel):
    """Підтвердження виконання команди захисним шлюзом."""

    action_id: str = Field(alias="actionId")
    action: str
    applied: bool
    target: str
    state: dict[str, Any]