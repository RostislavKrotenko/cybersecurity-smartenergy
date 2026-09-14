"""Моделі керувальних дій та підтверджень їх виконання."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    """Повертає поточний час у часовому поясі UTC."""

    return datetime.now(timezone.utc)


class ActionType(str, Enum):
    """Перелік дій, які система кіберзахисту може виконати через Gateway."""

    BLOCK_SOURCE = "block_source"
    UNBLOCK_SOURCE = "unblock_source"
    ISOLATE_SERVICE = "isolate_service"
    RESTORE_SERVICE = "restore_service"
    SET_RATE_LIMIT = "set_rate_limit"


class ActionStatus(str, Enum):
    """Стан виконання керувальної дії."""

    APPLIED = "applied"
    REJECTED = "rejected"
    FAILED = "failed"
    IN_PROGRESS = "in_progress"


class SecurityAction(BaseModel):
    """Команда, сформована аналізатором системи кіберзахисту."""

    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
        use_enum_values=False,
    )

    action_id: str = Field(
        alias="actionId",
        min_length=1,
        max_length=128,
    )
    action_type: ActionType = Field(alias="actionType")
    target: str = Field(min_length=1, max_length=512)
    service_id: str = Field(
        default="iot-gateway",
        alias="serviceId",
        min_length=1,
        max_length=128,
    )
    reason: str = Field(min_length=1, max_length=1000)
    ttl_seconds: float | None = Field(
        default=None,
        alias="ttlSeconds",
        gt=0,
    )
    parameters: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(
        default_factory=utc_now,
        alias="createdAt",
    )

    @field_validator("action_id", "target", "service_id", "reason")
    @classmethod
    def strip_text(cls, value: str) -> str:
        """Видаляє зайві пробіли та забороняє порожні текстові значення."""

        normalized = value.strip()
        if not normalized:
            raise ValueError("Значення не може бути порожнім")
        return normalized


class ActionAck(BaseModel):
    """Підтвердження виконання або відхилення керувальної дії."""

    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
        use_enum_values=False,
    )

    action_id: str = Field(alias="actionId")
    action_type: ActionType = Field(alias="actionType")
    status: ActionStatus
    target: str
    service_id: str = Field(alias="serviceId")
    message: str
    retryable: bool = False
    duplicate: bool = False
    http_status: int | None = Field(default=None, alias="httpStatus")
    gateway_response: dict[str, Any] | None = Field(
        default=None,
        alias="gatewayResponse",
    )
    completed_at: datetime = Field(
        default_factory=utc_now,
        alias="completedAt",
    )

    @classmethod
    def in_progress(cls, action: SecurityAction) -> "ActionAck":
        """Створює підтвердження для команди, яка вже виконується."""

        return cls(
            actionId=action.action_id,
            actionType=action.action_type,
            status=[ActionStatus.IN](http://ActionStatus.IN)_PROGRESS,
            target=action.target,
            serviceId=action.service_id,
            message="Команда з таким actionId уже виконується",
            retryable=True,
            duplicate=True,
        )

    def as_duplicate(self) -> "ActionAck":
        """Позначає збережене підтвердження як результат повторної команди."""

        return self.model_copy(
            update={
                "duplicate": True,
                "message": (
                    f"Повторна команда не виконувалася. "
                    f"Попередній результат: {self.message}"
                ),
            }
        )