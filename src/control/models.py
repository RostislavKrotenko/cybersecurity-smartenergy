"""Моделі керувальних дій та підтверджень їх виконання."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.alias_generators import to_camel


def utc_now() -> datetime:
    """Повертає поточний час у часовому поясі UTC."""

    return datetime.now(timezone.utc)


class ControlModel(BaseModel):
    """Базова модель керувального API з підтримкою camelCase JSON."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        use_enum_values=False,
    )


class ActionType(str, Enum):
    """Перелік дій, які система може виконати через Gateway."""

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


class SecurityAction(ControlModel):
    """Команда, сформована аналізатором системи кіберзахисту."""

    action_id: str = Field(
        min_length=1,
        max_length=128,
    )
    action_type: ActionType
    target: str = Field(
        min_length=1,
        max_length=512,
    )
    service_id: str = Field(
        default="iot-gateway",
        min_length=1,
        max_length=128,
    )
    reason: str = Field(
        min_length=1,
        max_length=1000,
    )
    ttl_seconds: float | None = Field(
        default=None,
        gt=0,
    )
    parameters: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator(
        "action_id",
        "target",
        "service_id",
        "reason",
    )
    @classmethod
    def strip_text(cls, value: str) -> str:
        """Видаляє зайві пробіли з текстових значень."""

        normalized = value.strip()

        if not normalized:
            raise ValueError("Значення не може бути порожнім")

        return normalized


class ActionAck(ControlModel):
    """Підтвердження виконання або відхилення керувальної дії."""

    action_id: str
    action_type: ActionType
    status: ActionStatus
    target: str
    service_id: str
    message: str
    retryable: bool = False
    duplicate: bool = False
    http_status: int | None = None
    gateway_response: dict[str, Any] | None = None
    completed_at: datetime = Field(default_factory=utc_now)

    @classmethod
    def in_progress(
        cls,
        action: SecurityAction,
    ) -> "ActionAck":
        """Створює підтвердження для команди, яка вже виконується."""

        return cls(
            action_id=action.action_id,
            action_type=action.action_type,
            status=ActionStatus.IN_PROGRESS,
            target=action.target,
            service_id=action.service_id,
            message="Команда з таким actionId уже виконується",
            retryable=True,
            duplicate=True,
        )

    def as_duplicate(self) -> "ActionAck":
        """Позначає збережене підтвердження як повторний результат."""

        return self.model_copy(
            update={
                "duplicate": True,
                "message": (
                    "Повторна команда не виконувалася. "
                    f"Попередній результат: {self.message}"
                ),
            }
        )