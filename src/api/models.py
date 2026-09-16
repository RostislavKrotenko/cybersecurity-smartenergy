"""Pydantic-моделі відповідей REST API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Incident(BaseModel):
    """Модель одного інциденту."""

    incident_id: str = Field(..., description="Унікальний ідентифікатор інциденту")
    policy: str = Field(..., description="Політика безпеки (minimal/baseline/standard)")
    category: str = Field(..., description="Категорія інциденту")
    severity: str = Field(..., description="Рівень критичності (low/medium/high/critical)")
    component: str = Field(..., description="Уражений компонент")
    source: str | None = Field(None, description="Джерело або serviceId інциденту")
    start_ts: str | None = Field(None, description="Час початку інциденту (UTC)")
    detect_ts: str | None = Field(None, description="Час виявлення інциденту (UTC)")
    recover_ts: str | None = Field(None, description="Час відновлення після інциденту (UTC)")
    mttd_sec: float | None = Field(None, description="Середній час до виявлення, секунди")
    mttr_sec: float | None = Field(None, description="Середній час до відновлення, секунди")
    status: str = Field("active", description="Статус інциденту")
    details: dict[str, Any] = Field(default_factory=dict)


class IncidentListResponse(BaseModel):
    """Відповідь ендпоінта зі списком інцидентів."""

    total: int
    items: list[Incident]


class Action(BaseModel):
    """Модель однієї дії реагування."""

    action_id: str = Field(..., description="Унікальний ідентифікатор дії")
    action: str = Field(..., description="Тип дії (block_actor, isolate_component тощо)")
    target_component: str = Field(..., description="Цільовий компонент")
    target_id: str | None = Field(None, description="Ідентифікатор цілі (актор/IP)")
    ts_utc: str | None = Field(None, description="Часова мітка (UTC)")
    reason: str | None = Field(None, description="Причина виконання дії")
    correlation_id: str | None = Field(None, description="Пов'язаний ідентифікатор інциденту")
    status: str = Field("emitted", description="Статус дії (emitted/applied/failed)")


class ActionSummary(BaseModel):
    """Зведена статистика за діями реагування."""

    total: int = 0
    applied: int = 0
    failed: int = 0
    emitted: int = 0
    pending: int = 0


class ActionListResponse(BaseModel):
    """Відповідь ендпоінта зі списком дій."""

    total: int
    summary: ActionSummary
    items: list[Action]


class ComponentState(BaseModel):
    """Стан окремого компонента інфраструктури."""

    component_id: str = Field(..., description="Ідентифікатор компонента")
    component_type: str = Field("", description="Тип компонента")
    status: str = Field("healthy", description="Статус (healthy/degraded/isolated/down)")
    details: dict[str, Any] = Field(default_factory=dict)
    last_updated: str | None = Field(None, description="Час останнього оновлення")


class StateResponse(BaseModel):
    """Відповідь ендпоінта стану інфраструктури."""

    components: list[ComponentState]


class ActorCheckResponse(BaseModel):
    """Відповідь перевірки блокування актора."""

    actor: str
    blocked: bool


class ComponentCheckResponse(BaseModel):
    """Відповідь перевірки ізоляції компонента."""

    component_id: str
    isolated: bool


class PolicyMetrics(BaseModel):
    """Метрики для однієї політики безпеки."""

    policy: str = Field(..., description="Назва політики")
    availability_pct: float = Field(..., description="Доступність у відсотках")
    total_downtime_hr: float = Field(0.0, description="Загальний простій у годинах")
    mean_mttd_min: float = Field(0.0, description="Середній час до виявлення, хвилини")
    mean_mttr_min: float = Field(0.0, description="Середній час до відновлення, хвилини")
    incident_count: int = Field(0, description="Кількість інцидентів")


class OverallMetrics(BaseModel):
    """Загальні метрики системи."""

    total_incidents: int = 0
    total_actions: int = 0
    avg_availability_pct: float = 0.0
    avg_mttd_min: float = 0.0
    avg_mttr_min: float = 0.0


class MetricsResponse(BaseModel):
    """Відповідь ендпоінта метрик."""

    by_policy: list[PolicyMetrics]
    overall: OverallMetrics


class HealthResponse(BaseModel):
    """Відповідь сервісу перевірки здоров'я API."""

    status: str = "ok"
    version: str = "1.0.0"
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class CybersecuritySnapshotResponse(BaseModel):
    """Агрегований snapshot для UI модуля кіберзахисту."""

    model_config = ConfigDict(populate_by_name=True)

    generated_at: str = Field(..., alias="generatedAt", description="Час формування snapshot")
    backend: dict[str, Any] = Field(..., description="Стан backend-сервісу кіберзахисту")
    api: dict[str, Any] = Field(..., description="Стан API та backend-інтеграції")
    read_only: dict[str, Any] = Field(..., alias="readOnly", description="Read-only стан компонентів")
    network: dict[str, Any] = Field(..., description="Read-only доступність мережевих endpoint")
    metrics: dict[str, Any] = Field(..., description="Метрики кіберстійкості")
    telemetry: dict[str, Any] = Field(..., description="Остання MQTT-телеметрія")
    incidents: dict[str, Any] = Field(..., description="Активні інциденти")
    actions: dict[str, Any] = Field(..., description="Dispatcher дій реагування")
