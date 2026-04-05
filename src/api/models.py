"""Pydantic-моделі відповідей REST API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class Incident(BaseModel):
    """Модель одного інциденту."""

    incident_id: str = Field(..., description="Unique incident identifier")
    policy: str = Field(..., description="Security policy (minimal/baseline/standard)")
    category: str = Field(..., description="Incident category")
    severity: str = Field(..., description="Severity level (low/medium/high/critical)")
    component: str = Field(..., description="Affected component")
    start_ts: str | None = Field(None, description="Incident start timestamp (UTC)")
    detect_ts: str | None = Field(None, description="Detection timestamp (UTC)")
    recover_ts: str | None = Field(None, description="Recovery timestamp (UTC)")
    mttd_sec: float | None = Field(None, description="Mean time to detect (seconds)")
    mttr_sec: float | None = Field(None, description="Mean time to recover (seconds)")
    status: str = Field("active", description="Incident status")
    details: dict[str, Any] = Field(default_factory=dict)


class IncidentListResponse(BaseModel):
    """Відповідь ендпоінта зі списком інцидентів."""

    total: int
    items: list[Incident]


class Action(BaseModel):
    """Модель однієї дії реагування."""

    action_id: str = Field(..., description="Unique action identifier")
    action: str = Field(..., description="Action type (block_actor, isolate_component, etc)")
    target_component: str = Field(..., description="Target component")
    target_id: str | None = Field(None, description="Target identifier (actor/IP)")
    ts_utc: str | None = Field(None, description="Timestamp (UTC)")
    reason: str | None = Field(None, description="Reason for action")
    correlation_id: str | None = Field(None, description="Related incident ID")
    status: str = Field("emitted", description="Action status (emitted/applied/failed)")


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

    component_id: str = Field(..., description="Component identifier")
    component_type: str = Field("", description="Component type")
    status: str = Field("healthy", description="Status (healthy/degraded/isolated/down)")
    details: dict[str, Any] = Field(default_factory=dict)
    last_updated: str | None = Field(None, description="Last update timestamp")


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

    policy: str = Field(..., description="Policy name")
    availability_pct: float = Field(..., description="Availability percentage")
    total_downtime_hr: float = Field(0.0, description="Total downtime in hours")
    mean_mttd_min: float = Field(0.0, description="Mean time to detect (minutes)")
    mean_mttr_min: float = Field(0.0, description="Mean time to recover (minutes)")
    incident_count: int = Field(0, description="Number of incidents")


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
