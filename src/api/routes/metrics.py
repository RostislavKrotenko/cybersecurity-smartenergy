"""Роути API для метрик кіберстійкості."""

from __future__ import annotations

from fastapi import APIRouter

from src.api.data_provider import get_provider
from src.api.models import MetricsResponse, OverallMetrics, PolicyMetrics

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("", response_model=MetricsResponse)
def get_metrics() -> MetricsResponse:
    """Повертає метрики за політиками та загальні метрики системи."""
    provider = get_provider()

    raw_metrics = provider.get_metrics()
    by_policy = []
    for m in raw_metrics:
        by_policy.append(PolicyMetrics(
            policy=m.get("policy", ""),
            availability_pct=m.get("availability_pct", 0.0),
            total_downtime_hr=m.get("total_downtime_hr", 0.0),
            mean_mttd_min=m.get("mean_mttd_min", 0.0),
            mean_mttr_min=m.get("mean_mttr_min", 0.0),
            incident_count=m.get("incident_count", 0),
        ))

    raw_overall = provider.get_overall_metrics()
    overall = OverallMetrics(
        total_incidents=int(raw_overall.get("total_incidents", 0)),
        total_actions=int(raw_overall.get("total_actions", 0)),
        avg_availability_pct=raw_overall.get("avg_availability_pct", 0.0),
        avg_mttd_min=raw_overall.get("avg_mttd_min", 0.0),
        avg_mttr_min=raw_overall.get("avg_mttr_min", 0.0),
    )

    return MetricsResponse(by_policy=by_policy, overall=overall)


@router.get("/by-policy", response_model=list[PolicyMetrics])
def get_metrics_by_policy() -> list[PolicyMetrics]:
    """Повертає метрики, згруповані за політиками."""
    provider = get_provider()
    raw_metrics = provider.get_metrics()

    result = []
    for m in raw_metrics:
        result.append(PolicyMetrics(
            policy=m.get("policy", ""),
            availability_pct=m.get("availability_pct", 0.0),
            total_downtime_hr=m.get("total_downtime_hr", 0.0),
            mean_mttd_min=m.get("mean_mttd_min", 0.0),
            mean_mttr_min=m.get("mean_mttr_min", 0.0),
            incident_count=m.get("incident_count", 0),
        ))

    return result


@router.get("/overall", response_model=OverallMetrics)
def get_overall_metrics() -> OverallMetrics:
    """Повертає агреговані загальні метрики системи."""
    provider = get_provider()
    raw_overall = provider.get_overall_metrics()

    return OverallMetrics(
        total_incidents=int(raw_overall.get("total_incidents", 0)),
        total_actions=int(raw_overall.get("total_actions", 0)),
        avg_availability_pct=raw_overall.get("avg_availability_pct", 0.0),
        avg_mttd_min=raw_overall.get("avg_mttd_min", 0.0),
        avg_mttr_min=raw_overall.get("avg_mttr_min", 0.0),
    )
