"""Роути API для роботи з інцидентами."""

from __future__ import annotations

from fastapi import APIRouter, Query

from src.api.data_provider import get_provider
from src.api.models import Incident, IncidentListResponse

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=IncidentListResponse)
def get_incidents(
    limit: int = Query(1000, ge=1, le=10000, description="Max incidents to return"),
    severity: str | None = Query(None, description="Filter by severity"),
    component: str | None = Query(None, description="Filter by component"),
    policy: str | None = Query(None, description="Filter by policy"),
) -> IncidentListResponse:
    """Повертає список інцидентів з опційними фільтрами."""
    provider = get_provider()
    raw_incidents = provider.get_incidents(limit)

    if severity:
        raw_incidents = [i for i in raw_incidents if i.get("severity") == severity]
    if component:
        raw_incidents = [i for i in raw_incidents if i.get("component") == component]
    if policy:
        raw_incidents = [i for i in raw_incidents if i.get("policy") == policy]

    items = []
    for inc in raw_incidents:
        items.append(Incident(
            incident_id=inc.get("incident_id", ""),
            policy=inc.get("policy", ""),
            category=inc.get("category", ""),
            severity=inc.get("severity", ""),
            component=inc.get("component", ""),
            start_ts=str(inc.get("start_ts", "")) if inc.get("start_ts") else None,
            detect_ts=str(inc.get("detect_ts", "")) if inc.get("detect_ts") else None,
            recover_ts=str(inc.get("recover_ts", "")) if inc.get("recover_ts") else None,
            mttd_sec=inc.get("mttd_sec"),
            mttr_sec=inc.get("mttr_sec"),
            status=inc.get("status", "active"),
            details=inc.get("details", {}),
        ))

    return IncidentListResponse(total=len(items), items=items)


@router.get("/count")
def get_incident_count() -> dict[str, int]:
    """Повертає загальну кількість інцидентів."""
    provider = get_provider()
    return {"count": provider.get_incident_count()}
