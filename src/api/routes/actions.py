"""Роути API для роботи з діями реагування."""

from __future__ import annotations

from fastapi import APIRouter, Query

from src.api.data_provider import get_provider
from src.api.models import Action, ActionListResponse, ActionSummary

router = APIRouter(prefix="/actions", tags=["actions"])


@router.get("", response_model=ActionListResponse)
def get_actions(
    limit: int = Query(1000, ge=1, le=10000, description="Max actions to return"),
    status: str | None = Query(None, description="Filter by status (emitted/applied/failed)"),
    action_type: str | None = Query(None, description="Filter by action type"),
    component: str | None = Query(None, description="Filter by target component"),
) -> ActionListResponse:
    """Повертає список дій з опційними фільтрами."""
    provider = get_provider()
    raw_actions = provider.get_actions(limit)

    if status:
        raw_actions = [a for a in raw_actions if a.get("status") == status]
    if action_type:
        raw_actions = [a for a in raw_actions if a.get("action") == action_type]
    if component:
        raw_actions = [a for a in raw_actions if a.get("target_component") == component]

    summary_raw = provider.get_action_summary()
    summary = ActionSummary(
        total=summary_raw.get("total", 0),
        applied=summary_raw.get("applied", 0),
        failed=summary_raw.get("failed", 0),
        emitted=summary_raw.get("emitted", 0),
        pending=summary_raw.get("pending", 0),
    )

    items = []
    for act in raw_actions:
        items.append(Action(
            action_id=act.get("action_id", ""),
            action=act.get("action", ""),
            target_component=act.get("target_component", ""),
            target_id=act.get("target_id"),
            ts_utc=str(act.get("ts_utc", "")) if act.get("ts_utc") else None,
            reason=act.get("reason"),
            correlation_id=act.get("correlation_id"),
            status=act.get("status", "emitted"),
        ))

    return ActionListResponse(total=len(items), summary=summary, items=items)


@router.get("/summary", response_model=ActionSummary)
def get_action_summary() -> ActionSummary:
    """Повертає підсумкову статистику виконання дій."""
    provider = get_provider()
    summary_raw = provider.get_action_summary()
    return ActionSummary(
        total=summary_raw.get("total", 0),
        applied=summary_raw.get("applied", 0),
        failed=summary_raw.get("failed", 0),
        emitted=summary_raw.get("emitted", 0),
        pending=summary_raw.get("pending", 0),
    )
