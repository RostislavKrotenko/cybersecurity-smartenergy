"""Роути API для отримання стану інфраструктури."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Path

from src.api.data_provider import get_provider
from src.api.models import (
    ActorCheckResponse,
    ComponentCheckResponse,
    ComponentState,
    StateResponse,
)

router = APIRouter(prefix="/state", tags=["state"])


@router.get("", response_model=StateResponse)
def get_state() -> StateResponse:
    """Повертає стан усіх компонентів інфраструктури."""
    provider = get_provider()
    raw_states = provider.get_state()

    components = []
    for state in raw_states:
        details = state.details if isinstance(state.details, dict) else {}
        components.append(ComponentState(
            component_id=state.component_id,
            component_type=state.component_type,
            status=state.status,
            details=details,
            last_updated=state.last_updated if state.last_updated else None,
        ))

    return StateResponse(components=components)


@router.get("/components/{component_id}", response_model=ComponentState)
def get_component_state(
    component_id: str = Path(..., description="Component identifier"),
) -> ComponentState:
    """Повертає стан конкретного компонента."""
    provider = get_provider()
    state = provider.get_component_state(component_id)

    if state is None:
        raise HTTPException(status_code=404, detail=f"Component '{component_id}' not found")

    details = state.details if isinstance(state.details, dict) else {}
    return ComponentState(
        component_id=state.component_id,
        component_type=state.component_type,
        status=state.status,
        details=details,
        last_updated=state.last_updated if state.last_updated else None,
    )


@router.get("/actors/{actor}/blocked", response_model=ActorCheckResponse)
def check_actor_blocked(
    actor: str = Path(..., description="Actor identifier (IP or username)"),
) -> ActorCheckResponse:
    """Перевіряє, чи актор наразі заблокований."""
    provider = get_provider()
    blocked = provider.is_actor_blocked(actor)
    return ActorCheckResponse(actor=actor, blocked=blocked)


@router.get("/components/{component_id}/isolated", response_model=ComponentCheckResponse)
def check_component_isolated(
    component_id: str = Path(..., description="Component identifier"),
) -> ComponentCheckResponse:
    """Перевіряє, чи компонент наразі ізольований."""
    provider = get_provider()
    isolated = provider.is_component_isolated(component_id)
    return ComponentCheckResponse(component_id=component_id, isolated=isolated)
