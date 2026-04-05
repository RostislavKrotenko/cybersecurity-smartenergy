"""Провайдер даних для REST API.

Модуль інкапсулює доступ до файлів результатів і надає уніфікований
інтерфейс для API-роутів.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.adapters import (
    FileActionSource,
    FileIncidentSource,
    FileMetricsSource,
    FileStateSource,
)
from src.contracts.interfaces import (
    ActionSource,
    ComponentState,
    IncidentSource,
    MetricsSource,
    StateProvider,
)

# Шляхи відносно кореня репозиторію
ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_PATH = ROOT / "out" / "results.csv"
INCIDENTS_PATH = ROOT / "out" / "incidents.csv"
ACTIONS_PATH = ROOT / "out" / "actions.csv"
STATE_PATH = ROOT / "out" / "state.csv"
EVENTS_PATH = ROOT / "data" / "events.csv"


class APIDataProvider:
    """Постачає дані для REST-ендпоінтів API."""

    def __init__(
        self,
        incident_source: IncidentSource | None = None,
        action_source: ActionSource | None = None,
        metrics_source: MetricsSource | None = None,
        state_provider: StateProvider | None = None,
    ):
        self.incident_source = incident_source or FileIncidentSource(str(INCIDENTS_PATH))
        self.action_source = action_source or FileActionSource(str(ACTIONS_PATH))
        self.metrics_source = metrics_source or FileMetricsSource(str(RESULTS_PATH))
        self.state_provider = state_provider or FileStateSource(str(STATE_PATH))

    def get_incidents(self, limit: int = 10000) -> list[dict[str, Any]]:
        """Повертає інциденти у форматі списку словників."""
        return self.incident_source.get_incidents(limit)

    def get_incident_count(self) -> int:
        """Повертає загальну кількість інцидентів."""
        return self.incident_source.get_incident_count()

    def get_actions(self, limit: int = 10000) -> list[dict[str, Any]]:
        """Повертає дії у форматі списку словників."""
        return self.action_source.get_actions(limit)

    def get_action_summary(self) -> dict[str, int]:
        """Повертає агреговану статистику дій."""
        return self.action_source.get_action_summary()

    def get_metrics(self) -> list[dict[str, Any]]:
        """Повертає метрики, згруповані за політиками."""
        return self.metrics_source.get_metrics_by_policy()

    def get_overall_metrics(self) -> dict[str, float]:
        """Повертає загальні агреговані метрики системи."""
        return self.metrics_source.get_overall_metrics()

    def get_state(self) -> list[ComponentState]:
        """Повертає стан усіх компонентів інфраструктури."""
        return self.state_provider.get_all_components()

    def get_component_state(self, component_id: str) -> ComponentState | None:
        """Повертає стан конкретного компонента за його ідентифікатором."""
        return self.state_provider.get_component_state(component_id)

    def is_actor_blocked(self, actor: str) -> bool:
        """Перевіряє, чи заблокований вказаний актор."""
        return self.state_provider.is_actor_blocked(actor)

    def is_component_isolated(self, component_id: str) -> bool:
        """Перевіряє, чи ізольований вказаний компонент."""
        return self.state_provider.is_component_isolated(component_id)


_provider: APIDataProvider | None = None


def get_provider() -> APIDataProvider:
    """Повертає єдиний екземпляр APIDataProvider у процесі."""
    global _provider
    if _provider is None:
        _provider = APIDataProvider()
    return _provider
