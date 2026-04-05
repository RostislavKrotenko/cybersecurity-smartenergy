"""Контракти даних для всіх модулів системи."""

from src.contracts.action import Action, ActionAck, ActionType
from src.contracts.alert import Alert
from src.contracts.enums import Component, EventType, Severity
from src.contracts.event import Event
from src.contracts.incident import Incident
from src.contracts.integration_contract_v1 import (
    INTEGRATION_CONTRACT_VERSION,
    validate_action_ack_v1,
    validate_action_v1,
    validate_event_v1,
)
from src.contracts.interfaces import (
    ActionExecutor,
    ActionFeedback,
    ActionResult,
    ActionSink,
    ActionSource,
    ActionStatus,
    ComponentState,
    EventSink,
    EventSource,
    IncidentSource,
    MetricsSource,
    StateProvider,
)

__all__ = [
    "INTEGRATION_CONTRACT_VERSION",
    "Action",
    "ActionAck",
    "ActionExecutor",
    "ActionFeedback",
    "ActionResult",
    "ActionSink",
    "ActionSource",
    "ActionStatus",
    "ActionType",
    "Alert",
    "Component",
    "ComponentState",
    "Event",
    "EventSink",
    "EventSource",
    "EventType",
    "Incident",
    "IncidentSource",
    "MetricsSource",
    "Severity",
    "StateProvider",
    "validate_action_ack_v1",
    "validate_action_v1",
    "validate_event_v1",
]
