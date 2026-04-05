"""Abstract interfaces for plug-and-play integration with real SmartEnergy systems.

These interfaces decouple the analyzer/responder from specific data sources and
action executors. To integrate with a real SmartEnergy system:

1. Implement EventSource for your data source (Kafka, SIEM, Modbus, etc.)
2. Implement ActionSink for your response system (SOAR, SCADA API, etc.)
3. Pass your implementations to the pipeline functions

The file-based implementations (FileEventSource, FileActionSink) serve as
reference implementations and are used for simulation/testing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.contracts.action import Action, ActionAck
from src.contracts.event import Event

# ═══════════════════════════════════════════════════════════════════════════
#  EventSource - abstraction for event input
# ═══════════════════════════════════════════════════════════════════════════


class EventSource(ABC):
    """Abstract source of security events.

    Implement this interface to connect the analyzer to different data sources:
    - FileEventSource: CSV/JSONL files (simulation)
    - KafkaEventSource: Apache Kafka topics
    - SiemEventSource: Splunk/Elastic/QRadar APIs
    - ModbusEventSource: Direct Modbus device polling
    - MqttEventSource: MQTT broker subscription
    """

    @abstractmethod
    def read_batch(self, limit: int = 10000) -> list[Event]:
        """Read a batch of events from the source.

        Args:
            limit: Maximum number of events to read.

        Returns:
            List of Event objects.
        """
        pass

    @abstractmethod
    def read_stream(self, poll_interval_sec: float = 1.0) -> Iterator[list[Event]]:
        """Stream events in batches (for watch mode).

        Yields batches of new events as they become available.

        Args:
            poll_interval_sec: How often to check for new events.

        Yields:
            Batches of Event objects.
        """
        pass

    @abstractmethod
    def get_offset(self) -> Any:
        """Get current read position for resumption."""
        pass

    @abstractmethod
    def seek(self, offset: Any) -> None:
        """Seek to a specific position in the source."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Release any resources held by the source."""
        pass


# ═══════════════════════════════════════════════════════════════════════════
#  EventSink - abstraction for event output
# ═══════════════════════════════════════════════════════════════════════════


class EventSink(ABC):
    """Abstract sink for outputting events.

    Implement this interface to send events to different destinations:
    - FileEventSink: JSONL/CSV files (simulation)
    - KafkaEventSink: Apache Kafka topics
    - SiemEventSink: Forward to SIEM (Splunk, Elastic)
    - MqttEventSink: Publish to MQTT broker

    Used by:
    - Emulator: to output generated events
    - Normalizer: to output normalized events
    """

    @abstractmethod
    def emit(self, event: Event) -> None:
        """Emit a single event.

        Args:
            event: The event to emit.
        """
        pass

    @abstractmethod
    def emit_batch(self, events: list[Event]) -> None:
        """Emit multiple events.

        Args:
            events: List of events to emit.
        """
        pass

    @abstractmethod
    def flush(self) -> None:
        """Flush any buffered events to the destination."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Release any resources held by the sink."""
        pass


# ═══════════════════════════════════════════════════════════════════════════
#  ActionSink - abstraction for action output
# ═══════════════════════════════════════════════════════════════════════════


class ActionStatus(str, Enum):
    """Status of an emitted action."""
    PENDING = "pending"
    EMITTED = "emitted"
    APPLIED = "applied"
    FAILED = "failed"


@dataclass
class ActionResult:
    """Result of action execution."""
    success: bool
    action_id: str
    status: ActionStatus
    state_events: list[Event] = field(default_factory=list)
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ActionSink(ABC):
    """Abstract sink for response actions.

    Implement this interface to send actions to different execution backends:
    - FileActionSink: JSONL file (for emulator consumption)
    - SoarActionSink: SOAR platform API (Phantom, XSOAR, etc.)
    - ScadaActionSink: Direct SCADA/PLC commands
    - RestActionSink: Generic REST API calls
    """

    @abstractmethod
    def emit(self, action: Action) -> str:
        """Emit a single action.

        Args:
            action: The action to emit.

        Returns:
            Tracking ID for the action.
        """
        pass

    @abstractmethod
    def emit_batch(self, actions: list[Action]) -> list[str]:
        """Emit multiple actions.

        Args:
            actions: List of actions to emit.

        Returns:
            List of tracking IDs.
        """
        pass

    @abstractmethod
    def get_status(self, action_id: str) -> ActionStatus:
        """Get the status of a previously emitted action.

        Args:
            action_id: The action ID to check.

        Returns:
            Current status of the action.
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Release any resources held by the sink."""
        pass


# ═══════════════════════════════════════════════════════════════════════════
#  ActionFeedback - abstraction for action acknowledgements
# ═══════════════════════════════════════════════════════════════════════════


class ActionFeedback(ABC):
    """Abstract source of action acknowledgements.

    Implement this to receive feedback when actions are executed:
    - FileActionFeedback: Read from actions_applied.jsonl
    - WebhookActionFeedback: Receive HTTP callbacks
    - QueueActionFeedback: Subscribe to response queue
    """

    @abstractmethod
    def read_acks(self, since: Any = None) -> tuple[list[ActionAck], Any]:
        """Read new action acknowledgements.

        Args:
            since: Offset/cursor from previous read.

        Returns:
            Tuple of (list of ActionAck, new offset).
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Release any resources."""
        pass


# ═══════════════════════════════════════════════════════════════════════════
#  ActionExecutor - abstraction for direct action execution
# ═══════════════════════════════════════════════════════════════════════════


class ActionExecutor(ABC):
    """Abstract executor for direct action execution on infrastructure.

    This is used when the analyzer directly controls infrastructure,
    rather than emitting actions for a separate executor.

    Implement this for:
    - SimulatedExecutor: Update WorldState (current emulator)
    - FirewallExecutor: Configure firewall rules via API
    - ScadaExecutor: Send SCADA commands
    - CloudExecutor: AWS/GCP/Azure infrastructure actions
    """

    @abstractmethod
    def execute(self, action: Action) -> ActionResult:
        """Execute an action on the target infrastructure.

        Args:
            action: The action to execute.

        Returns:
            ActionResult with success/failure and any state events.
        """
        pass

    @abstractmethod
    def supports_action(self, action_type: str) -> bool:
        """Check if this executor supports a given action type.

        Args:
            action_type: The action type string.

        Returns:
            True if this executor can handle the action.
        """
        pass

    @abstractmethod
    def get_component_status(self, component_id: str) -> dict[str, Any]:
        """Get current status of a component.

        Args:
            component_id: The component identifier.

        Returns:
            Dict with component status information.
        """
        pass


# ═══════════════════════════════════════════════════════════════════════════
#  StateProvider - abstraction for infrastructure state
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class ComponentState:
    """State of a single component."""
    component_id: str
    component_type: str
    status: str  # healthy, degraded, isolated, down
    details: dict[str, Any] = field(default_factory=dict)
    last_updated: str = ""


class StateProvider(ABC):
    """Abstract provider for infrastructure state.

    Implement this to query real infrastructure state:
    - SimulatedStateProvider: From WorldState (current)
    - ScadaStateProvider: Query SCADA/RTU status
    - MonitoringStateProvider: From Prometheus/Grafana
    """

    @abstractmethod
    def get_component_state(self, component_id: str) -> ComponentState | None:
        """Get state of a specific component.

        Args:
            component_id: The component identifier.

        Returns:
            ComponentState or None if not found.
        """
        pass

    @abstractmethod
    def get_all_components(self) -> list[ComponentState]:
        """Get state of all known components.

        Returns:
            List of ComponentState objects.
        """
        pass

    @abstractmethod
    def is_actor_blocked(self, actor: str) -> bool:
        """Check if an actor is currently blocked.

        Args:
            actor: The actor identifier.

        Returns:
            True if the actor is blocked.
        """
        pass

    @abstractmethod
    def is_component_isolated(self, component_id: str) -> bool:
        """Check if a component is currently isolated.

        Args:
            component_id: The component identifier.

        Returns:
            True if the component is isolated.
        """
        pass


# ═══════════════════════════════════════════════════════════════════════════
#  Dashboard Data Sources - abstractions for dashboard data
# ═══════════════════════════════════════════════════════════════════════════


class IncidentSource(ABC):
    """Abstract source for incident data.

    Implement this to fetch incidents from different backends:
    - FileIncidentSource: Read from incidents.csv
    - SiemIncidentSource: Query SIEM API
    - DatabaseIncidentSource: Query incident database
    """

    @abstractmethod
    def get_incidents(self, limit: int = 10000) -> list[dict[str, Any]]:
        """Get list of incidents.

        Args:
            limit: Maximum number of incidents to return.

        Returns:
            List of incident dictionaries.
        """
        pass

    @abstractmethod
    def get_incident_count(self) -> int:
        """Get total number of incidents."""
        pass


class ActionSource(ABC):
    """Abstract source for action data.

    Implement this to fetch actions from different backends:
    - FileActionSource: Read from actions.csv
    - SoarActionSource: Query SOAR platform
    - DatabaseActionSource: Query action database
    """

    @abstractmethod
    def get_actions(self, limit: int = 10000) -> list[dict[str, Any]]:
        """Get list of actions.

        Args:
            limit: Maximum number of actions to return.

        Returns:
            List of action dictionaries.
        """
        pass

    @abstractmethod
    def get_action_summary(self) -> dict[str, int]:
        """Get summary of actions by status.

        Returns:
            Dict with keys: total, applied, failed, pending/emitted.
        """
        pass


class MetricsSource(ABC):
    """Abstract source for resilience metrics.

    Implement this to fetch metrics from different backends:
    - FileMetricsSource: Read from results.csv
    - PrometheusMetricsSource: Query Prometheus
    - DatabaseMetricsSource: Query metrics database
    """

    @abstractmethod
    def get_metrics_by_policy(self) -> list[dict[str, Any]]:
        """Get metrics grouped by security policy.

        Returns:
            List of dicts with policy, availability, mttd, mttr, etc.
        """
        pass

    @abstractmethod
    def get_overall_metrics(self) -> dict[str, float]:
        """Get overall system metrics.

        Returns:
            Dict with aggregated metrics.
        """
        pass
