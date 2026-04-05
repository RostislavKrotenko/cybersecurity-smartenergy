"""File-based adapters for simulation and testing.

These adapters implement the abstract interfaces using local files (CSV/JSONL).
They serve as:
1. Reference implementations for how to implement the interfaces
2. Working adapters for simulation/testing scenarios
3. Fallback when real infrastructure is not available

To integrate with real SmartEnergy systems, create new adapters in this package:
- kafka_adapter.py: KafkaEventSource, KafkaActionSink
- siem_adapter.py: SplunkEventSource, ElasticEventSource
- scada_adapter.py: ScadaActionExecutor, ScadaStateProvider
- soar_adapter.py: XsoarActionSink, PhantomActionSink
"""

from __future__ import annotations

import csv
import json
import logging
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from src.contracts.action import Action, ActionAck
from src.contracts.event import Event
from src.contracts.interfaces import (
    ActionFeedback,
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
from src.shared.file_utils import atomic_write

log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
#  FileEventSource - read events from CSV/JSONL files
# ═══════════════════════════════════════════════════════════════════════════


class FileEventSource(EventSource):
    """Event source that reads from local CSV or JSONL files.

    This is the simulation/testing implementation. For production,
    implement KafkaEventSource, SiemEventSource, etc.
    """

    def __init__(self, path: str):
        """Initialize with file path.

        Args:
            path: Path to CSV or JSONL file.
        """
        self.path = Path(path)
        self._offset: int = 0
        self._is_jsonl = self.path.suffix in (".jsonl", ".ndjson")

    def read_batch(self, limit: int = 10000) -> list[Event]:
        """Read all events from the file (batch mode)."""
        if not self.path.exists():
            log.warning("Event source file not found: %s", self.path)
            return []

        if self._is_jsonl:
            return self._read_jsonl(limit)
        return self._read_csv(limit)

    def _read_csv(self, limit: int) -> list[Event]:
        """Read events from CSV file."""
        events: list[Event] = []
        with open(self.path, encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader):
                if i >= limit:
                    break
                events.append(Event.from_dict(row))
        log.info("FileEventSource: loaded %d events from CSV: %s", len(events), self.path)
        return events

    def _read_jsonl(self, limit: int) -> list[Event]:
        """Read events from JSONL file."""
        events: list[Event] = []
        with open(self.path, encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if i >= limit:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    events.append(Event.from_dict(obj))
                except (json.JSONDecodeError, KeyError) as exc:
                    log.warning("Skipping JSONL line %d: %s", i + 1, exc)
        log.info("FileEventSource: loaded %d events from JSONL: %s", len(events), self.path)
        return events

    def read_stream(self, poll_interval_sec: float = 1.0) -> Iterator[list[Event]]:
        """Stream new events by tailing the file (watch mode)."""
        while True:
            events = self._read_new_lines()
            yield events
            time.sleep(poll_interval_sec)

    def _read_new_lines(self) -> list[Event]:
        """Read lines appended since last read."""
        if not self.path.exists():
            return []

        try:
            current_size = self.path.stat().st_size
        except OSError:
            return []

        if current_size <= self._offset:
            return []

        events: list[Event] = []
        with open(self.path, encoding="utf-8") as fh:
            fh.seek(self._offset)
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    events.append(Event.from_dict(obj))
                except (json.JSONDecodeError, KeyError) as exc:
                    log.debug("Skipping line: %s", exc)
            self._offset = fh.tell()

        return events

    def get_offset(self) -> int:
        """Get current file offset."""
        return self._offset

    def seek(self, offset: Any) -> None:
        """Seek to a specific file offset."""
        if isinstance(offset, int):
            self._offset = offset

    def close(self) -> None:
        """No resources to release for file source."""
        pass


# ═══════════════════════════════════════════════════════════════════════════
#  FileEventSink - write events to JSONL file
# ═══════════════════════════════════════════════════════════════════════════


class FileEventSink(EventSink):
    """Event sink that writes to a local JSONL file.

    Used by Emulator and Normalizer to output events.
    For production, implement KafkaEventSink, SiemEventSink, etc.
    """

    def __init__(self, path: str):
        """Initialize with file path.

        Args:
            path: Path to JSONL file for event output.
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._buffer: list[Event] = []
        self._count = 0

    def emit(self, event: Event) -> None:
        """Emit a single event to the file."""
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(event.to_json() + "\n")
            fh.flush()
        self._count += 1

    def emit_batch(self, events: list[Event]) -> None:
        """Emit multiple events to the file."""
        if not events:
            return

        with open(self.path, "a", encoding="utf-8") as fh:
            for event in events:
                fh.write(event.to_json() + "\n")
            fh.flush()
        self._count += len(events)
        log.info("FileEventSink: emitted %d events -> %s", len(events), self.path)

    def flush(self) -> None:
        """Flush buffered events (no-op for file sink)."""
        pass

    def close(self) -> None:
        """Release resources."""
        log.info("FileEventSink: total %d events written to %s", self._count, self.path)

    @property
    def event_count(self) -> int:
        """Get total number of events emitted."""
        return self._count


# ═══════════════════════════════════════════════════════════════════════════
#  FileActionSink - write actions to JSONL file
# ═══════════════════════════════════════════════════════════════════════════


class FileActionSink(ActionSink):
    """Action sink that writes to a local JSONL file.

    This is the simulation/testing implementation. For production,
    implement SoarActionSink, ScadaActionSink, etc.
    """

    def __init__(self, path: str, csv_path: str | None = None):
        """Initialize with file path.

        Args:
            path: Path to JSONL file for action output.
            csv_path: Optional path for CSV summary output.
        """
        self.path = Path(path)
        self.csv_path = Path(csv_path) if csv_path else None
        self._actions: dict[str, Action] = {}
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, action: Action) -> str:
        """Emit a single action to the file."""
        action.status = "emitted"
        self._actions[action.action_id] = action

        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(action.to_json() + "\n")
            fh.flush()

        log.info("FileActionSink: emitted %s -> %s", action.action_id, self.path)
        return action.action_id

    def emit_batch(self, actions: list[Action]) -> list[str]:
        """Emit multiple actions to the file."""
        if not actions:
            return []

        ids: list[str] = []
        with open(self.path, "a", encoding="utf-8") as fh:
            for action in actions:
                action.status = "emitted"
                self._actions[action.action_id] = action
                fh.write(action.to_json() + "\n")
                ids.append(action.action_id)
            fh.flush()

        log.info("FileActionSink: emitted %d actions -> %s", len(actions), self.path)
        return ids

    def get_status(self, action_id: str) -> ActionStatus:
        """Get status of a previously emitted action."""
        action = self._actions.get(action_id)
        if action is None:
            return ActionStatus.PENDING
        return ActionStatus(action.status)

    def update_status(self, action_id: str, status: ActionStatus) -> None:
        """Update status of an action (called by feedback reader)."""
        action = self._actions.get(action_id)
        if action:
            action.status = status.value

    def get_all_actions(self) -> list[Action]:
        """Get all tracked actions."""
        return list(self._actions.values())

    def write_csv_summary(self) -> None:
        """Write CSV summary of all actions."""
        if not self.csv_path:
            return

        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [Action.csv_header()]
        for action in self._actions.values():
            lines.append(action.to_csv_row())
        content = "\n".join(lines) + "\n"
        atomic_write(str(self.csv_path), content)

        log.info("FileActionSink: wrote CSV -> %s", self.csv_path)

    def close(self) -> None:
        """Write final CSV summary on close."""
        if self.csv_path:
            self.write_csv_summary()


# ═══════════════════════════════════════════════════════════════════════════
#  FileActionFeedback - read ACKs from JSONL file
# ═══════════════════════════════════════════════════════════════════════════


class FileActionFeedback(ActionFeedback):
    """Action feedback reader from local JSONL file.

    Reads action acknowledgements (ACKs) from actions_applied.jsonl.
    """

    def __init__(self, path: str):
        """Initialize with file path.

        Args:
            path: Path to actions_applied.jsonl file.
        """
        self.path = Path(path)
        self._offset: int = 0

    def read_acks(self, since: Any = None) -> tuple[list[ActionAck], int]:
        """Read new ACKs from the file."""
        if since is not None and isinstance(since, int):
            self._offset = since

        if not self.path.exists():
            return [], self._offset

        try:
            size = self.path.stat().st_size
        except OSError:
            return [], self._offset

        if size <= self._offset:
            return [], self._offset

        acks: list[ActionAck] = []
        with open(self.path, encoding="utf-8") as fh:
            fh.seek(self._offset)
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ack = ActionAck.from_json(line)
                    acks.append(ack)
                except (json.JSONDecodeError, KeyError) as exc:
                    log.debug("Skipping bad ACK line: %s", exc)
            self._offset = fh.tell()

        if acks:
            log.info("FileActionFeedback: read %d ACKs from %s", len(acks), self.path)

        return acks, self._offset

    def close(self) -> None:
        """No resources to release."""
        pass


# ═══════════════════════════════════════════════════════════════════════════
#  SimulatedStateProvider - read state from emulator WorldState
# ═══════════════════════════════════════════════════════════════════════════


class SimulatedStateProvider(StateProvider):
    """State provider backed by the emulator's WorldState.

    For production, implement ScadaStateProvider, MonitoringStateProvider, etc.
    """

    def __init__(self, world_state: Any = None):
        """Initialize with optional WorldState reference.

        Args:
            world_state: Reference to emulator WorldState (if available).
        """
        self._world_state = world_state
        self._components: dict[str, ComponentState] = {}
        self._blocked_actors: set[str] = set()
        self._isolated_components: set[str] = set()

    def set_world_state(self, world_state: Any) -> None:
        """Update WorldState reference."""
        self._world_state = world_state

    def get_component_state(self, component_id: str) -> ComponentState | None:
        """Get state of a specific component."""
        if self._world_state is not None:
            return self._state_from_world(component_id)
        return self._components.get(component_id)

    def get_all_components(self) -> list[ComponentState]:
        """Get state of all known components."""
        if self._world_state is not None:
            # Return summary of known components
            return [
                self._state_from_world("gateway"),
                self._state_from_world("api"),
                self._state_from_world("db"),
                self._state_from_world("network"),
            ]
        return list(self._components.values())

    def is_actor_blocked(self, actor: str) -> bool:
        """Check if an actor is currently blocked."""
        if self._world_state is not None:
            return actor in getattr(self._world_state.auth, "blocked_actors", {})
        return actor in self._blocked_actors

    def is_component_isolated(self, component_id: str) -> bool:
        """Check if a component is currently isolated."""
        if self._world_state is not None:
            api = getattr(self._world_state, "api", None)
            if api and getattr(api, "status", "healthy") == "isolated":
                return True
        return component_id in self._isolated_components

    def _state_from_world(self, component_id: str) -> ComponentState:
        """Build ComponentState from WorldState."""
        ws = self._world_state
        details: dict[str, Any] = {}
        status = "healthy"

        if component_id == "gateway" and hasattr(ws, "gateway"):
            gw = ws.gateway
            if getattr(gw, "rate_limit_enabled", False):
                status = "rate_limited"
                details["rps"] = getattr(gw, "rate_limit_rps", 0)
                details["burst"] = getattr(gw, "rate_limit_burst", 0)

        elif component_id == "api" and hasattr(ws, "api"):
            api = ws.api
            status = getattr(api, "status", "healthy")

        elif component_id == "db" and hasattr(ws, "db"):
            db = ws.db
            status = getattr(db, "status", "healthy")
            details["snapshots"] = len(getattr(db, "snapshots", []))

        elif component_id == "network" and hasattr(ws, "network"):
            net = ws.network
            if getattr(net, "disconnected", False):
                status = "disconnected"
            elif getattr(net, "latency_ms", 0) > 0:
                status = "degraded"
                details["latency_ms"] = net.latency_ms
                details["drop_rate"] = getattr(net, "drop_rate", 0)

        return ComponentState(
            component_id=component_id,
            component_type=component_id,
            status=status,
            details=details,
        )

    # Methods for manual state updates (when WorldState not available)
    def set_component_status(self, component_id: str, status: str) -> None:
        """Manually set component status."""
        if component_id in self._components:
            self._components[component_id].status = status
        else:
            self._components[component_id] = ComponentState(
                component_id=component_id,
                component_type=component_id,
                status=status,
            )

    def block_actor(self, actor: str) -> None:
        """Mark an actor as blocked."""
        self._blocked_actors.add(actor)

    def unblock_actor(self, actor: str) -> None:
        """Mark an actor as unblocked."""
        self._blocked_actors.discard(actor)

    def isolate_component(self, component_id: str) -> None:
        """Mark a component as isolated."""
        self._isolated_components.add(component_id)
        self.set_component_status(component_id, "isolated")

    def release_isolation(self, component_id: str) -> None:
        """Release component isolation."""
        self._isolated_components.discard(component_id)
        self.set_component_status(component_id, "healthy")


# ═══════════════════════════════════════════════════════════════════════════
#  FileIncidentSource - read incidents from CSV file
# ═══════════════════════════════════════════════════════════════════════════


class FileIncidentSource(IncidentSource):
    """Incident source that reads from a local CSV file.

    For production, implement SiemIncidentSource, DatabaseIncidentSource, etc.
    """

    def __init__(self, path: str):
        """Initialize with file path.

        Args:
            path: Path to incidents.csv file.
        """
        self.path = Path(path)

    def get_incidents(self, limit: int = 10000) -> list[dict[str, Any]]:
        """Get list of incidents from CSV file."""
        if not self.path.exists():
            return []

        try:
            import pandas as pd
            df = pd.read_csv(self.path, nrows=limit)
            return df.to_dict("records")
        except Exception as e:
            log.warning("Failed to read incidents from %s: %s", self.path, e)
            return []

    def get_incident_count(self) -> int:
        """Get total number of incidents."""
        if not self.path.exists():
            return 0

        try:
            with open(self.path, encoding="utf-8") as fh:
                return sum(1 for _ in fh) - 1  # subtract header
        except Exception:
            return 0


# ═══════════════════════════════════════════════════════════════════════════
#  FileActionSource - read actions from CSV file
# ═══════════════════════════════════════════════════════════════════════════


class FileActionSource(ActionSource):
    """Action source that reads from a local CSV file.

    For production, implement SoarActionSource, DatabaseActionSource, etc.
    """

    def __init__(self, path: str):
        """Initialize with file path.

        Args:
            path: Path to actions.csv file.
        """
        self.path = Path(path)

    def get_actions(self, limit: int = 10000) -> list[dict[str, Any]]:
        """Get list of actions from CSV file."""
        if not self.path.exists():
            return []

        try:
            import pandas as pd
            df = pd.read_csv(self.path, nrows=limit)
            return df.to_dict("records")
        except Exception as e:
            log.warning("Failed to read actions from %s: %s", self.path, e)
            return []

    def get_action_summary(self) -> dict[str, int]:
        """Get summary of actions by status."""
        if not self.path.exists():
            return {"total": 0, "applied": 0, "failed": 0, "emitted": 0}

        try:
            import pandas as pd
            df = pd.read_csv(self.path)

            if "status" not in df.columns:
                return {"total": len(df), "applied": 0, "failed": 0, "emitted": len(df)}

            status_counts = df["status"].value_counts().to_dict()
            return {
                "total": len(df),
                "applied": status_counts.get("applied", 0),
                "failed": status_counts.get("failed", 0),
                "emitted": status_counts.get("emitted", 0),
            }
        except Exception as e:
            log.warning("Failed to read action summary from %s: %s", self.path, e)
            return {"total": 0, "applied": 0, "failed": 0, "emitted": 0}


# ═══════════════════════════════════════════════════════════════════════════
#  FileMetricsSource - read metrics from CSV file
# ═══════════════════════════════════════════════════════════════════════════


class FileMetricsSource(MetricsSource):
    """Metrics source that reads from a local CSV file.

    For production, implement PrometheusMetricsSource, DatabaseMetricsSource, etc.
    """

    def __init__(self, path: str):
        """Initialize with file path.

        Args:
            path: Path to results.csv file.
        """
        self.path = Path(path)

    def get_metrics_by_policy(self) -> list[dict[str, Any]]:
        """Get metrics grouped by security policy."""
        if not self.path.exists():
            return []

        try:
            import pandas as pd
            df = pd.read_csv(self.path)
            return df.to_dict("records")
        except Exception as e:
            log.warning("Failed to read metrics from %s: %s", self.path, e)
            return []

    def get_overall_metrics(self) -> dict[str, float]:
        """Get overall system metrics."""
        if not self.path.exists():
            return {}

        try:
            import pandas as pd
            df = pd.read_csv(self.path)

            # Aggregate metrics across all policies
            result = {}
            for col in ["availability", "mttd_sec", "mttr_sec", "downtime_sec"]:
                if col in df.columns:
                    result[col] = df[col].mean()

            return result
        except Exception as e:
            log.warning("Failed to read overall metrics from %s: %s", self.path, e)
            return {}


# ═══════════════════════════════════════════════════════════════════════════
#  FileStateSource - read component state from CSV file
# ═══════════════════════════════════════════════════════════════════════════


class FileStateSource(StateProvider):
    """State provider that reads from a local CSV file.

    For production, implement ScadaStateProvider, PrometheusStateProvider, etc.
    """

    def __init__(self, path: str):
        """Initialize with file path.

        Args:
            path: Path to state.csv file.
        """
        self.path = Path(path)
        self._cache: dict[str, ComponentState] = {}
        self._blocked_actors: set[str] = set()
        self._isolated_components: set[str] = set()

    def _load(self) -> None:
        """Load state from CSV file."""
        if not self.path.exists():
            return

        try:
            import pandas as pd
            df = pd.read_csv(self.path)

            self._cache.clear()
            self._blocked_actors.clear()
            self._isolated_components.clear()

            for _, row in df.iterrows():
                comp_id = row.get("component", "")
                status = row.get("status", "unknown")
                details_str = row.get("details", "{}")

                # Parse details
                details = {}
                if isinstance(details_str, str) and details_str.strip():
                    try:
                        details = json.loads(details_str)
                    except json.JSONDecodeError:
                        pass

                self._cache[comp_id] = ComponentState(
                    component_id=comp_id,
                    component_type=comp_id,
                    status=status,
                    details=details,
                    last_updated=row.get("last_updated", ""),
                )

                # Track isolated components
                if status == "isolated":
                    self._isolated_components.add(comp_id)

                # Track blocked actors from details
                if "blocked_actors" in details:
                    for actor in details.get("blocked_actors", []):
                        self._blocked_actors.add(actor)

        except Exception as e:
            log.warning("Failed to load state from %s: %s", self.path, e)

    def get_component_state(self, component_id: str) -> ComponentState | None:
        """Get state of a specific component."""
        self._load()
        return self._cache.get(component_id)

    def get_all_components(self) -> list[ComponentState]:
        """Get state of all known components."""
        self._load()
        return list(self._cache.values())

    def is_actor_blocked(self, actor: str) -> bool:
        """Check if an actor is currently blocked."""
        self._load()
        return actor in self._blocked_actors

    def is_component_isolated(self, component_id: str) -> bool:
        """Check if a component is currently isolated."""
        self._load()
        return component_id in self._isolated_components
