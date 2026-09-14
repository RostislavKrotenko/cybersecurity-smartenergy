"""Файлові адаптери для симуляції та тестування.

Адаптери реалізують абстрактні інтерфейси через локальні CSV/JSONL файли.
Вони потрібні як еталон реалізації, робочий режим емуляції та fallback,
коли реальна інфраструктура ще недоступна.

Для інтеграції з реальними системами SmartEnergy можна додати адаптери:
- kafka_adapter.py: KafkaEventSource, KafkaActionSink
- siem_adapter.py: SplunkEventSource, ElasticEventSource
- scada_adapter.py: ScadaActionExecutor, ScadaStateProvider
- soar_adapter.py: XsoarActionSink, PhantomActionSink
"""

from __future__ import annotations

import contextlib
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
from src.shared.file_utils import (
    atomic_write,
    load_offset_checkpoint,
    save_offset_checkpoint,
)

log = logging.getLogger(__name__)


class FileEventSource(EventSource):
    """Джерело подій із локального CSV або JSONL файла.

    У потоковому режимі позиція читання може зберігатися
    у checkpoint, щоб після перезапуску не обробляти старі події.
    """

    def __init__(
        self,
        path: str,
        checkpoint_path: str | Path | None = None,
    ) -> None:
        """Ініціалізує файлове джерело та відновлює offset."""
        self.path = Path(path)
        self._checkpoint_path = (
            Path(checkpoint_path)
            if checkpoint_path is not None
            else None
        )
        self._offset, self._inode = load_offset_checkpoint(
            self._checkpoint_path,
            self.path,
        )
        self._is_jsonl = self.path.suffix in {
            ".jsonl",
            ".ndjson",
        }
        self._last_mtime_ns: int | None = None

    def read_batch(self, limit: int = 10000) -> list[Event]:
        """Зчитує події з файла у пакетному режимі."""
        if not self.path.exists():
            log.warning(
                "Event source file not found: %s",
                self.path,
            )
            return []

        if self._is_jsonl:
            return self._read_jsonl(limit)

        return self._read_csv(limit)

    def _read_csv(self, limit: int) -> list[Event]:
        """Зчитує події з CSV файла."""
        events: list[Event] = []

        with self.path.open(
            "r",
            encoding="utf-8",
        ) as stream:
            reader = csv.DictReader(stream)

            for index, row in enumerate(reader):
                if index >= limit:
                    break

                events.append(Event.from_dict(row))

        log.info(
            "FileEventSource: loaded %d events from CSV: %s",
            len(events),
            self.path,
        )
        return events

    def _read_jsonl(self, limit: int) -> list[Event]:
        """Зчитує події з JSONL файла у пакетному режимі."""
        events: list[Event] = []

        with self.path.open(
            "r",
            encoding="utf-8",
        ) as stream:
            for index, line in enumerate(stream):
                if index >= limit:
                    break

                stripped = line.strip()

                if not stripped:
                    continue

                try:
                    payload = json.loads(stripped)

                    if not isinstance(payload, dict):
                        raise TypeError(
                            "JSONL-запис повинен бути об'єктом"
                        )

                    events.append(Event.from_dict(payload))

                except (
                    json.JSONDecodeError,
                    KeyError,
                    TypeError,
                    AttributeError,
                ) as error:
                    log.warning(
                        "Skipping JSONL line %d: %s",
                        index + 1,
                        error,
                    )

        log.info(
            "FileEventSource: loaded %d events from JSONL: %s",
            len(events),
            self.path,
        )
        return events

    def read_stream(
        self,
        poll_interval_sec: float = 1.0,
    ) -> Iterator[list[Event]]:
        """Повертає нові події через tail-читання файла."""
        while True:
            yield self._read_new_lines()
            time.sleep(poll_interval_sec)

    def _read_new_lines(self) -> list[Event]:
        """Зчитує рядки після збереженого offset."""
        if not self.path.exists():
            return []

        try:
            source_stat = self.path.stat()
        except OSError:
            return []

        current_size = source_stat.st_size
        current_inode = source_stat.st_ino
        current_mtime_ns = source_stat.st_mtime_ns

        if (
            self._inode is not None
            and self._inode != current_inode
        ):
            log.info(
                "FileEventSource: виявлено заміну файла %s",
                self.path,
            )
            self._offset = 0
            self._last_mtime_ns = None

        if current_size < self._offset:
            log.info(
                "FileEventSource: файл %s скорочено "
                "(offset=%d -> 0)",
                self.path,
                self._offset,
            )
            self._offset = 0
            self._last_mtime_ns = None

        self._inode = current_inode

        if current_size == self._offset:
            if (
                self._last_mtime_ns is not None
                and current_mtime_ns != self._last_mtime_ns
            ):
                log.info(
                    "FileEventSource: файл %s було "
                    "перезаписано без зміни розміру",
                    self.path,
                )
                self._offset = 0
            else:
                self._last_mtime_ns = current_mtime_ns
                self._save_checkpoint()
                return []

        if current_size == 0:
            self._last_mtime_ns = current_mtime_ns
            self._save_checkpoint()
            return []

        events: list[Event] = []

        try:
            with self.path.open(
                "r",
                encoding="utf-8",
            ) as stream:
                stream.seek(self._offset)

                while len(events) < 10000:
                    line_start = stream.tell()
                    line = stream.readline()

                    if not line:
                        break

                    if not line.endswith("\n"):
                        stream.seek(line_start)
                        break

                    stripped = line.strip()

                    if not stripped:
                        continue

                    try:
                        payload = json.loads(stripped)

                        if not isinstance(payload, dict):
                            raise TypeError(
                                "JSONL-запис повинен бути об'єктом"
                            )

                        events.append(
                            Event.from_dict(payload)
                        )

                    except (
                        json.JSONDecodeError,
                        KeyError,
                        TypeError,
                        AttributeError,
                    ) as error:
                        log.warning(
                            "Пропущено некоректну подію: %s",
                            error,
                        )

                self._offset = stream.tell()

        except OSError:
            log.exception(
                "Не вдалося прочитати події з %s",
                self.path,
            )
            return []

        with contextlib.suppress(OSError):
            source_stat = self.path.stat()
            self._inode = source_stat.st_ino
            self._last_mtime_ns = source_stat.st_mtime_ns

        self._save_checkpoint()
        return events

    def get_offset(self) -> int:
        """Повертає поточний byte-offset файла."""
        return self._offset

    def seek(self, offset: Any) -> None:
        """Установлює новий byte-offset файла."""
        if not isinstance(offset, int) or offset < 0:
            raise ValueError(
                "Offset подій має бути невід'ємним цілим числом"
            )

        self._offset = offset
        self._save_checkpoint()

    def close(self) -> None:
        """Зберігає поточну позицію перед закриттям."""
        self._save_checkpoint()

    def _save_checkpoint(self) -> None:
        """Зберігає позицію потокового читання."""
        save_offset_checkpoint(
            self._checkpoint_path,
            self.path,
            self._offset,
            self._inode,
        )
        
        
class FileEventSink(EventSink):
    """Приймач подій, який записує їх у локальний JSONL файл.

    Використовується емулятором і нормалізатором. Для production-режиму
    можна реалізувати KafkaEventSink, SiemEventSink або інший адаптер.
    """

    def __init__(self, path: str):
        """Ініціалізує приймач шляхом до JSONL файла."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._buffer: list[Event] = []
        self._count = 0

    def emit(self, event: Event) -> None:
        """Записує одну подію у файл."""
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(event.to_json() + "\n")
            fh.flush()
        self._count += 1

    def emit_batch(self, events: list[Event]) -> None:
        """Записує пакет подій у файл."""
        if not events:
            return

        with open(self.path, "a", encoding="utf-8") as fh:
            for event in events:
                fh.write(event.to_json() + "\n")
            fh.flush()
        self._count += len(events)
        log.info("FileEventSink: emitted %d events -> %s", len(events), self.path)

    def flush(self) -> None:
        """Файловий приймач записує без буфера, тому дія порожня."""
        pass

    def close(self) -> None:
        """Фіксує фінальну статистику запису."""
        log.info("FileEventSink: total %d events written to %s", self._count, self.path)

    @property
    def event_count(self) -> int:
        """Повертає загальну кількість записаних подій."""
        return self._count


class FileActionSink(ActionSink):
    """Приймач дій, який записує їх у локальний JSONL файл.

    Для production-інтеграції варто реалізувати SoarActionSink,
    ScadaActionSink або інший виконавець.
    """

    def __init__(self, path: str, csv_path: str | None = None):
        """Ініціалізує приймач шляхами до JSONL і опційного CSV файла."""
        self.path = Path(path)
        self.csv_path = Path(csv_path) if csv_path else None
        self._actions: dict[str, Action] = {}
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, action: Action) -> str:
        """Записує одну дію у файл."""
        action.status = "emitted"
        self._actions[action.action_id] = action

        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(action.to_json() + "\n")
            fh.flush()

        log.info("FileActionSink: emitted %s -> %s", action.action_id, self.path)
        return action.action_id

    def emit_batch(self, actions: list[Action]) -> list[str]:
        """Записує пакет дій у файл."""
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
        """Повертає статус раніше записаної дії."""
        action = self._actions.get(action_id)
        if action is None:
            return ActionStatus.PENDING
        return ActionStatus(action.status)

    def update_status(self, action_id: str, status: ActionStatus) -> None:
        """Оновлює статус дії після отримання підтвердження."""
        action = self._actions.get(action_id)
        if action:
            action.status = status.value

    def get_all_actions(self) -> list[Action]:
        """Повертає всі відстежувані дії."""
        return list(self._actions.values())

    def write_csv_summary(self) -> None:
        """Записує CSV-зведення всіх дій."""
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
        """Записує фінальне CSV-зведення під час закриття."""
        if self.csv_path:
            self.write_csv_summary()

class FileActionFeedback(ActionFeedback):
    """Джерело підтверджень дій із локального JSONL файла."""

    def __init__(self, path: str):
        """Ініціалізує читач шляхом до actions_applied.jsonl."""
        self.path = Path(path)
        self._offset: int = 0
        self._last_mtime_ns: int | None = None

    def read_acks(self, since: Any = None) -> tuple[list[ActionAck], int]:
        """Зчитує нові ACK-записи з файла."""
        if since is not None and isinstance(since, int):
            self._offset = since

        if not self.path.exists():
            return [], self._offset

        try:
            st = self.path.stat()
            size = st.st_size
            mtime_ns = st.st_mtime_ns
        except OSError:
            return [], self._offset

        # ACK-файл обрізано або ротовано, тому читаємо з початку.
        if size < self._offset:
            log.info(
                "FileActionFeedback: detected truncate/rotation for %s (offset=%d -> 0)",
                self.path,
                self._offset,
            )
            self._offset = 0

        if size == self._offset:
            if self._last_mtime_ns is not None and mtime_ns != self._last_mtime_ns:
                log.info(
                    "FileActionFeedback: detected same-size rewrite for %s (offset=%d -> 0)",
                    self.path,
                    self._offset,
                )
                self._offset = 0
            else:
                self._last_mtime_ns = mtime_ns
                return [], self._offset

        if size == 0:
            self._last_mtime_ns = mtime_ns
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

        with contextlib.suppress(OSError):
            self._last_mtime_ns = self.path.stat().st_mtime_ns

        if acks:
            log.info("FileActionFeedback: read %d ACKs from %s", len(acks), self.path)

        return acks, self._offset

    def close(self) -> None:
        """Файловий читач не тримає додаткових ресурсів."""
        pass


class SimulatedStateProvider(StateProvider):
    """Провайдер стану, що читає дані з WorldState емулятора.

    Для production-режиму варто реалізувати ScadaStateProvider,
    MonitoringStateProvider або інший провайдер реального стану.
    """

    def __init__(self, world_state: Any = None):
        """Ініціалізує провайдер опційним посиланням на WorldState."""
        self._world_state = world_state
        self._components: dict[str, ComponentState] = {}
        self._blocked_actors: set[str] = set()
        self._isolated_components: set[str] = set()

    def set_world_state(self, world_state: Any) -> None:
        """Оновлює посилання на WorldState."""
        self._world_state = world_state

    def get_component_state(self, component_id: str) -> ComponentState | None:
        """Повертає стан конкретного компонента."""
        if self._world_state is not None:
            return self._state_from_world(component_id)
        return self._components.get(component_id)

    def get_all_components(self) -> list[ComponentState]:
        """Повертає стан усіх відомих компонентів."""
        if self._world_state is not None:
            return [
                self._state_from_world("gateway"),
                self._state_from_world("api"),
                self._state_from_world("db"),
                self._state_from_world("network"),
            ]
        return list(self._components.values())

    def is_actor_blocked(self, actor: str) -> bool:
        """Перевіряє, чи актор зараз заблокований."""
        if self._world_state is not None:
            return actor in getattr(self._world_state.auth, "blocked_actors", {})
        return actor in self._blocked_actors

    def is_component_isolated(self, component_id: str) -> bool:
        """Перевіряє, чи компонент зараз ізольований."""
        if self._world_state is not None:
            api = getattr(self._world_state, "api", None)
            if api and getattr(api, "status", "healthy") == "isolated":
                return True
        return component_id in self._isolated_components

    def _state_from_world(self, component_id: str) -> ComponentState:
        """Створює ComponentState на основі WorldState."""
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

    def set_component_status(self, component_id: str, status: str) -> None:
        """Вручну задає статус компонента."""
        if component_id in self._components:
            self._components[component_id].status = status
        else:
            self._components[component_id] = ComponentState(
                component_id=component_id,
                component_type=component_id,
                status=status,
            )

    def block_actor(self, actor: str) -> None:
        """Позначає актора як заблокованого."""
        self._blocked_actors.add(actor)

    def unblock_actor(self, actor: str) -> None:
        """Позначає актора як розблокованого."""
        self._blocked_actors.discard(actor)

    def isolate_component(self, component_id: str) -> None:
        """Позначає компонент як ізольований."""
        self._isolated_components.add(component_id)
        self.set_component_status(component_id, "isolated")

    def release_isolation(self, component_id: str) -> None:
        """Знімає ізоляцію компонента."""
        self._isolated_components.discard(component_id)
        self.set_component_status(component_id, "healthy")

class FileIncidentSource(IncidentSource):
    """Джерело інцидентів із локального CSV файла.

    Для production-режиму варто реалізувати SiemIncidentSource або
    DatabaseIncidentSource.
    """

    def __init__(self, path: str):
        """Ініціалізує джерело шляхом до incidents.csv."""
        self.path = Path(path)

    def get_incidents(self, limit: int = 10000) -> list[dict[str, Any]]:
        """Повертає список інцидентів із CSV файла."""
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
        """Повертає загальну кількість інцидентів."""
        if not self.path.exists():
            return 0

        try:
            with open(self.path, encoding="utf-8") as fh:
                return sum(1 for _ in fh) - 1  # віднімаємо заголовок CSV
        except Exception:
            return 0


class FileActionSource(ActionSource):
    """Джерело дій реагування з локального CSV файла.

    Для production-режиму варто реалізувати SoarActionSource або
    DatabaseActionSource.
    """

    def __init__(self, path: str):
        """Ініціалізує джерело шляхом до actions.csv."""
        self.path = Path(path)

    def get_actions(self, limit: int = 10000) -> list[dict[str, Any]]:
        """Повертає список дій із CSV файла."""
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
        """Повертає зведення дій за статусами."""
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

class FileMetricsSource(MetricsSource):
    """Джерело метрик із локального CSV файла.

    Для production-режиму варто реалізувати PrometheusMetricsSource або
    DatabaseMetricsSource.
    """

    def __init__(self, path: str):
        """Ініціалізує джерело шляхом до results.csv."""
        self.path = Path(path)

    def get_metrics_by_policy(self) -> list[dict[str, Any]]:
        """Повертає метрики, згруповані за політикою безпеки."""
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
        """Повертає агреговані метрики системи у форматі API."""
        if not self.path.exists():
            return {}

        try:
            import pandas as pd

            df = pd.read_csv(self.path)

            if df.empty:
                return {}

            def numeric_mean(column: str) -> float:
                """Обчислює середнє лише для коректних числових значень."""
                values = pd.to_numeric(
                    df[column],
                    errors="coerce",
                ).dropna()

                if values.empty:
                    return 0.0

                return float(values.mean())

            result: dict[str, float] = {}

            # Підтримка старого формату CSV.
            for column in [
                "availability",
                "mttd_sec",
                "mttr_sec",
                "downtime_sec",
            ]:
                if column in df.columns:
                    result[column] = numeric_mean(column)

            if "availability_pct" in df.columns:
                result["avg_availability_pct"] = numeric_mean(
                    "availability_pct"
                )
            elif "availability" in result:
                result["avg_availability_pct"] = result["availability"]

            if "mean_mttd_min" in df.columns:
                result["avg_mttd_min"] = numeric_mean(
                    "mean_mttd_min"
                )
            elif "mttd_sec" in result:
                result["avg_mttd_min"] = result["mttd_sec"] / 60.0

            if "mean_mttr_min" in df.columns:
                result["avg_mttr_min"] = numeric_mean(
                    "mean_mttr_min"
                )
            elif "mttr_sec" in result:
                result["avg_mttr_min"] = result["mttr_sec"] / 60.0

            if "incidents_total" in df.columns:
                incidents = pd.to_numeric(
                    df["incidents_total"],
                    errors="coerce",
                ).fillna(0)
                result["total_incidents"] = float(incidents.sum())
            elif "incident_count" in df.columns:
                incidents = pd.to_numeric(
                    df["incident_count"],
                    errors="coerce",
                ).fillna(0)
                result["total_incidents"] = float(incidents.sum())

            return result

        except Exception as error:
            log.warning(
                "Failed to read overall metrics from %s: %s",
                self.path,
                error,
            )
            return {}

class FileStateSource(StateProvider):
    """Провайдер стану, який читає локальний CSV файл.

    Для production-режиму варто реалізувати ScadaStateProvider або
    PrometheusStateProvider.
    """

    def __init__(self, path: str):
        """Ініціалізує провайдер шляхом до state.csv."""
        self.path = Path(path)
        self._cache: dict[str, ComponentState] = {}
        self._blocked_actors: set[str] = set()
        self._isolated_components: set[str] = set()

    def _load(self) -> None:
        """Завантажує стан із CSV файла."""
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

                details = self._parse_details(details_str)
                if isinstance(details_str, str) and details_str.strip():
                    with contextlib.suppress(json.JSONDecodeError):
                        details = json.loads(details_str)

                last_updated = row.get("last_updated", "")
                if not last_updated:
                    last_updated = row.get("timestamp_utc", "")

                self._cache[comp_id] = ComponentState(
                    component_id=comp_id,
                    component_type=comp_id,
                    status=status,
                    details=details,
                    last_updated=last_updated,
                )

                if status == "isolated":
                    self._isolated_components.add(comp_id)

                if "blocked_actors" in details:
                    for actor in details.get("blocked_actors", []):
                        self._blocked_actors.add(actor)

        except Exception as e:
            log.warning("Failed to load state from %s: %s", self.path, e)

    @staticmethod
    def _parse_details(details_str: Any) -> dict[str, Any]:
        """Перетворює JSON або короткий текст details у словник."""
        if not isinstance(details_str, str) or not details_str.strip():
            return {}

        stripped = details_str.strip()
        with contextlib.suppress(json.JSONDecodeError):
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return parsed

        details: dict[str, Any] = {}
        for part in stripped.split():
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            details[key.strip()] = value.strip().strip(",")

        if details:
            return details

        return {"summary": stripped}

    def get_component_state(self, component_id: str) -> ComponentState | None:
        """Повертає стан конкретного компонента."""
        self._load()
        return self._cache.get(component_id)

    def get_all_components(self) -> list[ComponentState]:
        """Повертає стан усіх відомих компонентів."""
        self._load()
        return list(self._cache.values())

    def is_actor_blocked(self, actor: str) -> bool:
        """Перевіряє, чи актор зараз заблокований."""
        self._load()
        return actor in self._blocked_actors

    def is_component_isolated(self, component_id: str) -> bool:
        """Перевіряє, чи компонент зараз ізольований."""
        self._load()
        return component_id in self._isolated_components
