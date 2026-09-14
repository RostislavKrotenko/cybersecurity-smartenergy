"""Абстрактні інтерфейси для інтеграції з реальними системами SmartEnergy.

Інтерфейси відділяють аналізатор і реагування від конкретних джерел даних,
сховищ та виконавців дій. Для реальної інфраструктури потрібно реалізувати
відповідні адаптери, наприклад KafkaEventSource, SoarActionSink або
ScadaStateProvider, і передати їх у конвеєр.

Файлові адаптери залишаються еталонною реалізацією для симуляції й тестів.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.contracts.action import Action, ActionAck
from src.contracts.event import Event


class EventSource(ABC):
    """Джерело подій безпеки.

    Реалізації можуть читати події з різних джерел:
    - FileEventSource: CSV/JSONL файли для симуляції
    - KafkaEventSource: топіки Apache Kafka
    - SiemEventSource: API Splunk/Elastic/QRadar
    - ModbusEventSource: пряме опитування Modbus-пристроїв
    - MqttEventSource: підписка на MQTT broker
    """

    @abstractmethod
    def read_batch(self, limit: int = 10000) -> list[Event]:
        """Зчитує пакет подій з джерела."""
        pass

    @abstractmethod
    def read_stream(self, poll_interval_sec: float = 1.0) -> Iterator[list[Event]]:
        """Повертає потік пакетів подій для режиму спостереження."""
        pass

    @abstractmethod
    def get_offset(self) -> Any:
        """Повертає поточну позицію читання для відновлення."""
        pass

    @abstractmethod
    def seek(self, offset: Any) -> None:
        """Переходить до вказаної позиції у джерелі."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Звільняє ресурси джерела."""
        pass


class EventSink(ABC):
    """Приймач нормалізованих або згенерованих подій.

    Реалізації можуть передавати події в різні напрямки:
    - FileEventSink: JSONL/CSV файли для симуляції
    - KafkaEventSink: топіки Apache Kafka
    - SiemEventSink: передача в SIEM (Splunk, Elastic)
    - MqttEventSink: публікація в MQTT broker

    Використовується емулятором і нормалізатором.
    """

    @abstractmethod
    def emit(self, event: Event) -> None:
        """Передає одну подію."""
        pass

    @abstractmethod
    def emit_batch(self, events: list[Event]) -> None:
        """Передає пакет подій."""
        pass

    @abstractmethod
    def flush(self) -> None:
        """Записує буферизовані події в цільове сховище."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Звільняє ресурси приймача."""
        pass


class ActionStatus(str, Enum):
    """Статус дії реагування."""

    PENDING = "pending"
    EMITTED = "emitted"
    APPLIED = "applied"
    FAILED = "failed"


@dataclass
class ActionResult:
    """Результат виконання дії реагування."""

    success: bool
    action_id: str
    status: ActionStatus
    state_events: list[Event] = field(default_factory=list)
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ActionSink(ABC):
    """Приймач дій реагування.

    Реалізації можуть передавати дії у файл, SOAR-платформу, SCADA/PLC API
    або інший REST-сервіс.
    """

    @abstractmethod
    def emit(self, action: Action) -> str:
        """Передає одну дію і повертає її ідентифікатор відстеження."""
        pass

    @abstractmethod
    def emit_batch(self, actions: list[Action]) -> list[str]:
        """Передає пакет дій і повертає їхні ідентифікатори."""
        pass

    @abstractmethod
    def get_status(self, action_id: str) -> ActionStatus:
        """Повертає статус раніше переданої дії."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Звільняє ресурси приймача."""
        pass


class ActionFeedback(ABC):
    """Джерело підтверджень виконання дій.

    Реалізації можуть читати ACK із JSONL, HTTP callback або черги повідомлень.
    """

    @abstractmethod
    def read_acks(self, since: Any = None) -> tuple[list[ActionAck], Any]:
        """Зчитує нові підтвердження та повертає новий offset/cursor."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Звільняє ресурси джерела."""
        pass


class ActionExecutor(ABC):
    """Виконавець дій безпосередньо в інфраструктурі.

    Цей інтерфейс потрібен, коли аналізатор не лише емітить дії, а й одразу
    застосовує їх через емулятор, firewall API, SCADA API або хмарні сервіси.
    """

    @abstractmethod
    def execute(self, action: Action) -> ActionResult:
        """Виконує дію в цільовій інфраструктурі."""
        pass

    @abstractmethod
    def supports_action(self, action_type: str) -> bool:
        """Перевіряє, чи підтримується вказаний тип дії."""
        pass

    @abstractmethod
    def get_component_status(self, component_id: str) -> dict[str, Any]:
        """Повертає поточний статус компонента."""
        pass


class GatewayControl(ABC):
    """Інтерфейс керування API/IoT gateway.

    Реалізація може звертатися до емулятора, Nginx/WAF API, MQTT command topic
    або іншого gateway-management бекенду. Аналізатор і далі емітить загальний
    Action, а ActionRouter перетворює його на конкретний виклик.
    """

    @abstractmethod
    def enable_rate_limit(
        self,
        *,
        action_id: str,
        correlation_id: str,
        rps: int,
        burst: int,
        duration_sec: int,
    ) -> ActionResult:
        """Вмикає тимчасовий rate limiting на gateway."""
        pass

    @abstractmethod
    def disable_rate_limit(self, *, action_id: str, correlation_id: str) -> ActionResult:
        """Вимикає активний rate limiting на gateway."""
        pass


class ApiControl(ABC):
    """Інтерфейс керування API та бекенд-сервісами."""

    @abstractmethod
    def isolate_component(
        self,
        *,
        action_id: str,
        correlation_id: str,
        component_id: str,
        target_id: str,
        duration_sec: int,
    ) -> ActionResult:
        """Тимчасово ізолює компонент, доступний через API."""
        pass

    @abstractmethod
    def release_isolation(
        self,
        *,
        action_id: str,
        correlation_id: str,
        component_id: str,
        target_id: str,
    ) -> ActionResult:
        """Знімає ізоляцію з API-компонента."""
        pass


class AuthControl(ABC):
    """Інтерфейс керування автентифікацією та доступом."""

    @abstractmethod
    def block_actor(
        self,
        *,
        action_id: str,
        correlation_id: str,
        actor: str,
        ip: str,
        duration_sec: int,
    ) -> ActionResult:
        """Тимчасово блокує користувача, актора, IP-адресу або їх комбінацію."""
        pass

    @abstractmethod
    def unblock_actor(
        self,
        *,
        action_id: str,
        correlation_id: str,
        actor: str,
        ip: str,
    ) -> ActionResult:
        """Знімає блокування користувача або IP-адреси."""
        pass


class DatabaseControl(ABC):
    """Інтерфейс керування БД, зокрема Postgres, InfluxDB або MongoDB."""

    @abstractmethod
    def backup(self, *, action_id: str, correlation_id: str, name: str) -> ActionResult:
        """Створює backup/snapshot бази даних."""
        pass

    @abstractmethod
    def restore(self, *, action_id: str, correlation_id: str, snapshot: str) -> ActionResult:
        """Відновлює базу даних із вказаного snapshot."""
        pass

    @abstractmethod
    def corrupt(self, *, action_id: str, correlation_id: str) -> ActionResult:
        """Позначає або симулює пошкодження БД для контрольованого тесту."""
        pass

    @abstractmethod
    def verify_integrity(self) -> bool:
        """Повертає результат перевірки цілісності БД."""
        pass


class NetworkControl(ABC):
    """Інтерфейс керування мережевою інфраструктурою або симулятором."""

    @abstractmethod
    def degrade_network(
        self,
        *,
        action_id: str,
        correlation_id: str,
        latency_ms: int,
        drop_rate: float,
        ttl_sec: int,
        disconnected: bool,
    ) -> ActionResult:
        """Застосовує тимчасову деградацію мережі."""
        pass

    @abstractmethod
    def reset_network(self, *, action_id: str, correlation_id: str) -> ActionResult:
        """Скидає стан деградації або відмови мережі."""
        pass


@dataclass
class ComponentState:
    """Стан одного компонента інфраструктури."""

    component_id: str
    component_type: str
    status: str  # допустимі стани: healthy, degraded, isolated, down
    details: dict[str, Any] = field(default_factory=dict)
    last_updated: str = ""


class StateProvider(ABC):
    """Провайдер стану інфраструктури.

    Реалізації можуть читати стан із WorldState, SCADA/RTU, Prometheus/Grafana
    або іншої системи моніторингу.
    """

    @abstractmethod
    def get_component_state(self, component_id: str) -> ComponentState | None:
        """Повертає стан конкретного компонента."""
        pass

    @abstractmethod
    def get_all_components(self) -> list[ComponentState]:
        """Повертає стан усіх відомих компонентів."""
        pass

    @abstractmethod
    def is_actor_blocked(self, actor: str) -> bool:
        """Перевіряє, чи актор зараз заблокований."""
        pass

    @abstractmethod
    def is_component_isolated(self, component_id: str) -> bool:
        """Перевіряє, чи компонент зараз ізольований."""
        pass


class IncidentSource(ABC):
    """Джерело даних про інциденти для dashboard/API.

    Реалізації можуть читати інциденти з CSV, SIEM API або бази даних.
    """

    @abstractmethod
    def get_incidents(self, limit: int = 10000) -> list[dict[str, Any]]:
        """Повертає список інцидентів."""
        pass

    @abstractmethod
    def get_incident_count(self) -> int:
        """Повертає загальну кількість інцидентів."""
        pass


class ActionSource(ABC):
    """Джерело даних про дії реагування.

    Реалізації можуть читати дії з CSV, SOAR-платформи або бази даних.
    """

    @abstractmethod
    def get_actions(self, limit: int = 10000) -> list[dict[str, Any]]:
        """Повертає список дій реагування."""
        pass

    @abstractmethod
    def get_action_summary(self) -> dict[str, int]:
        """Повертає зведення дій за статусами."""
        pass


class MetricsSource(ABC):
    """Джерело метрик кіберстійкості.

    Реалізації можуть читати метрики з CSV, Prometheus або бази даних.
    """

    @abstractmethod
    def get_metrics_by_policy(self) -> list[dict[str, Any]]:
        """Повертає метрики, згруповані за політикою безпеки."""
        pass

    @abstractmethod
    def get_overall_metrics(self) -> dict[str, float]:
        """Повертає агреговані метрики системи."""
        pass
