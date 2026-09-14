"""Пакет адаптерів із підмінними реалізаціями абстрактних інтерфейсів.

Доступні файлові адаптери:
- FileEventSource: читає події з CSV/JSONL
- FileEventSink: записує події в JSONL
- FileActionSink: записує дії в JSONL
- FileActionFeedback: читає ACK із JSONL
- FileIncidentSource: читає інциденти з CSV
- FileActionSource: читає дії з CSV
- FileMetricsSource: читає метрики з CSV
- FileStateSource: читає стан компонентів з CSV
- SimulatedStateProvider: читає стан із WorldState емулятора

Поточний файловий контур:
    Emulator (events) -> FileEventSink -> events.jsonl
    events.jsonl -> FileEventSource -> Analyzer -> FileActionSink -> actions.jsonl
    Analyzer -> incidents.csv, actions.csv, state.csv
    Dashboard <- FileIncidentSource, FileActionSource, FileStateSource

Коли буде доступна реальна інфраструктура SmartEnergy, File* адаптери можна
замінити Kafka*, Scada*, Soar* або Siem* адаптерами без зміни бізнес-логіки.
"""

from src.adapters.action_router import ActionRouter, ComponentControls
from src.adapters.file_adapter import (
    FileActionFeedback,
    FileActionSink,
    FileActionSource,
    FileEventSink,
    FileEventSource,
    FileIncidentSource,
    FileMetricsSource,
    FileStateSource,
    SimulatedStateProvider,
)

__all__ = [
    "ActionRouter",
    "ComponentControls",
    "FileActionFeedback",
    "FileActionSink",
    "FileActionSource",
    "FileEventSink",
    "FileEventSource",
    "FileIncidentSource",
    "FileMetricsSource",
    "FileStateSource",
    "SimulatedStateProvider",
]
