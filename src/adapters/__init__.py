"""Adapters package - plug-and-play implementations of abstract interfaces.

Available adapters:
- FileEventSource: Read events from CSV/JSONL files
- FileEventSink: Write events to JSONL files
- FileActionSink: Write actions to JSONL files
- FileActionFeedback: Read ACKs from JSONL files
- FileIncidentSource: Read incidents from CSV files
- FileActionSource: Read actions from CSV files
- FileMetricsSource: Read metrics from CSV files
- FileStateSource: Read component state from CSV files
- SimulatedStateProvider: State from emulator WorldState

How it works:
    Emulator (events) -> FileEventSink -> events.jsonl
    events.jsonl -> FileEventSource -> Analyzer -> FileActionSink -> actions.jsonl
    Analyzer -> incidents.csv, actions.csv, state.csv
    Dashboard <- FileIncidentSource, FileActionSource, FileStateSource

When real SmartEnergy infrastructure is available:
    Replace File* adapters with Kafka*, Scada*, Soar*, Siem* adapters.
    The interfaces allow swapping data sources without changing business logic.
"""

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
