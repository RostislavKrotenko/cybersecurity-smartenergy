"""Тести стійкості file-based адаптерів до truncate/rotation і битих рядків."""

from __future__ import annotations

from pathlib import Path

from src.adapters.file_adapter import FileActionFeedback, FileEventSource
from src.contracts.action import ActionAck
from src.contracts.event import Event


def _event_json_line(ts: str, value: str) -> str:
    ev = Event(
        timestamp=ts,
        source="api-gw-01",
        component="api",
        event="http_request",
        key="endpoint",
        value=value,
        severity="low",
    )
    return ev.to_json()


def test_file_event_source_repeated_read_and_bad_lines(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    src = FileEventSource(str(path))

    path.write_text(_event_json_line("2026-01-01T00:00:00Z", "/a") + "\n", encoding="utf-8")

    first = src._read_new_lines()
    assert len(first) == 1
    assert first[0].value == "/a"

    second = src._read_new_lines()
    assert second == []

    with path.open("a", encoding="utf-8") as fh:
        fh.write("{bad-json}\n")
        fh.write(_event_json_line("2026-01-01T00:00:01Z", "/b") + "\n")

    third = src._read_new_lines()
    assert len(third) == 1
    assert third[0].value == "/b"


def test_file_event_source_handles_truncate_then_reads_new_data(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    src = FileEventSource(str(path))

    path.write_text(_event_json_line("2026-01-01T00:00:00Z", "v1") + "\n", encoding="utf-8")
    events = src._read_new_lines()
    assert len(events) == 1
    old_offset = src.get_offset()
    assert old_offset > 0

    # Симулюємо ротацію/транкацію: спочатку обнуляємо файл, потім пишемо нову подію.
    path.write_text("", encoding="utf-8")
    with path.open("a", encoding="utf-8") as fh:
        fh.write(_event_json_line("2026-01-01T00:00:02Z", "v2") + "\n")

    events_after_truncate = src._read_new_lines()
    assert len(events_after_truncate) == 1
    assert events_after_truncate[0].value == "v2"


def test_file_action_feedback_handles_bad_lines_and_truncate(tmp_path: Path):
    path = tmp_path / "actions_applied.jsonl"
    fb = FileActionFeedback(str(path))

    ack1 = ActionAck(
        action_id="ACT-0001",
        correlation_id="INC-001",
        target_component="api",
        action="isolate_component",
        applied_ts_utc="2026-01-01T00:00:01Z",
        result="success",
        state_event="isolation_enabled",
    )
    path.write_text(ack1.to_json() + "\n", encoding="utf-8")

    acks, off = fb.read_acks()
    assert len(acks) == 1
    assert acks[0].action_id == "ACT-0001"

    with path.open("a", encoding="utf-8") as fh:
        fh.write("not-json\n")
        fh.write(
            ActionAck(
                action_id="ACT-0002",
                correlation_id="INC-002",
                target_component="db",
                action="restore_db",
                applied_ts_utc="2026-01-01T00:00:02Z",
                result="failed",
                error="restore_failed",
            ).to_json()
            + "\n"
        )

    acks2, off2 = fb.read_acks(since=off)
    assert len(acks2) == 1
    assert acks2[0].action_id == "ACT-0002"

    # Транкація: новий файл з новим ACK.
    ack3 = ActionAck(
        action_id="ACT-0003",
        correlation_id="INC-003",
        target_component="network",
        action="reset_network",
        applied_ts_utc="2026-01-01T00:00:03Z",
        result="success",
        state_event="network_reset_applied",
    )
    path.write_text(ack3.to_json() + "\n", encoding="utf-8")

    acks3, _ = fb.read_acks(since=off2)
    assert len(acks3) == 1
    assert acks3[0].action_id == "ACT-0003"
