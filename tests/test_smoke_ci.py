"""Стабільний smoke-набір для CI без зовнішніх залежностей (DB/network services)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from src.adapters.file_adapter import FileEventSink, FileEventSource
from src.analyzer.correlator import correlate
from src.analyzer.detector import detect
from src.analyzer.metrics import compute
from src.api.main import app
from tests.conftest import make_event


def test_smoke_closed_loop_core_without_external_services():
    rules_cfg = {
        "rules": [
            {
                "id": "RULE-BF-001",
                "name": "Brute-Force Authentication",
                "threat_type": "credential_attack",
                "enabled": True,
                "match": {"event": "auth_failure"},
                "window_sec": 60,
                "threshold": 3,
                "severity": "high",
                "confidence": 0.85,
                "response_hint": "block_actor",
            }
        ]
    }

    events = [
        make_event(event="auth_failure", timestamp=f"2026-03-01T10:00:0{i}Z", ip="10.0.0.1")
        for i in range(3)
    ]

    alerts = detect(events, rules_cfg)
    incidents = correlate(alerts, "baseline")
    metrics = compute(incidents, "baseline", horizon_sec=3600)

    assert len(alerts) >= 1
    assert len(incidents) >= 1
    assert metrics.incidents_total >= 1


def test_smoke_file_event_source_sink_roundtrip(tmp_path: Path):
    out = tmp_path / "events.jsonl"

    sink = FileEventSink(str(out))
    sink.emit(
        make_event(
            timestamp="2026-03-01T10:00:00Z",
            source="api-gw-01",
            component="api",
            event="http_request",
            key="endpoint",
            value="/api/v1/health",
            severity="low",
        )
    )
    sink.close()

    source = FileEventSource(str(out))
    batch = source.read_batch(limit=10)
    assert len(batch) == 1
    assert batch[0].event == "http_request"


def test_smoke_api_boot_and_health():
    client = TestClient(app)
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
