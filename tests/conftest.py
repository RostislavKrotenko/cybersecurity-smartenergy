"""Фікстури для тестів."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.contracts.alert import Alert
from src.contracts.event import Event
from src.contracts.incident import Incident

_COMPONENT_MARKERS_BY_FILE: dict[str, tuple[str, ...]] = {
    "test_actions_loop.py": (
        "component_analyzer",
        "component_contracts",
        "component_emulator",
        "component_pipeline",
    ),
    "test_api_endpoints.py": ("component_api", "component_contracts"),
    "test_cli_and_reporter.py": (
        "component_analyzer",
        "component_api",
        "component_emulator",
        "component_normalizer",
    ),
    "test_closed_loop.py": (
        "component_analyzer",
        "component_contracts",
        "component_emulator",
        "component_pipeline",
    ),
    "test_contracts.py": ("component_contracts",),
    "test_correlator.py": ("component_analyzer",),
    "test_db_restore.py": ("component_db", "component_emulator"),
    "test_detector.py": ("component_analyzer",),
    "test_emulator.py": ("component_contracts", "component_emulator"),
    "test_file_adapter_resilience.py": ("component_adapters", "component_contracts"),
    "test_filters.py": ("component_normalizer",),
    "test_hybrid_and_interfaces.py": (
        "component_adapters",
        "component_contracts",
        "component_emulator",
    ),
    "test_integration_contract_v1.py": ("component_contracts", "component_shared"),
    "test_integration.py": ("component_analyzer", "component_pipeline"),
    "test_integration_modes.py": ("component_analyzer", "component_pipeline", "component_shared"),
    "test_jsonl_live.py": (
        "component_analyzer",
        "component_emulator",
        "component_pipeline",
    ),
    "test_metrics.py": ("component_analyzer",),
    "test_noise_and_scenarios.py": ("component_emulator", "component_shared"),
    "test_normalizer_pipeline.py": ("component_normalizer", "component_pipeline"),
    "test_normalizer.py": ("component_contracts", "component_normalizer"),
    "test_parser.py": ("component_contracts", "component_normalizer"),
    "test_policy_engine.py": ("component_analyzer",),
    "test_reliability.py": ("component_shared", "component_contracts"),
    "test_adapter_certification.py": ("component_adapters", "component_contracts"),
    "test_analyzer_pipeline_helpers.py": (
        "component_analyzer",
        "component_pipeline",
        "component_contracts",
    ),
    "test_emulator_engine_helpers.py": ("component_emulator", "component_contracts"),
    "test_file_adapter_interfaces.py": (
        "component_adapters",
        "component_contracts",
        "component_emulator",
    ),
    "test_shared_utils_extra.py": ("component_shared",),
    "test_smoke_ci.py": ("component_adapters", "component_analyzer", "component_api"),
    "test_state_store.py": ("component_analyzer", "component_emulator"),
}

_TYPE_MARKERS_BY_FILE: dict[str, tuple[str, ...]] = {
    "test_actions_loop.py": ("type_integration", "type_e2e"),
    "test_api_endpoints.py": ("type_api", "type_integration"),
    "test_cli_and_reporter.py": ("type_cli", "type_unit"),
    "test_closed_loop.py": ("type_integration", "type_e2e"),
    "test_contracts.py": ("type_contract", "type_unit"),
    "test_correlator.py": ("type_unit",),
    "test_db_restore.py": ("type_integration", "type_e2e"),
    "test_detector.py": ("type_unit",),
    "test_emulator_engine_helpers.py": ("type_unit",),
    "test_emulator.py": ("type_unit",),
    "test_file_adapter_resilience.py": ("type_resilience", "type_unit"),
    "test_file_adapter_interfaces.py": ("type_unit",),
    "test_filters.py": ("type_unit",),
    "test_hybrid_and_interfaces.py": ("type_contract", "type_unit"),
    "test_analyzer_pipeline_helpers.py": ("type_unit", "type_resilience"),
    "test_integration_contract_v1.py": ("type_contract", "type_unit"),
    "test_integration.py": ("type_integration",),
    "test_integration_modes.py": ("type_integration", "type_resilience"),
    "test_jsonl_live.py": ("type_integration",),
    "test_metrics.py": ("type_unit",),
    "test_noise_and_scenarios.py": ("type_unit",),
    "test_normalizer_pipeline.py": ("type_integration",),
    "test_normalizer.py": ("type_unit",),
    "test_parser.py": ("type_unit",),
    "test_policy_engine.py": ("type_unit",),
    "test_reliability.py": ("type_unit", "type_resilience"),
    "test_adapter_certification.py": ("type_contract", "type_integration"),
    "test_shared_utils_extra.py": ("type_unit",),
    "test_smoke_ci.py": ("type_integration", "type_smoke"),
    "test_state_store.py": ("type_unit",),
}

_SPECIAL_MARKERS_BY_FILE: dict[str, tuple[str, ...]] = {
    "test_db_restore.py": ("external", "slow"),
}

_PRIORITY_MARKERS = {"priority_p0", "priority_p1", "priority_p2", "priority_p3"}


def _item_file_name(item: pytest.Item) -> str:
    path = getattr(item, "path", None)
    if path is not None:
        return path.name
    return Path(str(item.fspath)).name


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    del config
    for item in items:
        file_name = _item_file_name(item)

        for marker in _COMPONENT_MARKERS_BY_FILE.get(file_name, ()):
            item.add_marker(marker)
        for marker in _TYPE_MARKERS_BY_FILE.get(file_name, ()):
            item.add_marker(marker)
        for marker in _SPECIAL_MARKERS_BY_FILE.get(file_name, ()):
            item.add_marker(marker)

        marker_names = {mark.name for mark in item.iter_markers()}
        if marker_names.intersection(_PRIORITY_MARKERS):
            continue

        if "type_smoke" in marker_names:
            item.add_marker("priority_p0")
            continue
        if "external" in marker_names or "slow" in marker_names:
            item.add_marker("priority_p3")
            continue
        if marker_names.intersection(
            {"type_integration", "type_api", "type_contract", "type_resilience"}
        ):
            item.add_marker("priority_p1")
            continue

        item.add_marker("priority_p2")


def make_event(
    *,
    timestamp: str = "2026-02-26T10:00:00Z",
    source: str = "api-gw-01",
    component: str = "api",
    event: str = "raw_log",
    key: str = "message",
    value: str = "",
    severity: str = "low",
    actor: str = "",
    ip: str = "",
    unit: str = "",
    tags: str = "",
    correlation_id: str = "",
) -> Event:
    return Event(
        timestamp=timestamp,
        source=source,
        component=component,
        event=event,
        key=key,
        value=value,
        severity=severity,
        actor=actor,
        ip=ip,
        unit=unit,
        tags=tags,
        correlation_id=correlation_id,
    )


def make_alert(
    *,
    alert_id: str = "ALR-0001",
    rule_id: str = "RULE-BF-001",
    rule_name: str = "Brute-Force Authentication",
    threat_type: str = "credential_attack",
    severity: str = "high",
    confidence: float = 0.85,
    timestamp: str = "2026-02-26T10:00:00Z",
    component: str = "api",
    source: str = "api-gw-01",
    description: str = "test alert",
    event_count: int = 5,
    event_ids: str = "COR-001",
    response_hint: str = "block_ip",
) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        rule_name=rule_name,
        threat_type=threat_type,
        severity=severity,
        confidence=confidence,
        timestamp=timestamp,
        component=component,
        source=source,
        description=description,
        event_count=event_count,
        event_ids=event_ids,
        response_hint=response_hint,
    )


def make_incident(
    *,
    incident_id: str = "INC-001",
    policy: str = "baseline",
    threat_type: str = "credential_attack",
    severity: str = "high",
    component: str = "api",
    event_count: int = 5,
    start_ts: str = "2026-02-26T10:00:00Z",
    detect_ts: str = "2026-02-26T10:00:30Z",
    recover_ts: str = "2026-02-26T10:02:30Z",
    mttd_sec: float = 30.0,
    mttr_sec: float = 120.0,
    impact_score: float = 0.6,
    description: str = "test incident",
    response_action: str = "block_ip",
) -> Incident:
    return Incident(
        incident_id=incident_id,
        policy=policy,
        threat_type=threat_type,
        severity=severity,
        component=component,
        event_count=event_count,
        start_ts=start_ts,
        detect_ts=detect_ts,
        recover_ts=recover_ts,
        mttd_sec=mttd_sec,
        mttr_sec=mttr_sec,
        impact_score=impact_score,
        description=description,
        response_action=response_action,
    )


def ts_offset(base: str = "2026-02-26T10:00:00Z", seconds: int = 0) -> str:
    """Повертає ISO-8601 timestamp зі зсувом в секундах."""
    dt = datetime.fromisoformat(base.replace("Z", "+00:00"))
    dt += timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def brute_force_rule() -> dict:
    """Мінімальна конфігурація brute-force правила."""
    return {
        "rules": [
            {
                "id": "RULE-BF-001",
                "name": "Brute-Force Authentication",
                "threat_type": "credential_attack",
                "enabled": True,
                "match": {"event": "auth_failure", "group_by": ["ip", "source"]},
                "window_sec": 60,
                "threshold": 5,
                "severity": "high",
                "confidence": 0.85,
                "response_hint": "block_ip",
            }
        ]
    }


@pytest.fixture
def ddos_rule() -> dict:
    """Мінімальна конфігурація DDoS правила."""
    return {
        "rules": [
            {
                "id": "RULE-DDOS-001",
                "name": "DDoS / API Rate Flood",
                "threat_type": "availability_attack",
                "enabled": True,
                "match": {"event": "rate_exceeded", "group_by": ["source"]},
                "window_sec": 30,
                "threshold": 10,
                "severity": "critical",
                "confidence": 0.90,
                "response_hint": "rate_limit_ip_range",
            }
        ]
    }


@pytest.fixture
def spoof_rule() -> dict:
    """Мінімальна конфігурація spoof правила."""
    return {
        "rules": [
            {
                "id": "RULE-SPOOF-001",
                "name": "Telemetry Value Anomaly",
                "threat_type": "integrity_attack",
                "enabled": True,
                "match": {"event": "telemetry_read", "group_by": ["source", "key"]},
                "bounds": {
                    "voltage": {"min": 180.0, "max": 280.0},
                    "power_kw": {"min": -10.0, "max": 100.0},
                },
                "delta": {"voltage": 50.0, "power_kw": 30.0},
                "window_sec": 60,
                "threshold": 3,
                "severity": "medium",
                "confidence": 0.75,
                "response_hint": "flag_for_review",
            }
        ]
    }


@pytest.fixture
def unauthorized_cmd_rule() -> dict:
    """Мінімальна конфігурація unauthorized cmd правила."""
    return {
        "rules": [
            {
                "id": "RULE-UCMD-001",
                "name": "Unauthorized Command Execution",
                "threat_type": "integrity_attack",
                "enabled": True,
                "match": {
                    "event": "cmd_exec",
                    "actor_not_in": ["operator", "admin"],
                },
                "window_sec": 120,
                "threshold": 1,
                "severity": "critical",
                "confidence": 0.95,
                "response_hint": "block_actor_and_alert",
            }
        ]
    }


@pytest.fixture
def network_failure_rule() -> dict:
    """Мінімальна конфігурація network failure правила."""
    return {
        "rules": [
            {
                "id": "RULE-NET-001",
                "name": "Network Failure Detection",
                "threat_type": "network_failure",
                "enabled": True,
                "match": {
                    "event": "service_status",
                    "key": "status",
                    "values": ["degraded", "down", "packet_loss", "timeout", "unreachable"],
                    "component": "network",
                    "group_by": ["source"],
                },
                "window_sec": 60,
                "threshold": 2,
                "severity": "high",
                "confidence": 0.88,
                "severity_override": [
                    {"value": "down", "severity": "critical"},
                    {"value": "unreachable", "severity": "critical"},
                ],
                "response_hint": "reset_network",
            }
        ]
    }


@pytest.fixture
def outage_rule() -> dict:
    """Мінімальна конфігурація outage правила."""
    return {
        "rules": [
            {
                "id": "RULE-OUT-001",
                "name": "Service Outage Detection",
                "threat_type": "outage",
                "enabled": True,
                "match": {
                    "event": "service_status",
                    "key": "status",
                    "values": ["degraded", "down"],
                    "group_by": ["source"],
                },
                "window_sec": 60,
                "threshold": 1,
                "severity": "high",
                "confidence": 0.90,
                "severity_override": [{"value": "down", "severity": "critical"}],
                "response_hint": "notify_oncall",
            }
        ]
    }
