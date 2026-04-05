"""Тести генераторів шуму та атак-сценаріїв (форма/якість/межі)."""

from __future__ import annotations

import random
from datetime import UTC, datetime

import pytest

from src.contracts.event import Event
from src.emulator.devices import Device
from src.emulator.noise import (
    AccessGenerator,
    AuthGenerator,
    SystemHealthGenerator,
    TelemetryGenerator,
)
from src.emulator.scenarios.brute_force import BruteForceScenario
from src.emulator.scenarios.ddos_abuse import DDoSAbuseScenario
from src.emulator.scenarios.network_failure import NetworkFailureScenario
from src.emulator.scenarios.outage import OutageScenario
from src.emulator.scenarios.telemetry_spoof import TelemetrySpoofScenario
from src.emulator.scenarios.unauthorized_cmd import UnauthorizedCmdScenario
from src.shared.severity import SEV_ORDER
from src.shared.time_utils import parse_iso_ts


def _devices() -> dict[str, Device]:
    return {
        "api-gw-01": Device(id="api-gw-01", ip="10.0.0.10", component="api", protocols=["http"]),
        "gateway-01": Device(
            id="gateway-01", ip="10.0.0.11", component="gateway", protocols=["http"]
        ),
        "db-primary": Device(id="db-primary", ip="10.0.0.20", component="db", protocols=["tcp"]),
        "switch-core-01": Device(
            id="switch-core-01", ip="10.0.0.30", component="network", protocols=["snmp"]
        ),
        "meter-17": Device(id="meter-17", ip="10.0.0.40", component="edge", protocols=["modbus"]),
        "scada-hmi-01": Device(
            id="scada-hmi-01", ip="10.0.0.50", component="collector", protocols=["opcua"]
        ),
        "firewall-01": Device(
            id="firewall-01", ip="10.0.0.60", component="network", protocols=["snmp"]
        ),
    }


def _assert_event_contract(ev: Event):
    assert ev.timestamp
    assert ev.source
    assert ev.component
    assert ev.event
    assert ev.key
    assert ev.severity in SEV_ORDER
    parse_iso_ts(ev.timestamp)


@pytest.mark.parametrize(
    "gen_cls,cfg",
    [
        (
            TelemetryGenerator,
            {
                "sources": ["meter-17"],
                "component": ["edge"],
                "keys": [{"key": "voltage", "range": [210.0, 240.0], "unit": "V"}],
                "interval_sec": [1, 1],
                "severity": "low",
                "tags": ["telemetry"],
            },
        ),
        (
            AccessGenerator,
            {
                "sources": ["api-gw-01"],
                "component": ["api"],
                "actors": ["operator"],
                "keys": [{"key": "endpoint", "values": ["/api/v1/health"]}],
                "interval_sec": [1, 1],
                "severity": "low",
                "tags": ["api"],
            },
        ),
        (
            AuthGenerator,
            {
                "sources": ["gateway-01"],
                "component": ["gateway"],
                "actors": ["admin"],
                "keys": [{"key": "method", "values": ["password"]}],
                "interval_sec": [1, 1],
                "severity": "low",
                "tags": ["auth"],
            },
        ),
        (
            SystemHealthGenerator,
            {
                "sources": ["db-primary"],
                "component": ["db"],
                "keys": [{"key": "status", "values": ["healthy"]}],
                "interval_sec": [1, 1],
                "severity": "low",
                "tags": ["health"],
            },
        ),
    ],
)
def test_noise_generators_emit_valid_events(gen_cls, cfg):
    rng = random.Random(42)
    gen = gen_cls(cfg, _devices(), rng)
    now = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)

    events = gen.generate(now, offset_sec=10.0)
    assert events

    for ev in events:
        _assert_event_contract(ev)


@pytest.mark.parametrize(
    "scenario_cls,cfg,expected_event",
    [
        (
            BruteForceScenario,
            {
                "target_sources": ["gateway-01"],
                "target_components": ["gateway"],
                "schedule": {"start_offset_sec": [1, 1], "duration_sec": [10, 10]},
                "correlation_prefix": "COR-BF",
                "injection": [
                    {
                        "event": "auth_failure",
                        "count": [12, 12],
                        "interval_ms": [1, 1],
                        "ip_pool": ["10.1.1.1"],
                        "actor": "unknown",
                        "severity_progression": [
                            {"threshold": 0, "severity": "high"},
                            {"threshold": 10, "severity": "critical"},
                        ],
                        "keys": [{"key": "username", "values": ["admin"]}],
                        "tags": ["auth", "failure"],
                    }
                ],
            },
            "auth_failure",
        ),
        (
            DDoSAbuseScenario,
            {
                "target_sources": ["api-gw-01"],
                "target_components": ["api"],
                "schedule": {"start_offset_sec": [1, 1], "duration_sec": [10, 10]},
                "correlation_prefix": "COR-DD",
                "injection": [
                    {
                        "event": "rate_exceeded",
                        "count": [4, 4],
                        "interval_ms": [1, 1],
                        "source_pool": ["api-gw-01"],
                        "ip_pool": ["203.0.113.10"],
                        "keys": [{"key": "rps", "range": [1000, 1200], "unit": "req/s"}],
                        "severity": "critical",
                        "tags": ["flood"],
                    }
                ],
            },
            "rate_exceeded",
        ),
        (
            TelemetrySpoofScenario,
            {
                "target_sources": ["meter-17"],
                "target_components": ["edge"],
                "schedule": {"start_offset_sec": [1, 1], "duration_sec": [10, 10]},
                "correlation_prefix": "COR-SP",
                "injection": [
                    {
                        "event": "telemetry_read",
                        "count": [3, 3],
                        "interval_ms": [1, 1],
                        "keys": [{"key": "voltage", "range": [500.0, 700.0], "unit": "V"}],
                        "severity": "low",
                        "tags": ["telemetry"],
                    }
                ],
            },
            "telemetry_read",
        ),
        (
            UnauthorizedCmdScenario,
            {
                "target_sources": ["scada-hmi-01"],
                "target_components": ["collector"],
                "schedule": {"start_offset_sec": [1, 1], "duration_sec": [10, 10]},
                "correlation_prefix": "COR-UC",
                "injection": [
                    {
                        "event": "cmd_exec",
                        "count": [2, 2],
                        "interval_ms": [1, 1],
                        "actor_pool": ["guest"],
                        "ip_pool": ["10.2.2.2"],
                        "keys": [{"key": "command", "values": ["breaker_open"]}],
                        "severity": "critical",
                        "tags": ["cmd"],
                    }
                ],
            },
            "cmd_exec",
        ),
        (
            OutageScenario,
            {
                "target_sources": ["db-primary"],
                "target_components": ["db"],
                "schedule": {"start_offset_sec": [1, 1], "duration_sec": [10, 10]},
                "correlation_prefix": "COR-OUT",
                "injection": [
                    {
                        "event": "db_error",
                        "count": [2, 2],
                        "interval_ms": [1, 1],
                        "source_pool": ["db-primary"],
                        "keys": [{"key": "error_type", "values": ["checksum_mismatch"]}],
                        "severity": "critical",
                        "tags": ["db"],
                    }
                ],
            },
            "db_error",
        ),
        (
            NetworkFailureScenario,
            {
                "target_sources": ["switch-core-01"],
                "target_components": ["network"],
                "schedule": {"start_offset_sec": [1, 1], "duration_sec": [10, 10]},
                "correlation_prefix": "COR-NET",
                "injection": [
                    {
                        "event": "service_status",
                        "count": [2, 2],
                        "interval_ms": [1, 1],
                        "source_pool": ["switch-core-01"],
                        "keys": [{"key": "status", "values": ["down"]}],
                        "severity": "critical",
                        "tags": ["network"],
                    }
                ],
            },
            "service_status",
        ),
    ],
)
def test_attack_scenarios_generate_expected_shape_and_bounds(scenario_cls, cfg, expected_event):
    rng = random.Random(42)
    scenario = scenario_cls(
        cfg=cfg,
        devices=_devices(),
        rng=rng,
        sim_start=datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC),
        sim_duration_sec=120,
    )

    events = scenario.generate()
    assert events
    assert all(e.event == expected_event for e in events)

    for ev in events:
        _assert_event_contract(ev)
        assert ev.correlation_id

    # Специфічні перевірки меж для числових payload.
    if scenario_cls is DDoSAbuseScenario:
        for ev in events:
            assert 1000 <= float(ev.value) <= 1200

    if scenario_cls is TelemetrySpoofScenario:
        for ev in events:
            assert 500.0 <= float(ev.value) <= 700.0

    if scenario_cls is BruteForceScenario:
        assert len(events) == 12
        assert any(e.severity == "critical" for e in events)
        assert any("escalated" in e.tags for e in events if e.severity == "critical")


def test_mix_noise_and_attack_events_keep_event_quality():
    rng = random.Random(7)
    devices = _devices()

    noise = TelemetryGenerator(
        {
            "sources": ["meter-17"],
            "component": ["edge"],
            "keys": [{"key": "voltage", "range": [210.0, 240.0], "unit": "V"}],
            "interval_sec": [1, 1],
            "severity": "low",
            "tags": ["telemetry"],
        },
        devices,
        rng,
    )

    scenario = NetworkFailureScenario(
        cfg={
            "target_sources": ["switch-core-01"],
            "target_components": ["network"],
            "schedule": {"start_offset_sec": [1, 1], "duration_sec": [10, 10]},
            "injection": [
                {
                    "event": "service_status",
                    "count": [3, 3],
                    "interval_ms": [1, 1],
                    "source_pool": ["switch-core-01"],
                    "keys": [{"key": "status", "values": ["degraded", "down"]}],
                    "severity": "high",
                    "tags": ["network"],
                }
            ],
        },
        devices=devices,
        rng=rng,
        sim_start=datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC),
        sim_duration_sec=120,
    )

    events = []
    events.extend(noise.generate(datetime(2026, 3, 1, 12, 0, 5, tzinfo=UTC), offset_sec=10.0))
    events.extend(scenario.generate())

    assert len(events) >= 4
    assert any(e.event == "telemetry_read" for e in events)
    assert any(e.event == "service_status" for e in events)

    for ev in events:
        _assert_event_contract(ev)
        # Мікс не має деградувати до порожніх значень payload.
        assert str(ev.value) != ""
