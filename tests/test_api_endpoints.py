"""Тести REST API: позитивні/негативні кейси, фільтри, контракт, збої out-файлів."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api import data_provider as dp
from src.api.main import app
from src.api.routes import actions as actions_routes
from src.api.routes import incidents as incidents_routes
from src.api.routes import metrics as metrics_routes
from src.api.routes import state as state_routes
from src.contracts.interfaces import ComponentState


class _StubProvider:
    def __init__(self):
        self._incidents = [
            {
                "incident_id": "INC-001",
                "policy": "baseline",
                "category": "credential_attack",
                "severity": "high",
                "component": "api",
                "start_ts": "2026-03-01T10:00:00Z",
                "detect_ts": "2026-03-01T10:00:10Z",
                "recover_ts": "2026-03-01T10:01:00Z",
                "mttd_sec": 10.0,
                "mttr_sec": 50.0,
                "status": "active",
                "details": {"src": "api-gw-01"},
            },
            {
                "incident_id": "INC-002",
                "policy": "standard",
                "category": "outage",
                "severity": "critical",
                "component": "db",
                "start_ts": "2026-03-01T11:00:00Z",
                "detect_ts": "2026-03-01T11:00:05Z",
                "recover_ts": "2026-03-01T11:02:00Z",
                "mttd_sec": 5.0,
                "mttr_sec": 115.0,
                "status": "resolved",
                "details": {},
            },
        ]
        self._actions = [
            {
                "action_id": "ACT-001",
                "action": "block_actor",
                "target_component": "auth",
                "target_id": "attacker",
                "ts_utc": "2026-03-01T10:00:12Z",
                "reason": "credential_attack",
                "correlation_id": "INC-001",
                "status": "applied",
            },
            {
                "action_id": "ACT-002",
                "action": "restore_db",
                "target_component": "db",
                "target_id": "db-primary",
                "ts_utc": "2026-03-01T11:00:10Z",
                "reason": "outage",
                "correlation_id": "INC-002",
                "status": "failed",
            },
        ]

    def get_incidents(self, limit: int = 10000):
        return self._incidents[:limit]

    def get_incident_count(self) -> int:
        return len(self._incidents)

    def get_actions(self, limit: int = 10000):
        return self._actions[:limit]

    def get_action_summary(self):
        return {"total": 2, "applied": 1, "failed": 1, "emitted": 0, "pending": 0}

    def get_metrics(self):
        return [
            {
                "policy": "baseline",
                "availability_pct": 99.8,
                "total_downtime_hr": 0.1,
                "mean_mttd_min": 1.2,
                "mean_mttr_min": 2.4,
                "incident_count": 1,
            }
        ]

    def get_overall_metrics(self):
        return {
            "total_incidents": 2,
            "total_actions": 2,
            "avg_availability_pct": 99.8,
            "avg_mttd_min": 1.2,
            "avg_mttr_min": 2.4,
        }

    def get_state(self):
        return [
            ComponentState(component_id="api", component_type="api", status="healthy", details={}),
            ComponentState(component_id="db", component_type="db", status="degraded", details={}),
        ]

    def get_component_state(self, component_id: str):
        for s in self.get_state():
            if s.component_id == component_id:
                return s
        return None

    def is_actor_blocked(self, actor: str) -> bool:
        return actor == "attacker"

    def is_component_isolated(self, component_id: str) -> bool:
        return component_id == "api"


@pytest.fixture
def api_client(monkeypatch):
    provider = _StubProvider()
    monkeypatch.setattr(incidents_routes, "get_provider", lambda: provider)
    monkeypatch.setattr(actions_routes, "get_provider", lambda: provider)
    monkeypatch.setattr(state_routes, "get_provider", lambda: provider)
    monkeypatch.setattr(metrics_routes, "get_provider", lambda: provider)
    return TestClient(app)


def test_health_and_root_endpoints(api_client: TestClient):
    r = api_client.get("/")
    assert r.status_code == 200
    assert r.json()["docs"] == "/api/docs"

    r2 = api_client.get("/api/health")
    assert r2.status_code == 200
    assert r2.json()["status"] == "ok"

    r3 = api_client.get("/healthz")
    assert r3.status_code == 200
    assert r3.json() == {"status": "ok"}


def test_incidents_positive_filters_and_contract(api_client: TestClient):
    r = api_client.get("/api/incidents", params={"limit": 10, "severity": "critical"})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["incident_id"] == "INC-002"
    assert isinstance(item["details"], dict)
    assert isinstance(item["mttd_sec"], float)

    count = api_client.get("/api/incidents/count")
    assert count.status_code == 200
    assert count.json()["count"] == 2


def test_incidents_invalid_params(api_client: TestClient):
    r = api_client.get("/api/incidents", params={"limit": 0})
    assert r.status_code == 422


def test_actions_positive_filters_and_contract(api_client: TestClient):
    r = api_client.get("/api/actions", params={"status": "applied", "component": "auth"})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["summary"]["failed"] == 1
    item = body["items"][0]
    assert item["action_id"] == "ACT-001"
    assert item["status"] == "applied"

    summary = api_client.get("/api/actions/summary")
    assert summary.status_code == 200
    assert summary.json()["total"] == 2


def test_actions_invalid_params(api_client: TestClient):
    r = api_client.get("/api/actions", params={"limit": 10001})
    assert r.status_code == 422


def test_state_positive_and_negative_cases(api_client: TestClient):
    r = api_client.get("/api/state")
    assert r.status_code == 200
    body = r.json()
    assert len(body["components"]) == 2

    comp = api_client.get("/api/state/components/api")
    assert comp.status_code == 200
    assert comp.json()["status"] == "healthy"

    not_found = api_client.get("/api/state/components/unknown")
    assert not_found.status_code == 404

    blocked = api_client.get("/api/state/actors/attacker/blocked")
    assert blocked.status_code == 200
    assert blocked.json()["blocked"] is True

    isolated = api_client.get("/api/state/components/api/isolated")
    assert isolated.status_code == 200
    assert isolated.json()["isolated"] is True


def test_metrics_endpoints(api_client: TestClient):
    r = api_client.get("/api/metrics")
    assert r.status_code == 200
    body = r.json()
    assert len(body["by_policy"]) == 1
    assert body["overall"]["total_incidents"] == 2

    by_policy = api_client.get("/api/metrics/by-policy")
    assert by_policy.status_code == 200
    assert by_policy.json()[0]["policy"] == "baseline"

    overall = api_client.get("/api/metrics/overall")
    assert overall.status_code == 200
    assert overall.json()["avg_mttr_min"] == 2.4


def test_data_provider_missing_out_files_returns_safe_defaults(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(dp, "INCIDENTS_PATH", tmp_path / "missing_incidents.csv")
    monkeypatch.setattr(dp, "ACTIONS_PATH", tmp_path / "missing_actions.csv")
    monkeypatch.setattr(dp, "RESULTS_PATH", tmp_path / "missing_results.csv")
    monkeypatch.setattr(dp, "STATE_PATH", tmp_path / "missing_state.csv")

    provider = dp.APIDataProvider()
    assert provider.get_incidents() == []
    assert provider.get_incident_count() == 0
    assert provider.get_actions() == []
    assert provider.get_action_summary()["total"] == 0
    assert provider.get_metrics() == []
    assert provider.get_overall_metrics() == {}
    assert provider.get_state() == []


def test_data_provider_corrupted_out_files_does_not_crash(monkeypatch, tmp_path: Path):
    incidents = tmp_path / "incidents.csv"
    actions = tmp_path / "actions.csv"
    results = tmp_path / "results.csv"
    state = tmp_path / "state.csv"

    incidents.write_text('incident_id,policy\n"unterminated\n', encoding="utf-8")
    actions.write_text('action_id,status\n"unterminated\n', encoding="utf-8")
    results.write_text('policy,availability\n"unterminated\n', encoding="utf-8")
    state.write_text('component,status,details\n"unterminated\n', encoding="utf-8")

    monkeypatch.setattr(dp, "INCIDENTS_PATH", incidents)
    monkeypatch.setattr(dp, "ACTIONS_PATH", actions)
    monkeypatch.setattr(dp, "RESULTS_PATH", results)
    monkeypatch.setattr(dp, "STATE_PATH", state)

    provider = dp.APIDataProvider()

    assert provider.get_incidents() == []
    assert provider.get_actions() == []
    assert provider.get_metrics() == []
    # Для state/counters важливо не впасти.
    assert isinstance(provider.get_incident_count(), int)
    assert isinstance(provider.get_action_summary(), dict)
    assert isinstance(provider.get_state(), list)
