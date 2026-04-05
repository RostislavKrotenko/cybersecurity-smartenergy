"""Тести CLI-аргументів і генерації звітів."""

from __future__ import annotations

import types
from pathlib import Path

import pytest

from src.analyzer import cli as analyzer_cli
from src.analyzer.metrics import PolicyMetrics
from src.analyzer.reporter import (
    write_incidents_csv,
    write_plots,
    write_report_html,
    write_report_txt,
    write_results_csv,
)
from src.contracts.event import Event
from src.emulator import cli as emulator_cli
from src.normalizer import cli as normalizer_cli
from tests.conftest import make_incident


def test_analyzer_build_parser_defaults_and_invalid_choice():
    parser = analyzer_cli.build_parser()
    args = parser.parse_args([])
    assert args.input == "data/events.csv"
    assert args.out_dir == "out"
    assert args.policies == "all"
    assert args.watch is False
    assert args.integration_mode == "active"
    assert args.shadow_actions_path is None

    with pytest.raises(SystemExit):
        parser.parse_args(["--log-level", "INVALID"])


def test_analyzer_main_watch_and_batch_modes(monkeypatch):
    calls: dict[str, object] = {}

    monkeypatch.setattr(analyzer_cli, "setup_logging", lambda *_: None)

    def fake_watch_pipeline(**kwargs):
        calls["watch"] = kwargs

    def fake_create_file_adapters(**kwargs):
        calls["adapters"] = kwargs
        return "EVENT_SOURCE", "ACTION_SINK"

    def fake_run_pipeline_with_adapters(**kwargs):
        calls["run"] = kwargs

    monkeypatch.setattr(analyzer_cli, "watch_pipeline", fake_watch_pipeline)
    monkeypatch.setattr(analyzer_cli, "create_file_adapters", fake_create_file_adapters)
    monkeypatch.setattr(analyzer_cli, "run_pipeline_with_adapters", fake_run_pipeline_with_adapters)

    analyzer_cli.main(
        [
            "--watch",
            "--input",
            "data/live/events.jsonl",
            "--poll-interval-ms",
            "500",
            "--integration-mode",
            "shadow",
            "--shadow-actions-path",
            "out/custom_shadow.csv",
        ]
    )
    assert "watch" in calls
    assert calls["watch"]["input_path"] == "data/live/events.jsonl"
    assert calls["watch"]["poll_interval_sec"] == 0.5
    assert calls["watch"]["integration_mode"] == "shadow"
    assert calls["watch"]["shadow_actions_path"] == "out/custom_shadow.csv"

    calls.clear()
    analyzer_cli.main(
        ["--input", "data/events.csv", "--out-dir", "out", "--integration-mode", "active"]
    )
    assert "adapters" in calls and "run" in calls
    assert calls["run"]["event_source"] == "EVENT_SOURCE"
    assert calls["run"]["integration_mode"] == "active"


def test_normalizer_build_parser_defaults_and_invalid_choice():
    parser = normalizer_cli.build_parser()
    args = parser.parse_args([])
    assert args.inputs == "logs/*.log"
    assert args.mapping == "config/mapping.yaml"
    assert args.follow is False

    with pytest.raises(SystemExit):
        parser.parse_args(["--log-level", "NOPE"])


def test_normalizer_main_follow_and_batch(monkeypatch):
    calls: dict[str, object] = {}

    monkeypatch.setattr(normalizer_cli, "setup_logging", lambda *_: None)

    class FakePipeline:
        def __init__(self, mapping_path: str, tz_name: str):
            calls["init"] = (mapping_path, tz_name)

        def follow(self, *, input_glob: str, out_path: str, poll_interval_sec: float):
            calls["follow"] = {
                "input_glob": input_glob,
                "out_path": out_path,
                "poll_interval_sec": poll_interval_sec,
            }

        def run_with_sink(
            self, *, input_glob: str, event_sink, quarantine_path: str, stats_path: str
        ):
            calls["run_with_sink"] = {
                "input_glob": input_glob,
                "event_sink": event_sink,
                "quarantine_path": quarantine_path,
                "stats_path": stats_path,
            }

    class FakeSink:
        def __init__(self, out: str):
            self.out = out

        def close(self):
            calls["sink_closed"] = True

    monkeypatch.setattr(normalizer_cli, "NormalizerPipeline", FakePipeline)
    monkeypatch.setattr(normalizer_cli, "FileEventSink", FakeSink)

    normalizer_cli.main(["--follow", "--inputs", "logs/live/*.log", "--poll-interval-ms", "250"])
    assert "follow" in calls
    assert calls["follow"]["poll_interval_sec"] == 0.25

    calls.clear()
    normalizer_cli.main(["--inputs", "logs/*.log", "--out", "data/events.jsonl"])
    assert "run_with_sink" in calls
    assert calls.get("sink_closed") is True


def test_emulator_parse_args_defaults_and_invalid_choice():
    args = emulator_cli._parse_args([])
    assert args.seed == 42
    assert args.format == "csv"
    assert args.live is False

    with pytest.raises(SystemExit):
        emulator_cli._parse_args(["--format", "xml"])


def test_emulator_main_routes_batch_and_live_modes(monkeypatch, tmp_path: Path):
    calls: dict[str, object] = {}

    monkeypatch.setattr(emulator_cli, "setup_logging", lambda *_: None)
    monkeypatch.setattr(emulator_cli, "load_yaml", lambda *_: {})

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            calls.setdefault("engine_inits", []).append({"args": args, "kwargs": kwargs})

        def run(self):
            return [
                Event(
                    timestamp="2026-03-01T10:00:00Z",
                    source="api-gw-01",
                    component="api",
                    event="http_request",
                    key="endpoint",
                    value="/health",
                    severity="low",
                )
            ]

    class FakeSink:
        def __init__(self, path: str):
            self.path = path
            calls.setdefault("sink_paths", []).append(path)

        def emit_batch(self, events):
            calls.setdefault("batch_events", []).append(len(events))

        def flush(self):
            calls["sink_flushed"] = True

        def close(self):
            calls.setdefault("sink_closed", 0)
            calls["sink_closed"] += 1

    monkeypatch.setattr(emulator_cli, "EmulatorEngine", FakeEngine)
    monkeypatch.setattr(emulator_cli, "FileEventSink", FakeSink)

    monkeypatch.setattr(
        emulator_cli,
        "stream_to_sink",
        lambda **kwargs: calls.__setitem__("stream_to_sink", kwargs) or 2,
    )
    monkeypatch.setattr(
        emulator_cli,
        "_stream_to_sink_infinite",
        lambda **kwargs: calls.__setitem__("stream_to_sink_infinite", kwargs),
    )
    monkeypatch.setattr(
        emulator_cli,
        "stream_demo_highrate",
        lambda **kwargs: calls.__setitem__("stream_demo_highrate", kwargs),
    )
    monkeypatch.setattr(
        emulator_cli,
        "stream_jsonl",
        lambda **kwargs: calls.__setitem__("stream_jsonl", kwargs) or 3,
    )
    monkeypatch.setattr(
        emulator_cli,
        "stream_jsonl_infinite",
        lambda **kwargs: calls.__setitem__("stream_jsonl_infinite", kwargs),
    )

    # Batch mode -> FileEventSink path + emit_batch
    emulator_cli.main(["--out", str(tmp_path / "batch_events")])
    assert calls["batch_events"][-1] == 1
    assert calls["sink_paths"][-1].endswith(".csv")

    # Live + sink mode + finite max events
    emulator_cli.main(["--live", "--out", str(tmp_path / "live_sink.jsonl"), "--max-events", "5"])
    assert "stream_to_sink" in calls

    # Live + sink mode + infinite stream loop wrapper
    emulator_cli.main(["--live", "--out", str(tmp_path / "live_sink_infinite.jsonl")])
    assert "stream_to_sink_infinite" in calls

    # Live + demo profile path
    emulator_cli.main(
        [
            "--live",
            "--profile",
            "demo_high_rate",
            "--out",
            str(tmp_path / "live_demo.jsonl"),
        ]
    )
    assert "stream_demo_highrate" in calls

    # Live + legacy finite JSONL path (sink_mode=False via raw_log_dir)
    emulator_cli.main(
        [
            "--live",
            "--out",
            str(tmp_path / "live_legacy.jsonl"),
            "--raw-log-dir",
            str(tmp_path / "raw"),
            "--max-events",
            "2",
        ]
    )
    assert "stream_jsonl" in calls

    # Live + legacy infinite JSONL path (sink_mode=False via csv_out)
    emulator_cli.main(
        [
            "--live",
            "--out",
            str(tmp_path / "live_legacy_infinite.jsonl"),
            "--csv-out",
            str(tmp_path / "live.csv"),
        ]
    )
    assert "stream_jsonl_infinite" in calls


def test_api_module_entrypoint_workers_logic(monkeypatch):
    from src.api import __main__ as api_main

    calls: dict[str, object] = {}

    def fake_run(app_path: str, **kwargs):
        calls["app_path"] = app_path
        calls["kwargs"] = kwargs

    fake_uvicorn = types.SimpleNamespace(run=fake_run)

    import sys

    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)
    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "--host", "127.0.0.1", "--port", "9000", "--reload", "--workers", "4"],
    )

    api_main.main()

    assert calls["app_path"] == "src.api.main:app"
    assert calls["kwargs"]["host"] == "127.0.0.1"
    assert calls["kwargs"]["port"] == 9000
    assert calls["kwargs"]["reload"] is True
    assert calls["kwargs"]["workers"] == 1


def test_report_generation_fields_format_and_empty_inputs(tmp_path: Path):
    metrics = [
        PolicyMetrics(
            policy="baseline",
            availability_pct=99.9,
            total_downtime_hr=0.1,
            mean_mttd_min=1.2,
            mean_mttr_min=2.3,
            incidents_total=2,
            incidents_by_severity={"high": 1, "critical": 1},
            incidents_by_threat={"credential_attack": 1, "outage": 1},
        )
    ]
    incidents = [
        make_incident(incident_id="INC-001", severity="high"),
        make_incident(incident_id="INC-002", severity="critical"),
    ]
    ranking = [
        {
            "policy": "baseline",
            "effectiveness": 0.92,
            "avg_mttd_mult": 0.9,
            "avg_mttr_mult": 0.8,
            "enabled_controls": ["mfa", "rate_limit"],
        }
    ]

    results_csv = tmp_path / "results.csv"
    incidents_csv = tmp_path / "incidents.csv"
    report_txt = tmp_path / "report.txt"
    report_html = tmp_path / "report.html"

    write_results_csv(metrics, str(results_csv))
    write_incidents_csv(incidents, str(incidents_csv))
    write_report_txt(metrics, incidents, ranking, str(report_txt), actions_count=5)
    write_report_html(metrics, incidents, ranking, str(report_html))

    assert results_csv.exists()
    assert incidents_csv.exists()
    assert report_txt.exists()
    assert report_html.exists()

    txt = report_txt.read_text(encoding="utf-8")
    assert "SmartEnergy Cyber-Resilience Report" in txt
    assert "Policy: baseline" in txt
    assert "Actions issued:" in txt

    html = report_html.read_text(encoding="utf-8")
    assert "<table" in html
    assert "Policy Comparison" in html
    assert "INC-001" in html

    # Порожні вхідні дані також мають давати валідний звіт.
    empty_txt = tmp_path / "report_empty.txt"
    empty_html = tmp_path / "report_empty.html"
    write_report_txt([], [], [], str(empty_txt))
    write_report_html([], [], [], str(empty_html))
    assert empty_txt.exists() and empty_html.exists()


def test_report_plots_are_generated(tmp_path: Path):
    metrics = [
        PolicyMetrics(
            policy="baseline",
            availability_pct=99.9,
            total_downtime_hr=0.1,
            mean_mttd_min=1.2,
            mean_mttr_min=2.3,
            incidents_total=2,
            incidents_by_severity={"high": 1, "critical": 1},
            incidents_by_threat={"credential_attack": 1, "outage": 1},
        ),
        PolicyMetrics(
            policy="hardening",
            availability_pct=99.5,
            total_downtime_hr=0.3,
            mean_mttd_min=2.0,
            mean_mttr_min=4.0,
            incidents_total=3,
            incidents_by_severity={"high": 2, "critical": 1},
            incidents_by_threat={"availability_attack": 2, "outage": 1},
        ),
    ]

    write_plots(metrics, str(tmp_path))

    assert (tmp_path / "plots" / "availability.png").exists()
    assert (tmp_path / "plots" / "downtime.png").exists()
    assert (tmp_path / "plots" / "mttd_mttr.png").exists()
