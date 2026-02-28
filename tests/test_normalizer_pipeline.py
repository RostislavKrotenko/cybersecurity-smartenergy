"""Tests for src.normalizer.pipeline — NormalizerPipeline orchestrator."""

from __future__ import annotations

import csv
import json
from datetime import UTC
from pathlib import Path

import pytest

from src.normalizer.pipeline import NormalizerPipeline, _resolve_tz

# ═══════════════════════════════════════════════════════════════════════════
#  _resolve_tz
# ═══════════════════════════════════════════════════════════════════════════

class TestResolveTz:
    def test_utc(self):
        tz = _resolve_tz("UTC")
        assert tz == UTC

    def test_named_timezone(self):
        tz = _resolve_tz("Europe/Kyiv")
        assert str(tz) == "Europe/Kyiv"


# ═══════════════════════════════════════════════════════════════════════════
#  NormalizerPipeline — integration tests with real file I/O
# ═══════════════════════════════════════════════════════════════════════════

class TestNormalizerPipeline:
    """Integration tests that run the pipeline over temporary files."""

    @pytest.fixture
    def tmp_dirs(self, tmp_path):
        """Create temp input/output directories."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        out_dir = tmp_path / "output"
        out_dir.mkdir()
        return input_dir, out_dir

    @pytest.fixture
    def minimal_mapping(self, tmp_path):
        """Write a minimal mapping.yaml and return its path."""
        mapping = {
            "defaults": {
                "source": "unknown",
                "component": "unknown",
                "event": "raw_log",
                "severity": "low",
            },
            "normalizer": {
                "dedup": {"enabled": False, "window_sec": 2},
            },
            "profiles": {
                "api": {
                    "file_pattern": "api",
                    "line_regex": r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<level>\w+)\s+(?P<host>\S+)\s+(?P<msg>.+)$',
                    "timestamp_format": "iso_space",
                    "source_field": "host",
                    "level_field": "level",
                    "message_field": "msg",
                    "severity_map": {"info": "low", "warn": "medium", "error": "high"},
                    "event_rules": [
                        {"pattern": r"GET|POST", "event": "http_request", "tags": "api"},
                    ],
                    "component_rules": [
                        {"pattern": "api", "component": "api"},
                    ],
                },
            },
        }
        import yaml
        path = tmp_path / "mapping.yaml"
        with open(path, "w") as f:
            yaml.dump(mapping, f)
        return str(path)

    def test_run_with_valid_input(self, tmp_dirs, minimal_mapping):
        input_dir, out_dir = tmp_dirs
        # Write sample log file
        log_file = input_dir / "api_gateway.log"
        log_file.write_text(
            "2026-02-26 10:00:00 INFO api-gw-01 GET /api/v1/health 200\n"
            "2026-02-26 10:00:05 ERROR api-gw-01 POST /api/v1/command 500\n"
        )

        pipeline = NormalizerPipeline(minimal_mapping)
        events_path = str(out_dir / "events.csv")
        quarantine_path = str(out_dir / "quarantine.csv")
        stats_path = str(out_dir / "stats.json")

        pipeline.run(
            input_glob=str(input_dir / "*.log"),
            out_path=events_path,
            quarantine_path=quarantine_path,
            stats_path=stats_path,
        )

        # Check events.csv was written
        assert Path(events_path).exists()
        with open(events_path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["source"] == "api-gw-01"
        assert rows[0]["event"] == "http_request"

        # Check stats.json
        with open(stats_path) as f:
            stats = json.load(f)
        assert stats["total_parsed"] == 2
        assert stats["total_quarantined"] == 0

    def test_run_with_no_matching_files(self, tmp_dirs, minimal_mapping):
        input_dir, out_dir = tmp_dirs
        pipeline = NormalizerPipeline(minimal_mapping)
        # No files to match
        pipeline.run(
            input_glob=str(input_dir / "*.log"),
            out_path=str(out_dir / "events.csv"),
            quarantine_path=str(out_dir / "quarantine.csv"),
            stats_path=str(out_dir / "stats.json"),
        )
        # Should not crash; output files not created since no files processed

    def test_quarantine_lines_with_no_matching_profile(self, tmp_dirs, minimal_mapping):
        input_dir, out_dir = tmp_dirs
        # Write a file that doesn't match "api" pattern
        log_file = input_dir / "firewall.log"
        log_file.write_text("line1\nline2\n")

        pipeline = NormalizerPipeline(minimal_mapping)
        quarantine_path = str(out_dir / "quarantine.csv")

        pipeline.run(
            input_glob=str(input_dir / "firewall.log"),
            out_path=str(out_dir / "events.csv"),
            quarantine_path=quarantine_path,
            stats_path=str(out_dir / "stats.json"),
        )

        assert Path(quarantine_path).exists()
        with open(quarantine_path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert all(r["reason"] == "no_profile" for r in rows)

    def test_dedup_enabled(self, tmp_dirs, tmp_path):
        """With dedup enabled, identical events within window are removed."""
        input_dir, out_dir = tmp_dirs
        import yaml

        mapping = {
            "defaults": {"severity": "low", "source": "unknown", "component": "unknown", "event": "raw_log"},
            "normalizer": {"dedup": {"enabled": True, "window_sec": 5}},
            "profiles": {
                "api": {
                    "file_pattern": "api",
                    "line_regex": r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<level>\w+)\s+(?P<host>\S+)\s+(?P<msg>.+)$',
                    "timestamp_format": "iso_space",
                    "source_field": "host",
                    "level_field": "level",
                    "message_field": "msg",
                    "severity_map": {"info": "low"},
                    "event_rules": [{"pattern": "GET", "event": "http_request"}],
                    "component_rules": [{"pattern": "api", "component": "api"}],
                },
            },
        }
        mapping_path = tmp_path / "mapping_dedup.yaml"
        with open(mapping_path, "w") as f:
            yaml.dump(mapping, f)

        log_file = input_dir / "api.log"
        # Two identical lines 1 second apart → should dedup to 1
        log_file.write_text(
            "2026-02-26 10:00:00 INFO api-gw-01 GET /health 200\n"
            "2026-02-26 10:00:01 INFO api-gw-01 GET /health 200\n"
        )

        pipeline = NormalizerPipeline(str(mapping_path))
        events_path = str(out_dir / "events.csv")

        pipeline.run(
            input_glob=str(input_dir / "api.log"),
            out_path=events_path,
            quarantine_path=str(out_dir / "q.csv"),
            stats_path=str(out_dir / "s.json"),
        )

        with open(events_path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        # Dedup should have removed the second identical event
        assert len(rows) == 1
