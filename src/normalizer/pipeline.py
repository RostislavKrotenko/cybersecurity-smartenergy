"""Normalizer pipeline: read raw logs → parse → filter → write outputs.

Orchestrates the full normalisation flow:
  1. Read mapping.yaml, compile profiles
  2. Glob input files
  3. For each file, select profile by filename, parse each line
  4. Sort events by timestamp
  5. Optionally deduplicate
  6. Write data/events.csv   (Event Contract)
  7. Write out/quarantine.csv (rejected lines + reasons)
  8. Write out/normalize_stats.json
"""

from __future__ import annotations

import csv
import glob
import json
import logging
from datetime import UTC, timezone
from pathlib import Path
from typing import Any

from src.contracts.event import Event
from src.normalizer.filters import deduplicate
from src.normalizer.parser import Profile, build_profiles, parse_line, select_profile
from src.shared.config_loader import load_yaml

log = logging.getLogger(__name__)


def _resolve_tz(tz_name: str) -> timezone | Any:
    """Return a tzinfo object for the given timezone name."""
    if tz_name.upper() == "UTC":
        return UTC
    # Python 3.9+ zoneinfo
    from zoneinfo import ZoneInfo
    return ZoneInfo(tz_name)


class NormalizerPipeline:
    """Top-level orchestrator for normalisation."""

    def __init__(self, mapping_path: str, tz_name: str = "UTC") -> None:
        cfg = load_yaml(mapping_path)
        self.profiles: list[Profile] = build_profiles(cfg)
        self.defaults: dict[str, str] = cfg.get("defaults", {})
        self.tz = _resolve_tz(tz_name)

        # Dedup settings
        norm_cfg = cfg.get("normalizer", {})
        dedup_cfg = norm_cfg.get("dedup", {})
        self.dedup_enabled: bool = dedup_cfg.get("enabled", False)
        self.dedup_window: int = dedup_cfg.get("window_sec", 2)

    # ── Public API ───────────────────────────────────────────────────────

    def run(
        self,
        input_glob: str,
        out_path: str,
        quarantine_path: str,
        stats_path: str,
    ) -> None:
        """Execute the full normalisation pipeline."""
        files = sorted(glob.glob(input_glob))
        if not files:
            log.warning("No files match pattern: %s", input_glob)
            return

        all_events: list[Event] = []
        quarantine: list[dict[str, Any]] = []
        stats: dict[str, Any] = {
            "total_lines": 0,
            "total_parsed": 0,
            "total_quarantined": 0,
            "by_source": {},
        }

        for fpath in files:
            self._process_file(fpath, all_events, quarantine, stats)

        # Sort by timestamp
        all_events.sort(key=lambda e: e.timestamp)

        # Dedup
        if self.dedup_enabled and all_events:
            before = len(all_events)
            all_events = deduplicate(all_events, window_sec=self.dedup_window)
            removed = before - len(all_events)
            stats["dedup_removed"] = removed
            stats["total_parsed"] -= removed

        # Write outputs
        self._write_events(all_events, out_path)
        self._write_quarantine(quarantine, quarantine_path)
        self._write_stats(stats, stats_path)

        log.info(
            "Done: %d events written, %d quarantined, %d total lines across %d files",
            len(all_events),
            stats["total_quarantined"],
            stats["total_lines"],
            len(files),
        )

    # ── File processing ──────────────────────────────────────────────────

    def _process_file(
        self,
        fpath: str,
        events: list[Event],
        quarantine: list[dict[str, Any]],
        stats: dict[str, Any],
    ) -> None:
        """Parse one input file, appending results to events/quarantine."""
        fname = Path(fpath).name
        profile = select_profile(self.profiles, fname)

        if profile is None:
            log.warning("No profile matches '%s' — all lines quarantined", fname)
            self._quarantine_whole_file(fpath, quarantine, stats)
            return

        log.info("Processing %s with profile '%s'", fpath, profile.name)
        file_stats = {"lines": 0, "parsed": 0, "quarantined": 0}

        with open(fpath, encoding="utf-8", errors="replace") as fh:
            for line_no, raw_line in enumerate(fh, 1):
                file_stats["lines"] += 1
                result = parse_line(raw_line, profile, self.tz)

                if isinstance(result, Event):
                    events.append(result)
                    file_stats["parsed"] += 1
                else:
                    line_text, reason = result
                    quarantine.append({
                        "file": fpath,
                        "line_no": line_no,
                        "raw_line": line_text,
                        "reason": reason,
                    })
                    file_stats["quarantined"] += 1

        stats["by_source"][fpath] = file_stats
        stats["total_lines"] += file_stats["lines"]
        stats["total_parsed"] += file_stats["parsed"]
        stats["total_quarantined"] += file_stats["quarantined"]

    def _quarantine_whole_file(
        self,
        fpath: str,
        quarantine: list[dict[str, Any]],
        stats: dict[str, Any],
    ) -> None:
        """Quarantine every line of a file that has no matching profile."""
        file_stats = {"lines": 0, "parsed": 0, "quarantined": 0}
        with open(fpath, encoding="utf-8", errors="replace") as fh:
            for line_no, raw_line in enumerate(fh, 1):
                file_stats["lines"] += 1
                file_stats["quarantined"] += 1
                quarantine.append({
                    "file": fpath,
                    "line_no": line_no,
                    "raw_line": raw_line.rstrip("\n\r"),
                    "reason": "no_profile",
                })
        stats["by_source"][fpath] = file_stats
        stats["total_lines"] += file_stats["lines"]
        stats["total_quarantined"] += file_stats["quarantined"]

    # ── Output writers ───────────────────────────────────────────────────

    @staticmethod
    def _write_events(events: list[Event], path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(Event.csv_header() + "\n")
            for ev in events:
                fh.write(ev.to_csv_row() + "\n")
        log.info("Wrote %d events → %s", len(events), path)

    @staticmethod
    def _write_quarantine(quarantine: list[dict[str, Any]], path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=["file", "line_no", "raw_line", "reason"],
                quoting=csv.QUOTE_ALL,
            )
            writer.writeheader()
            writer.writerows(quarantine)
        log.info("Wrote %d quarantined lines → %s", len(quarantine), path)

    @staticmethod
    def _write_stats(stats: dict[str, Any], path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(stats, fh, indent=2, ensure_ascii=False)
        log.info("Wrote stats → %s", path)
