"""Конвеєр нормалізації: raw логи -> парсинг -> фільтрація -> запис."""

from __future__ import annotations

import csv
import glob
import json
import logging
import os
import time
from datetime import UTC, timezone
from pathlib import Path
from typing import Any

from src.contracts.event import Event
from src.normalizer.filters import deduplicate
from src.normalizer.parser import Profile, build_profiles, parse_line, select_profile
from src.shared.config_loader import load_yaml

log = logging.getLogger(__name__)


def _resolve_tz(tz_name: str) -> timezone | Any:
    """Повертає tzinfo об'єкт для вказаного імені часового поясу."""
    if tz_name.upper() == "UTC":
        return UTC
    # Python 3.9+ zoneinfo
    from zoneinfo import ZoneInfo

    return ZoneInfo(tz_name)


class NormalizerPipeline:
    """Оркестратор нормалізації."""

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
                    quarantine.append(
                        {
                            "file": fpath,
                            "line_no": line_no,
                            "raw_line": line_text,
                            "reason": reason,
                        }
                    )
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
                quarantine.append(
                    {
                        "file": fpath,
                        "line_no": line_no,
                        "raw_line": raw_line.rstrip("\n\r"),
                        "reason": "no_profile",
                    }
                )
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
        log.info("Wrote stats -> %s", path)

    # ── Follow (live tail) mode ──────────────────────────────────────────

    def follow(
        self,
        input_glob: str,
        out_path: str,
        poll_interval_sec: float = 1.0,
    ) -> None:
        """Continuously tail log files matching *input_glob* and append
        normalized events to *out_path* (JSONL if .jsonl, else CSV).

        Never returns under normal operation -- stop with Ctrl+C.
        """
        out_p = Path(out_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        use_jsonl = out_p.suffix in (".jsonl", ".ndjson")

        # Track file offsets for tailing
        file_offsets: dict[str, int] = {}
        total_parsed = 0
        total_quarantined = 0
        iteration = 0

        # Write CSV header once if CSV mode
        if not use_jsonl and not out_p.exists():
            with open(out_p, "w", encoding="utf-8", newline="") as fh:
                fh.write(Event.csv_header() + "\n")

        print(f"Normalizer follow mode: {input_glob} -> {out_path}")
        print(f"  poll interval: {poll_interval_sec:.1f}s")
        print("  Press Ctrl+C to stop.")

        try:
            while True:
                files = sorted(glob.glob(input_glob))
                new_events: list[Event] = []

                for fpath in files:
                    fname = Path(fpath).name
                    profile = select_profile(self.profiles, fname)
                    if profile is None:
                        continue

                    current_size = os.path.getsize(fpath)
                    prev_offset = file_offsets.get(fpath, 0)

                    if current_size <= prev_offset:
                        continue

                    with open(fpath, encoding="utf-8", errors="replace") as fh:
                        fh.seek(prev_offset)
                        for raw_line in fh:
                            result = parse_line(raw_line, profile, self.tz)
                            if isinstance(result, Event):
                                new_events.append(result)
                                total_parsed += 1
                            else:
                                total_quarantined += 1

                    file_offsets[fpath] = current_size

                if new_events:
                    iteration += 1
                    # Append to output
                    with open(out_p, "a", encoding="utf-8", newline="") as fh:
                        for ev in new_events:
                            if use_jsonl:
                                fh.write(ev.to_json() + "\n")
                            else:
                                fh.write(ev.to_csv_row() + "\n")
                        fh.flush()

                    log.info(
                        "[tick %d] +%d events normalized, total=%d parsed, %d quarantined",
                        iteration,
                        len(new_events),
                        total_parsed,
                        total_quarantined,
                    )

                time.sleep(poll_interval_sec)
        except KeyboardInterrupt:
            print(
                f"\nNormalizer follow stopped. total_parsed={total_parsed}, "
                f"quarantined={total_quarantined}"
            )
