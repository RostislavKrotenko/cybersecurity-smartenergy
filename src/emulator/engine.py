"""Emulator engine -- orchestrates background traffic + attack injection.

The engine:
1. Reads ``components.yaml`` -> builds device index.
2. Reads ``scenarios.yaml`` -> creates background generators + attack scenarios.
3. Steps through simulated time, collecting events.
4. Merges background + attack events into one sorted timeline.
5. Writes output in CSV (default) or JSONL format.
6. In **live mode**, streams events to a JSONL file with realistic delays.
"""

from __future__ import annotations

import logging
import random as _random_mod
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from src.contracts.event import Event
from src.emulator.devices import build_device_index
from src.emulator.noise import (
    AccessGenerator,
    AuthGenerator,
    SystemHealthGenerator,
    TelemetryGenerator,
)
from src.emulator.scenarios.brute_force import BruteForceScenario
from src.emulator.scenarios.ddos_abuse import DDoSAbuseScenario
from src.emulator.scenarios.outage import OutageScenario
from src.emulator.scenarios.telemetry_spoof import TelemetrySpoofScenario
from src.emulator.scenarios.unauthorized_cmd import UnauthorizedCmdScenario

log = logging.getLogger(__name__)

# Registry: scenario name -> class
SCENARIO_REGISTRY: dict[str, type] = {
    "brute_force": BruteForceScenario,
    "ddos_abuse": DDoSAbuseScenario,
    "telemetry_spoofing": TelemetrySpoofScenario,
    "unauthorized_command": UnauthorizedCmdScenario,
    "outage_db_corruption": OutageScenario,
}


class EmulatorEngine:
    """Main simulation engine."""

    def __init__(
        self,
        components_cfg: dict[str, Any],
        scenarios_cfg: dict[str, Any],
        seed: int = 42,
        days: int | None = None,
        start_time: datetime | None = None,
        scenario_set: str = "all",
    ) -> None:
        self.rng = _random_mod.Random(seed)
        # also seed global random for any library code
        _random_mod.seed(seed)

        self.devices = build_device_index(components_cfg)

        sim = scenarios_cfg.get("simulation", {})
        self.duration_sec = sim.get("duration_sec", 3600)

        # --days overrides config duration
        if days is not None and days > 0:
            self.duration_sec = days * 86400

        if start_time is not None:
            self.sim_start = start_time
        else:
            raw = sim.get("start_time", "2026-02-26T10:00:00Z")
            self.sim_start = datetime.fromisoformat(raw.replace("Z", "+00:00"))

        self.bg_cfg = scenarios_cfg.get("background", {})
        self.attacks_cfg = scenarios_cfg.get("attacks", {})
        self.scenario_set = scenario_set

        log.info(
            "Engine init: duration=%ds, start=%s, seed=%d, scenarios=%s",
            self.duration_sec, self.sim_start.isoformat(), seed, scenario_set,
        )

    # ------------------------------------------------------------------
    # Background generators
    # ------------------------------------------------------------------

    def _build_bg_generators(self) -> list[Any]:
        gens: list[Any] = []
        mapping = {
            "telemetry": TelemetryGenerator,
            "access": AccessGenerator,
            "auth": AuthGenerator,
            "system_health": SystemHealthGenerator,
        }
        for key, cls in mapping.items():
            cfg = self.bg_cfg.get(key)
            if cfg:
                gens.append(cls(cfg, self.devices, self.rng))
        log.info("Built %d background generators", len(gens))
        return gens

    # ------------------------------------------------------------------
    # Attack scenarios
    # ------------------------------------------------------------------

    def _build_attacks(self) -> list[Event]:
        """Pre-generate all attack events and return them sorted."""
        all_attack_events: list[Event] = []
        wanted = set()
        if self.scenario_set and self.scenario_set.lower() != "all":
            wanted = {s.strip() for s in self.scenario_set.split(",")}

        for name, atk_cfg in self.attacks_cfg.items():
            if not atk_cfg.get("enabled", True):
                continue
            if wanted and name not in wanted:
                continue
            cls = SCENARIO_REGISTRY.get(name)
            if cls is None:
                log.warning("Unknown scenario '%s', skipping", name)
                continue
            scenario = cls(
                cfg=atk_cfg,
                devices=self.devices,
                rng=self.rng,
                sim_start=self.sim_start,
                sim_duration_sec=self.duration_sec,
            )
            evts = scenario.generate()
            all_attack_events.extend(evts)

        all_attack_events.sort(key=lambda e: e.timestamp)
        log.info("Total attack events pre-generated: %d", len(all_attack_events))
        return all_attack_events

    # ------------------------------------------------------------------
    # Main run
    # ------------------------------------------------------------------

    def run(self) -> list[Event]:
        """Execute the full simulation and return sorted events."""
        bg_gens = self._build_bg_generators()
        attack_events = self._build_attacks()

        # time-step resolution: 1 second
        step = timedelta(seconds=1)
        bg_events: list[Event] = []

        t = self.sim_start
        end = self.sim_start + timedelta(seconds=self.duration_sec)
        offset = 0.0

        while t < end:
            for gen in bg_gens:
                bg_events.extend(gen.generate(t, offset))
            t += step
            offset += 1.0

        log.info("Background events generated: %d", len(bg_events))

        # merge and sort
        all_events = bg_events + attack_events
        all_events.sort(key=lambda e: e.timestamp)

        log.info("Total events: %d (bg=%d + atk=%d)",
                 len(all_events), len(bg_events), len(attack_events))
        return all_events


# ------------------------------------------------------------------
# Writers
# ------------------------------------------------------------------

def write_csv(events: list[Event], path: Path) -> None:
    """Write events to a CSV file with header."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        fh.write(Event.csv_header() + "\n")
        for ev in events:
            fh.write(ev.to_csv_row() + "\n")
    log.info("Wrote %d events to %s", len(events), path)


def write_jsonl(events: list[Event], path: Path) -> None:
    """Write events to a JSONL file (one JSON per line)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(ev.to_json() + "\n")
    log.info("Wrote %d events to %s", len(events), path)


# ------------------------------------------------------------------
# Live streaming writer
# ------------------------------------------------------------------

def stream_jsonl(
    engine: EmulatorEngine,
    path: Path,
    interval_sec: float = 1.0,
    max_events: int | None = None,
) -> int:
    """Stream events to a JSONL file with real-time delays (live mode).

    Events are generated batch-first, then written one-by-one with sleep
    intervals to simulate realistic arrival. The file is opened in append
    mode so external consumers can tail it.

    Parameters
    ----------
    engine       : configured EmulatorEngine
    path         : output JSONL file (append mode)
    interval_sec : pause between event writes (seconds)
    max_events   : optional cap on total events

    Returns
    -------
    Number of events streamed.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    all_events = engine.run()
    if max_events is not None and len(all_events) > max_events:
        all_events = all_events[:max_events]

    all_events.sort(key=lambda e: e.timestamp)
    log.info("Live mode: streaming %d events to %s (interval=%.3fs)",
             len(all_events), path, interval_sec)

    count = 0
    with path.open("a", encoding="utf-8") as fh:
        for ev in all_events:
            fh.write(ev.to_json() + "\n")
            fh.flush()
            count += 1
            if count % 50 == 0:
                log.info("  streamed %d / %d events", count, len(all_events))
            time.sleep(interval_sec)

    log.info("Live streaming complete: %d events -> %s", count, path)
    return count


def stream_jsonl_infinite(
    engine: EmulatorEngine,
    path: Path,
    interval_sec: float = 1.0,
    raw_log_dir: Path | None = None,
) -> None:
    """Stream events infinitely, re-running the simulation in loops.

    Each loop generates a fresh batch of events (with a shifted time window
    and incremented seed) and writes them one-by-one. This never returns
    under normal operation -- stop with Ctrl+C / SIGTERM.

    If *raw_log_dir* is provided, raw syslog-style lines are also written
    to files named api.log, auth.log, edge.log inside that directory.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if raw_log_dir is not None:
        raw_log_dir.mkdir(parents=True, exist_ok=True)

    cycle = 0
    total_count = 0
    current_seed = engine.rng.randint(0, 2**31)

    log.info("Infinite live mode -> %s (interval=%.3fs)", path, interval_sec)

    while True:
        cycle += 1
        # Shift simulation start to current wall-clock time
        engine.sim_start = datetime.now(tz=datetime.UTC)
        _random_mod.seed(current_seed + cycle)
        engine.rng = _random_mod.Random(current_seed + cycle)

        events = engine.run()
        events.sort(key=lambda e: e.timestamp)
        log.info("Cycle %d: generated %d events", cycle, len(events))

        with path.open("a", encoding="utf-8") as fh:
            for ev in events:
                # Re-stamp to real wall-clock time
                ev.timestamp = datetime.now(tz=datetime.UTC).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )

                fh.write(ev.to_json() + "\n")
                fh.flush()
                total_count += 1

                # Also write raw logs
                if raw_log_dir is not None:
                    _write_raw_log(raw_log_dir, ev)

                if total_count % 100 == 0:
                    log.info("  total streamed: %d events (cycle %d)",
                             total_count, cycle)
                time.sleep(interval_sec)


# ------------------------------------------------------------------
# Raw log writer helpers
# ------------------------------------------------------------------

_RAW_LOG_MAP: dict[str, str] = {
    "api":       "api.log",
    "ui":        "api.log",
    "edge":      "edge.log",
    "inverter":  "edge.log",
    "collector": "edge.log",
    "db":        "api.log",
    "network":   "edge.log",
}

_AUTH_EVENTS = frozenset({
    "auth_success", "auth_failure", "login_attempt", "brute_force_attempt",
})


def _write_raw_log(log_dir: Path, ev: Event) -> None:
    """Append a single syslog-style line to the appropriate raw log file."""
    if ev.event in _AUTH_EVENTS or "auth" in ev.tags:
        filename = "auth.log"
    else:
        filename = _RAW_LOG_MAP.get(ev.component, "edge.log")

    line = (
        f"{ev.timestamp} {ev.source} {ev.component}/{ev.event}: "
        f"actor={ev.actor} ip={ev.ip} key={ev.key} value={ev.value} "
        f"severity={ev.severity} tags={ev.tags}"
    )

    log_path = log_dir / filename
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()
