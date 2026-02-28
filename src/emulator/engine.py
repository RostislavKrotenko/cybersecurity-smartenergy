"""Оркестратор емуляції: фоновий трафік + ін’єкція атак."""

from __future__ import annotations

import copy
import logging
import random as _random_mod
import time
from datetime import datetime, timedelta, timezone
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

# ── demo_high_rate overrides ─────────────────────────────────────────────
# These overrides shorten all schedule offsets and increase counts so that
# attacks fire within the first 10--30 seconds and repeat frequently.

_DEMO_SCHEDULE_OVERRIDES: dict[str, dict[str, Any]] = {
    "brute_force": {
        "schedule": {"start_offset_sec": [3, 8], "duration_sec": [10, 20]},
        "injection_count_mult": 2.0,
    },
    "ddos_abuse": {
        "schedule": {"start_offset_sec": [10, 18], "duration_sec": [15, 30]},
        "injection_count_mult": 2.0,
    },
    "telemetry_spoofing": {
        "schedule": {"start_offset_sec": [18, 25], "duration_sec": [10, 20]},
        "injection_count_mult": 2.0,
    },
    "unauthorized_command": {
        "schedule": {"start_offset_sec": [25, 35], "duration_sec": [5, 12]},
        "injection_count_mult": 2.0,
    },
    "outage_db_corruption": {
        "schedule": {"start_offset_sec": [35, 45], "duration_sec": [15, 30]},
        "injection_count_mult": 2.0,
    },
}


def _apply_demo_profile(attacks_cfg: dict[str, Any], attack_rate: float) -> dict[str, Any]:
    """Застосовує demo_high_rate профіль до конфігу."""
    cfg = copy.deepcopy(attacks_cfg)
    for name, overrides in _DEMO_SCHEDULE_OVERRIDES.items():
        if name not in cfg:
            continue
        cfg[name]["schedule"] = overrides["schedule"]
        count_mult = overrides.get("injection_count_mult", 1.0) * attack_rate
        for phase in cfg[name].get("injection", []):
            c = phase.get("count")
            if isinstance(c, list):
                phase["count"] = [max(1, int(c[0] * count_mult)), max(2, int(c[1] * count_mult))]
            elif isinstance(c, (int, float)):
                phase["count"] = max(1, int(c * count_mult))
    return cfg


def _apply_attack_rate(attacks_cfg: dict[str, Any], attack_rate: float) -> dict[str, Any]:
    """Множить кількість атак на attack_rate."""
    if attack_rate == 1.0:
        return attacks_cfg
    cfg = copy.deepcopy(attacks_cfg)
    for _name, atk in cfg.items():
        for phase in atk.get("injection", []):
            c = phase.get("count")
            if isinstance(c, list):
                phase["count"] = [max(1, int(c[0] * attack_rate)),
                                  max(2, int(c[1] * attack_rate))]
            elif isinstance(c, (int, float)):
                phase["count"] = max(1, int(c * attack_rate))
    return cfg


class EmulatorEngine:
    """Головний движок симуляції."""

    def __init__(
        self,
        components_cfg: dict[str, Any],
        scenarios_cfg: dict[str, Any],
        seed: int = 42,
        days: int | None = None,
        start_time: datetime | None = None,
        scenario_set: str = "all",
        profile: str = "default",
        attack_rate: float = 1.0,
    ) -> None:
        self.rng = _random_mod.Random(seed)
        _random_mod.seed(seed)

        self.devices = build_device_index(components_cfg)
        self.profile = profile
        self.attack_rate = attack_rate

        sim = scenarios_cfg.get("simulation", {})
        self.duration_sec = sim.get("duration_sec", 3600)

        if profile == "demo_high_rate":
            # Short cycles: 60s so attacks repeat frequently
            self.duration_sec = 60

        if days is not None and days > 0:
            self.duration_sec = days * 86400

        if start_time is not None:
            self.sim_start = start_time
        else:
            raw = sim.get("start_time", "2026-02-26T10:00:00Z")
            self.sim_start = datetime.fromisoformat(raw.replace("Z", "+00:00"))

        self.bg_cfg = scenarios_cfg.get("background", {})
        raw_attacks = scenarios_cfg.get("attacks", {})

        if profile == "demo_high_rate":
            self.attacks_cfg = _apply_demo_profile(raw_attacks, attack_rate)
        else:
            self.attacks_cfg = _apply_attack_rate(raw_attacks, attack_rate)

        self.scenario_set = scenario_set

        log.info(
            "Engine init: duration=%ds, start=%s, seed=%d, scenarios=%s, profile=%s, rate=%.1f",
            self.duration_sec,
            self.sim_start.isoformat(),
            seed,
            scenario_set,
            profile,
            attack_rate,
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

        log.info(
            "Total events: %d (bg=%d + atk=%d)", len(all_events), len(bg_events), len(attack_events)
        )
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
    """Stream events to a JSONL file with real-time delays (live mode)."""
    path.parent.mkdir(parents=True, exist_ok=True)

    all_events = engine.run()
    if max_events is not None and len(all_events) > max_events:
        all_events = all_events[:max_events]

    all_events.sort(key=lambda e: e.timestamp)
    log.info(
        "Live mode: streaming %d events to %s (interval=%.3fs)", len(all_events), path, interval_sec
    )

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
    csv_out: Path | None = None,
) -> None:
    """Stream events infinitely, re-running the simulation in loops.

    Each loop generates a fresh batch of events (with a shifted time window
    and incremented seed) and writes them one-by-one. This never returns
    under normal operation -- stop with Ctrl+C / SIGTERM.

    Multi-format output:
      - JSONL at *path* (always)
      - CSV at *csv_out* (if provided, appended per batch with header once)
      - Raw syslog-style logs in *raw_log_dir* (if provided): auth.log,
        api.log, system.log with intentionally dirty/mixed formats.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if raw_log_dir is not None:
        raw_log_dir.mkdir(parents=True, exist_ok=True)
    if csv_out is not None:
        csv_out.parent.mkdir(parents=True, exist_ok=True)

    cycle = 0
    total_count = 0
    csv_header_written = False
    current_seed = engine.rng.randint(0, 2**31)

    log.info("Infinite live mode -> %s (interval=%.3fs)", path, interval_sec)

    while True:
        cycle += 1
        engine.sim_start = datetime.now(tz=timezone.utc)
        _random_mod.seed(current_seed + cycle)
        engine.rng = _random_mod.Random(current_seed + cycle)

        events = engine.run()
        events.sort(key=lambda e: e.timestamp)
        log.info("Cycle %d: generated %d events", cycle, len(events))

        # Collect CSV batch for this cycle
        csv_batch: list[str] = []

        with path.open("a", encoding="utf-8") as fh:
            for ev in events:
                # Re-stamp to real wall-clock time
                ev.timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

                fh.write(ev.to_json() + "\n")
                fh.flush()
                total_count += 1

                # Collect CSV row
                if csv_out is not None:
                    csv_batch.append(ev.to_csv_row())

                # Write raw logs (dirty multi-format)
                if raw_log_dir is not None:
                    _write_dirty_raw_log(raw_log_dir, ev, engine.rng)

                if total_count % 50 == 0:
                    log.info(
                        "  [tick] total=%d events, cycle=%d",
                        total_count,
                        cycle,
                    )
                time.sleep(interval_sec)

        # Append CSV batch
        if csv_out is not None and csv_batch:
            with csv_out.open("a", encoding="utf-8", newline="") as cf:
                if not csv_header_written:
                    cf.write(Event.csv_header() + "\n")
                    csv_header_written = True
                for row in csv_batch:
                    cf.write(row + "\n")
                cf.flush()

        log.info(
            "Cycle %d complete: total_events=%d",
            cycle,
            total_count,
        )


# ------------------------------------------------------------------
# Dirty raw log writers -- intentionally messy formats for normalizer
# ------------------------------------------------------------------

_LOG_FILE_MAP: dict[str, str] = {
    "api": "api.log",
    "ui": "api.log",
    "db": "system.log",
    "network": "system.log",
    "edge": "system.log",
    "inverter": "system.log",
    "collector": "system.log",
}

_AUTH_EVENTS = frozenset(
    {
        "auth_success",
        "auth_failure",
        "login_attempt",
        "brute_force_attempt",
    }
)

# Syslog months for dirty timestamp format
_MONTHS = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]

# Severity level token pools for each log type
_API_LEVELS = ["INFO", "WARN", "ERROR", "DEBUG"]
_SYSLOG_PROGS = ["sshd", "pam_unix", "systemd", "security"]


def _dirty_ts_iso(dt: datetime) -> str:
    """ISO-space format: 2026-02-28 14:05:01"""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _dirty_ts_syslog(dt: datetime, rng: _random_mod.Random) -> str:
    """Syslog format: Feb 28 14:05:01 (no year, sometimes add extra space)."""
    month_str = _MONTHS[dt.month - 1]
    day = dt.day
    time_part = dt.strftime("%H:%M:%S")
    # Occasionally add extra space for dirtiness
    spacing = "  " if rng.random() < 0.15 else " "
    return f"{month_str}{spacing}{day:>2} {time_part}"


def _write_dirty_raw_log(log_dir: Path, ev: Event, rng: _random_mod.Random) -> None:
    """Write a single dirty raw log line to the appropriate log file.

    The format varies randomly between ISO-space and syslog styles.
    Fields are sometimes omitted. Severity levels use different casings.
    """
    now = datetime.now(tz=timezone.utc)

    if ev.event in _AUTH_EVENTS or "auth" in ev.tags:
        filename = "auth.log"
    else:
        filename = _LOG_FILE_MAP.get(ev.component, "system.log")

    log_path = log_dir / filename

    if filename == "auth.log":
        line = _format_auth_line(ev, now, rng)
    elif filename == "api.log":
        line = _format_api_line(ev, now, rng)
    else:
        line = _format_system_line(ev, now, rng)

    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()


def _format_auth_line(ev: Event, now: datetime, rng: _random_mod.Random) -> str:
    """Syslog-format auth line with intentional dirtiness."""
    ts = _dirty_ts_syslog(now, rng)
    prog = rng.choice(_SYSLOG_PROGS)
    pid = rng.randint(1000, 9999)

    if ev.event == "auth_failure":
        templates = [
            f"{ts} {ev.source} {prog}[{pid}]: Failed password for {ev.actor} from {ev.ip} port {rng.randint(1024, 65000)}",
            f"{ts} {ev.source} {prog}[{pid}]: authentication failure; logname= uid=0 euid=0 user={ev.actor}",
            f"{ts} {ev.source} {prog}[{pid}]: Invalid user {ev.actor} from {ev.ip}",
        ]
    elif ev.event == "auth_success":
        templates = [
            f"{ts} {ev.source} {prog}[{pid}]: Accepted password for {ev.actor} from {ev.ip} port {rng.randint(1024, 65000)}",
            f"{ts} {ev.source} {prog}[{pid}]: session opened for user {ev.actor}",
        ]
    else:
        templates = [
            f"{ts} {ev.source} {prog}[{pid}]: {ev.event} user={ev.actor} from {ev.ip}",
        ]

    line = rng.choice(templates)

    # Sometimes omit IP (dirty data)
    if rng.random() < 0.1 and "from" in line:
        line = line.split("from")[0].rstrip()

    return line


def _format_api_line(ev: Event, now: datetime, rng: _random_mod.Random) -> str:
    """ISO-space format API line with varying levels."""
    ts = _dirty_ts_iso(now)
    level = rng.choice(_API_LEVELS)

    # Map event severity to realistic level
    if ev.severity == "critical":
        level = rng.choice(["ERROR", "CRIT"])
    elif ev.severity == "high":
        level = rng.choice(["ERROR", "WARN"])
    elif ev.severity == "medium":
        level = "WARN"

    if ev.event == "http_request":
        method = rng.choice(["GET", "POST", "PUT", "DELETE"])
        status = rng.choice([200, 200, 200, 201, 400, 404, 500])
        path = ev.value if ev.value.startswith("/") else f"/api/v1/{ev.key}"
        line = f"{ts} {level} {ev.source} {method} {path} {status}"
        if ev.ip and rng.random() > 0.2:
            line += f" from {ev.ip}"
        if ev.actor and rng.random() > 0.3:
            line += f" user={ev.actor}"
    elif ev.event == "rate_exceeded":
        line = (
            f"{ts} {level} {ev.source} rate limit exceeded: "
            f"{ev.value} {ev.unit} from {ev.ip}"
        )
    elif ev.event == "service_status":
        line = f"{ts} {level} {ev.source} service status: {ev.value}"
        if rng.random() > 0.5:
            line += f" response time {rng.randint(50, 5000)}ms"
    elif ev.event == "db_error":
        line = (
            f"{ts} {level} {ev.source} database error: "
            f"{ev.value} table={ev.key}"
        )
    else:
        line = f"{ts} {level} {ev.source} {ev.event}: {ev.key}={ev.value}"

    return line


def _format_system_line(ev: Event, now: datetime, rng: _random_mod.Random) -> str:
    """Mixed-format system line (sometimes ISO, sometimes syslog)."""
    # Randomly choose timestamp format for maximum dirtiness
    if rng.random() < 0.4:
        ts = _dirty_ts_syslog(now, rng)
        # Syslog-style
        line = f"{ts} {ev.source} {ev.component}/{ev.event}: "
    else:
        ts = _dirty_ts_iso(now)
        level = "INFO"
        if ev.severity == "critical":
            level = "CRITICAL"
        elif ev.severity == "high":
            level = "ERROR"
        elif ev.severity == "medium":
            level = "WARNING"
        line = f"{ts} {level} {ev.source} "

    if ev.event == "service_status":
        line += f"status={ev.value}"
        if ev.ip and rng.random() > 0.4:
            line += f" addr={ev.ip}"
    elif ev.event == "telemetry_read":
        line += f"{ev.key}={ev.value}{ev.unit}"
    elif ev.event == "db_error":
        line += f"db error: {ev.value} integrity_check=FAIL"
    else:
        line += f"{ev.key}={ev.value}"
        if ev.severity in ("high", "critical"):
            line += f" severity={ev.severity}"

    return line
