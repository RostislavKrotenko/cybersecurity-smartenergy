"""Оркестратор емуляції: фоновий трафік + ін’єкція атак."""

from __future__ import annotations

import contextlib
import copy
import logging
import random as _random_mod
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.contracts.action import ActionAck
from src.contracts.event import Event
from src.contracts.interfaces import EventSink
from src.emulator.devices import build_device_index
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
from src.emulator.world import (
    WorldState,
    apply_action,
    expire_state,
    is_actor_blocked,
    is_isolated,
    is_network_degraded,
    is_rate_limited,
    read_new_actions,
)

log = logging.getLogger(__name__)

# Реєстр сценаріїв: назва -> клас
SCENARIO_REGISTRY: dict[str, type] = {
    "brute_force": BruteForceScenario,
    "ddos_abuse": DDoSAbuseScenario,
    "telemetry_spoofing": TelemetrySpoofScenario,
    "unauthorized_command": UnauthorizedCmdScenario,
    "outage_db_corruption": OutageScenario,
    "network_failure": NetworkFailureScenario,
}

# demo_high_rate скорочує затримки та підвищує кількість подій, щоб атаки
# запускалися в перші 10-30 секунд і регулярно повторювалися.

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
    "network_failure": {
        "schedule": {"start_offset_sec": [45, 55], "duration_sec": [10, 25]},
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
                phase["count"] = [max(1, int(c[0] * attack_rate)), max(2, int(c[1] * attack_rate))]
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

    def _build_attacks(self) -> list[Event]:
        """Заздалегідь генерує всі атакувальні події та повертає їх відсортованими."""
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
                log.warning("Невідомий сценарій '%s', пропущено", name)
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

    def run(self) -> list[Event]:
        """Виконує повну симуляцію та повертає відсортовані події."""
        bg_gens = self._build_bg_generators()
        attack_events = self._build_attacks()

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

        all_events = bg_events + attack_events
        all_events.sort(key=lambda e: e.timestamp)

        log.info(
            "Total events: %d (bg=%d + atk=%d)", len(all_events), len(bg_events), len(attack_events)
        )
        return all_events


def write_csv(events: list[Event], path: Path) -> None:
    """Записує події у CSV файл із заголовком."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        fh.write(Event.csv_header() + "\n")
        for ev in events:
            fh.write(ev.to_csv_row() + "\n")
    log.info("Wrote %d events to %s", len(events), path)


def write_jsonl(events: list[Event], path: Path) -> None:
    """Записує події у JSONL файл, по одному JSON на рядок."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(ev.to_json() + "\n")
    log.info("Wrote %d events to %s", len(events), path)


def stream_jsonl(
    engine: EmulatorEngine,
    path: Path,
    interval_sec: float = 1.0,
    max_events: int | None = None,
) -> int:
    """Потоково записує події у JSONL файл із live-затримками."""
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


def stream_to_sink(
    engine: EmulatorEngine,
    event_sink: EventSink,
    interval_sec: float = 1.0,
    max_events: int | None = None,
) -> int:
    """Потоково передає події в EventSink у live-режимі.

    Це інтерфейсна альтернатива stream_jsonl(), яку можна використовувати
    для підключення файлового, Kafka або іншого backend-приймача.
    """
    all_events = engine.run()
    if max_events is not None and len(all_events) > max_events:
        all_events = all_events[:max_events]

    all_events.sort(key=lambda e: e.timestamp)
    log.info(
        "Live mode: streaming %d events via EventSink (interval=%.3fs)",
        len(all_events),
        interval_sec,
    )

    count = 0
    for ev in all_events:
        event_sink.emit(ev)
        count += 1
        if count % 50 == 0:
            log.info("  streamed %d / %d events", count, len(all_events))
        time.sleep(interval_sec)

    event_sink.flush()
    log.info("EventSink streaming complete: %d events", count)
    return count


def stream_jsonl_infinite(
    engine: EmulatorEngine,
    path: Path,
    interval_sec: float = 1.0,
    raw_log_dir: Path | None = None,
    csv_out: Path | None = None,
) -> None:
    """Безкінечно стрімить події, повторно запускаючи симуляцію циклами.

    Кожен цикл генерує новий пакет подій зі зміщеним часовим вікном і seed,
    після чого записує їх по одній. За нормальної роботи функція не завершується.
    Виходи: JSONL, опційний CSV і опційні «брудні» сирі логи.
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

        csv_batch: list[str] = []

        with path.open("a", encoding="utf-8") as fh:
            for ev in events:
                ev.timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

                fh.write(ev.to_json() + "\n")
                fh.flush()
                total_count += 1

                if csv_out is not None:
                    csv_batch.append(ev.to_csv_row())

                if raw_log_dir is not None:
                    _write_dirty_raw_log(raw_log_dir, ev, engine.rng)

                if total_count % 50 == 0:
                    log.info(
                        "  [tick] total=%d events, cycle=%d",
                        total_count,
                        cycle,
                    )
                time.sleep(interval_sec)

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

# Місяці syslog-формату для «брудних» timestamp.
_MONTHS = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
]

# Набори рівнів severity для різних типів логів.
_API_LEVELS = ["INFO", "WARN", "ERROR", "DEBUG"]
_SYSLOG_PROGS = ["sshd", "pam_unix", "systemd", "security"]


def _dirty_ts_iso(dt: datetime) -> str:
    """Формат ISO з пробілом: 2026-02-28 14:05:01."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _dirty_ts_syslog(dt: datetime, rng: _random_mod.Random) -> str:
    """Формат syslog без року, іноді з додатковим пробілом."""
    month_str = _MONTHS[dt.month - 1]
    day = dt.day
    time_part = dt.strftime("%H:%M:%S")
    spacing = "  " if rng.random() < 0.15 else " "
    return f"{month_str}{spacing}{day:>2} {time_part}"


def _write_dirty_raw_log(log_dir: Path, ev: Event, rng: _random_mod.Random) -> None:
    """Записує один «брудний» сирий лог у відповідний файл.

    Формат випадково змінюється між ISO-space і syslog, окремі поля можуть
    пропускатися, а рівні severity мають різний регістр.
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
    """Формує auth-рядок у syslog-форматі з навмисним шумом."""
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

    if rng.random() < 0.1 and "from" in line:
        line = line.split("from")[0].rstrip()

    return line


def _format_api_line(ev: Event, now: datetime, rng: _random_mod.Random) -> str:
    """Формує API-рядок у ISO-space форматі з різними рівнями."""
    ts = _dirty_ts_iso(now)
    level = rng.choice(_API_LEVELS)

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
        line = f"{ts} {level} {ev.source} rate limit exceeded: {ev.value} {ev.unit} from {ev.ip}"
    elif ev.event == "service_status":
        line = f"{ts} {level} {ev.source} service status: {ev.value}"
        if rng.random() > 0.5:
            line += f" response time {rng.randint(50, 5000)}ms"
    elif ev.event == "db_error":
        line = f"{ts} {level} {ev.source} database error: {ev.value} table={ev.key}"
    else:
        line = f"{ts} {level} {ev.source} {ev.event}: {ev.key}={ev.value}"

    return line


def _format_system_line(ev: Event, now: datetime, rng: _random_mod.Random) -> str:
    """Формує system-рядок у змішаному ISO/syslog форматі."""
    if rng.random() < 0.4:
        ts = _dirty_ts_syslog(now, rng)
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


_ATTACK_SEQUENCE: list[str] = [
    "brute_force",
    "ddos_abuse",
    "telemetry_spoofing",
    "unauthorized_command",
    "outage_db_corruption",
    "network_failure",
]

# Пакети атак відкалібровані так, щоб перевищувати пороги rules.yaml.
# Це дає швидке спрацювання інцидентів у live-демо.

_DEMO_BURSTS: dict[str, dict[str, Any]] = {
    "brute_force": {
        "phases": [
            {
                "event": "auth_failure",
                "count": 8,
                "interval_ms": 200,
                "actor": "unknown",
                "severity": "high",
                "ip_pool": ["192.168.8.55"],
                "source_pool": ["gateway-01"],
                "keys": [
                    {"key": "username", "values": ["admin", "root", "operator", "test"]},
                ],
                "tags": "auth;failure",
            },
        ],
    },
    "ddos_abuse": {
        "phases": [
            {
                "event": "rate_exceeded",
                "count": 15,
                "interval_ms": 100,
                "actor": "unknown",
                "severity": "critical",
                "ip_pool": [
                    "203.0.113.10",
                    "203.0.113.11",
                    "203.0.113.12",
                ],
                "source_pool": ["api-gw-01"],
                "keys": [
                    {
                        "key": "requests_per_sec",
                        "range": [2000, 5000],
                        "unit": "req/s",
                    },
                ],
                "tags": "network;flood",
            },
            {
                "event": "service_status",
                "count": 2,
                "interval_ms": 500,
                "actor": "system",
                "severity": "critical",
                "source_pool": ["api-gw-01"],
                "keys": [{"key": "status", "values": ["degraded", "down"]}],
                "tags": "system;overload",
            },
        ],
    },
    "telemetry_spoofing": {
        "phases": [
            {
                "event": "telemetry_read",
                "count": 6,
                "interval_ms": 300,
                "actor": "system",
                "severity": "low",
                "source_pool": ["meter-17"],
                "keys": [
                    {"key": "voltage", "range": [500.0, 1200.0], "unit": "V"},
                ],
                "tags": "telemetry;periodic",
            },
        ],
    },
    "unauthorized_command": {
        "phases": [
            {
                "event": "cmd_exec",
                "count": 3,
                "interval_ms": 500,
                "actor_pool": ["readonly", "unknown", "guest"],
                "severity": "critical",
                "ip_pool": ["10.0.5.88", "10.0.5.89"],
                "source_pool": ["scada-hmi-01"],
                "keys": [
                    {
                        "key": "command",
                        "values": [
                            "breaker_open",
                            "breaker_close",
                            "set_voltage",
                            "emergency_shutdown",
                        ],
                    },
                ],
                "tags": "command;unauthorized",
            },
        ],
    },
    "outage_db_corruption": {
        "phases": [
            {
                "event": "db_error",
                "count": 3,
                "interval_ms": 500,
                "actor": "system",
                "severity": "critical",
                "source_pool": ["db-primary"],
                "keys": [
                    {
                        "key": "error_type",
                        "values": [
                            "integrity_violation",
                            "checksum_mismatch",
                            "wal_corruption",
                        ],
                    },
                ],
                "tags": "system;db;corruption",
            },
            {
                "event": "service_status",
                "count": 2,
                "interval_ms": 1000,
                "actor": "system",
                "severity": "critical",
                "source_pool": ["db-primary"],
                "keys": [{"key": "status", "values": ["degraded", "down"]}],
                "tags": "system;outage",
            },
        ],
    },
    "network_failure": {
        "phases": [
            {
                "event": "service_status",
                "count": 4,
                "interval_ms": 500,
                "actor": "system",
                "severity": "critical",
                "source_pool": ["switch-core-01", "firewall-01"],
                "keys": [
                    {"key": "status", "values": ["degraded", "down", "packet_loss", "unreachable"]},
                ],
                "tags": "network;failure",
            },
            {
                "event": "port_status",
                "count": 2,
                "interval_ms": 800,
                "actor": "system",
                "severity": "high",
                "source_pool": ["switch-core-01"],
                "keys": [{"key": "port_status", "values": ["down", "flapping"]}],
                "tags": "network;port",
            },
        ],
    },
}

# Шаблони фонових подій, які не мають бути атакувальними.
_BG_TEMPLATES: list[tuple[str, str, list[str], list[dict[str, Any]]]] = [
    (
        "telemetry_read",
        "system",
        [
            "meter-17",
            "meter-22",
            "inverter-01",
            "inverter-02",
            "inverter-03",
            "collector-01",
        ],
        [
            {"key": "voltage", "range": [218.0, 242.0], "unit": "V"},
            {"key": "power_kw", "range": [0.0, 55.0], "unit": "kW"},
            {"key": "frequency_hz", "range": [49.8, 50.2], "unit": "Hz"},
            {"key": "temperature_c", "range": [20.0, 65.0], "unit": "C"},
        ],
    ),
    (
        "http_request",
        "_rand_actor",
        ["api-gw-01", "ui-web-01"],
        [
            {
                "key": "endpoint",
                "values": [
                    "/api/v1/meters",
                    "/api/v1/inverters",
                    "/api/v1/status",
                    "/dashboard",
                    "/api/v1/config",
                ],
            },
        ],
    ),
    (
        "auth_success",
        "_rand_actor",
        ["api-gw-01", "gateway-01"],
        [
            {"key": "method", "values": ["password", "mfa", "certificate"]},
        ],
    ),
    (
        "service_status",
        "system",
        ["db-primary", "db-replica", "switch-core-01", "firewall-01"],
        [
            {"key": "status", "values": ["healthy"]},
        ],
    ),
]


def _random_bg_event(
    rng: _random_mod.Random,
    devices: dict[str, Any],
    now: datetime,
) -> Event:
    """Генерує одну випадкову безпечну фонову подію."""
    tpl = rng.choice(_BG_TEMPLATES)
    event_type, actor_tmpl, sources, key_specs = tpl
    source = rng.choice(sources)
    dev = devices.get(source)
    comp = dev.component if dev else "unknown"
    ip = dev.ip if dev else ""
    ks = rng.choice(key_specs)
    k = ks["key"]
    if "range" in ks:
        v = str(round(rng.uniform(ks["range"][0], ks["range"][1]), 2))
    else:
        v = str(rng.choice(ks["values"]))
    unit = ks.get("unit", "")
    if actor_tmpl == "_rand_actor":
        actor = rng.choice(["operator", "admin", "readonly"])
    else:
        actor = actor_tmpl
    return Event(
        timestamp=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        source=source,
        component=comp,
        event=event_type,
        key=k,
        value=v,
        severity="low",
        actor=actor,
        ip=ip,
        unit=unit,
        tags="demo;background",
    )


def _generate_attack_burst(
    name: str,
    rng: _random_mod.Random,
    devices: dict[str, Any],
    now: datetime,
) -> list[Event]:
    """Генерує пакет подій для *name*, відкалібрований під пороги детектора."""
    spec = _DEMO_BURSTS[name]
    events: list[Event] = []
    cor_id = f"COR-DEMO-{rng.randint(1000, 9999)}"
    t = now

    for phase in spec["phases"]:
        count: int = phase["count"]
        interval_ms: int = phase["interval_ms"]
        source = rng.choice(phase["source_pool"])
        dev = devices.get(source)
        comp = dev.component if dev else "unknown"

        for _i in range(count):
            ip_pool = phase.get("ip_pool", [dev.ip if dev else "0.0.0.0"])
            ip = rng.choice(ip_pool)
            ks = rng.choice(phase["keys"])
            k = ks.get("key", "")
            if "range" in ks:
                v = str(round(rng.uniform(ks["range"][0], ks["range"][1]), 2))
            else:
                v = str(rng.choice(ks.get("values", [""])))
            unit = ks.get("unit", "")
            actor = phase.get("actor") or rng.choice(phase.get("actor_pool", ["unknown"]))
            events.append(
                Event(
                    timestamp=t.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    source=source,
                    component=comp,
                    event=phase["event"],
                    key=k,
                    value=v,
                    severity=phase["severity"],
                    actor=actor,
                    ip=ip,
                    unit=unit,
                    tags=phase.get("tags", ""),
                    correlation_id=cor_id,
                )
            )
            t = t + timedelta(milliseconds=interval_ms)

    return events


def _rotate_if_needed(path: Path, max_mb: float) -> bool:
    """Ротує файл, якщо його розмір перевищив *max_mb*.

    Поточний файл перейменовується на ``*.bak`` із перезаписом попереднього
    backup. Повертає ``True``, якщо ротація виконана.
    """
    try:
        if path.stat().st_size / 1_048_576 > max_mb:
            bak = path.with_suffix(path.suffix + ".bak")
            if bak.exists():
                bak.unlink()
            path.rename(bak)
            log.info("Rotated %s (exceeded %.0f MB)", path.name, max_mb)
            return True
    except OSError:
        pass
    return False


def stream_demo_highrate(
    engine: EmulatorEngine,
    path: Path,
    interval_sec: float = 0.25,
    attack_every_sec: float = 10.0,
    bg_per_tick: int = 20,
    max_file_mb: float = 50.0,
    raw_log_dir: Path | None = None,
    csv_out: Path | None = None,
    actions_path: Path | None = None,
    applied_path: Path | None = None,
) -> None:
    """Стрімить події для live-демо з високим фоновим темпом і burst-атаками.

    Функція працює безкінечно. Якщо передано *actions_path*, емулятор читає
    actions.jsonl у tail-режимі й застосовує дії до WorldState. Якщо передано
    *applied_path*, після успішного застосування записується ACK.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if raw_log_dir is not None:
        raw_log_dir.mkdir(parents=True, exist_ok=True)
    if csv_out is not None:
        csv_out.parent.mkdir(parents=True, exist_ok=True)

    rng = engine.rng
    devices = engine.devices
    attack_idx = 0
    total_count = 0

    world = WorldState()
    actions_offset = 0

    csv_header_written = False
    if csv_out is not None:
        with contextlib.suppress(OSError):
            csv_header_written = csv_out.stat().st_size > 0

    last_attack_wall = time.monotonic() - attack_every_sec

    log.info(
        "Demo high-rate stream -> %s "
        "(tick=%.0f ms, attack_every=%ds, bg/tick=%d, max_file=%.0f MB, actions=%s)",
        path,
        interval_sec * 1000,
        int(attack_every_sec),
        bg_per_tick,
        max_file_mb,
        actions_path or "none",
    )

    while True:
        now = datetime.now(tz=timezone.utc)
        events: list[Event] = []

        if actions_path is not None:
            new_actions, actions_offset = read_new_actions(
                str(actions_path),
                actions_offset,
            )
            if new_actions:
                log.info(
                    "ACTIONS READ: %d new actions from %s",
                    len(new_actions),
                    actions_path,
                )
            acks: list[ActionAck] = []
            for act in new_actions:
                try:
                    state_events = apply_action(world, act)
                    events.extend(state_events)
                    se_name = state_events[0].event if state_events else act.action
                    acks.append(
                        ActionAck(
                            action_id=act.action_id,
                            correlation_id=act.correlation_id,
                            target_component=act.target_component,
                            action=act.action,
                            applied_ts_utc=datetime.now(tz=timezone.utc).strftime(
                                "%Y-%m-%dT%H:%M:%SZ",
                            ),
                            result="success",
                            state_event=se_name,
                        )
                    )
                    log.info(
                        "APPLIED action_id=%s %s -> %s (cor=%s)",
                        act.action_id,
                        act.action,
                        se_name,
                        act.correlation_id,
                    )
                except Exception as exc:
                    acks.append(
                        ActionAck(
                            action_id=act.action_id,
                            correlation_id=act.correlation_id,
                            target_component=act.target_component,
                            action=act.action,
                            applied_ts_utc=datetime.now(tz=timezone.utc).strftime(
                                "%Y-%m-%dT%H:%M:%SZ",
                            ),
                            result="failed",
                            error=str(exc),
                        )
                    )
                    log.error(
                        "FAILED action_id=%s %s: %s",
                        act.action_id,
                        act.action,
                        exc,
                    )
            if acks and applied_path is not None:
                applied_path.parent.mkdir(parents=True, exist_ok=True)
                with applied_path.open("a", encoding="utf-8") as fh:
                    for ack in acks:
                        fh.write(ack.to_json() + "\n")
                    fh.flush()
                log.info(
                    "ACKS WRITTEN: %d -> %s",
                    len(acks),
                    applied_path,
                )
            if new_actions:
                log.info(
                    "ACTIONS APPLIED: %d actions, %d state-change events generated",
                    len(new_actions),
                    len(events),
                )

        expire_events = expire_state(world)
        events.extend(expire_events)

        for _ in range(bg_per_tick):
            ev = _random_bg_event(rng, devices, now)
            if _should_suppress(ev, world):
                continue
            events.append(ev)

        if is_network_degraded(world):
            net_errors = _generate_network_errors(rng, devices, now, world)
            events.extend(net_errors)

        wall_elapsed = time.monotonic() - last_attack_wall
        if wall_elapsed >= attack_every_sec:
            name = _ATTACK_SEQUENCE[attack_idx % len(_ATTACK_SEQUENCE)]
            burst = _generate_attack_burst(name, rng, devices, now)
            filtered_burst = [e for e in burst if not _should_suppress(e, world)]
            if len(filtered_burst) < len(burst):
                log.info(
                    "World state suppressed %d/%d events from %s burst",
                    len(burst) - len(filtered_burst),
                    len(burst),
                    name,
                )
            events.extend(filtered_burst)
            attack_idx += 1
            last_attack_wall = time.monotonic()
            log.info(
                "ATTACK BURST [%d]: %s -> %d events (%d suppressed, next in %ds)",
                attack_idx,
                name,
                len(filtered_burst),
                len(burst) - len(filtered_burst),
                int(attack_every_sec),
            )

        with path.open("a", encoding="utf-8") as fh:
            for ev in events:
                fh.write(ev.to_json() + "\n")
            fh.flush()

        if csv_out is not None and events:
            with csv_out.open("a", encoding="utf-8", newline="") as cf:
                if not csv_header_written:
                    cf.write(Event.csv_header() + "\n")
                    csv_header_written = True
                for ev in events:
                    cf.write(ev.to_csv_row() + "\n")
                cf.flush()

        if raw_log_dir is not None:
            for ev in events:
                _write_dirty_raw_log(raw_log_dir, ev, rng)

        total_count += len(events)

        _rotate_if_needed(path, max_file_mb)
        if csv_out is not None and _rotate_if_needed(csv_out, max_file_mb):
            csv_header_written = False

        if raw_log_dir is not None:
            for lf in raw_log_dir.glob("*.log"):
                _rotate_if_needed(lf, max_file_mb)

        if total_count % 500 < len(events):
            log.info(
                "Demo stream: %d events total, %d attack bursts fired, "
                "world: rate_limit=%s, isolated=%s, blocked_actors=%d, db=%s, "
                "net_degraded=%s",
                total_count,
                attack_idx,
                world.gateway.rate_limit_enabled,
                world.api.status,
                len(world.auth.blocked_actors) + len(world.auth.blocked_ips),
                world.db.status,
                is_network_degraded(world),
            )

        time.sleep(interval_sec)


def _should_suppress(ev: Event, world: WorldState) -> bool:
    """Перевіряє, чи потрібно приглушити подію через поточний WorldState.

    Так захист впливає на потік подій: rate limit зменшує flood, заблоковані
    актори не автентифікуються, а ізольовані компоненти не обслуговують запити.
    """
    if is_rate_limited(world) and ev.event == "rate_exceeded":
        return True

    if ev.event in ("auth_failure", "auth_success") and is_actor_blocked(world, ev.actor, ev.ip):
        return True

    if is_isolated(world, ev.component) and ev.event not in (
        "isolation_enabled",
        "isolation_released",
        "isolation_expired",
        "action_result",
    ):
        return True

    if world.db.status == "restoring" and ev.event == "db_error":
        return True

    return (
        world.network.disconnected
        and ev.component in ("api", "ui")
        and ev.event in ("http_request", "auth_success")
    )


def _generate_network_errors(
    rng: _random_mod.Random,
    devices: dict[str, Any],
    now: datetime,
    world: WorldState,
) -> list[Event]:
    """Генерує timeout/error події пропорційно до деградації мережі."""
    events: list[Event] = []
    drop = world.network.drop_rate
    latency = world.network.latency_ms

    if world.network.disconnected:
        n_errors = rng.randint(3, 6)
    elif drop > 0.3 or latency > 500:
        n_errors = rng.randint(2, 4)
    elif drop > 0 or latency > 100:
        n_errors = rng.randint(1, 2)
    else:
        return events

    error_templates = [
        ("service_status", "degraded", "network", "switch-core-01"),
        ("service_status", "timeout", "api", "api-gw-01"),
        ("http_request", "timeout", "api", "api-gw-01"),
        ("service_status", "packet_loss", "network", "firewall-01"),
    ]

    for _ in range(n_errors):
        tpl = rng.choice(error_templates)
        evt_type, val, comp, src = tpl
        sev = "critical" if world.network.disconnected else "high"
        events.append(
            Event(
                timestamp=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                source=src,
                component=comp,
                event=evt_type,
                key="status" if evt_type == "service_status" else "endpoint",
                value=val,
                severity=sev,
                actor="system",
                ip="",
                unit="",
                tags="network;degradation",
                correlation_id="",
            )
        )

    return events
