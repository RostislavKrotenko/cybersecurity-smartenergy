"""Background (normal) traffic generators.

Each generator is a *callable* that, given the current simulation timestamp,
returns zero or more ``Event`` objects representing benign activity.
"""

from __future__ import annotations

import logging
import random as _random_mod
from datetime import datetime
from typing import Any

from src.contracts.event import Event
from src.emulator.devices import Device

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pick(rng: _random_mod.Random, seq: list[Any]) -> Any:
    return seq[rng.randint(0, len(seq) - 1)]


def _uniform(rng: _random_mod.Random, lo: float, hi: float) -> float:
    return round(rng.uniform(lo, hi), 2)


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Telemetry generator
# ---------------------------------------------------------------------------

class TelemetryGenerator:
    """Periodic telemetry readings from edge/inverter/collector devices."""

    def __init__(self, cfg: dict[str, Any], devices: dict[str, Device],
                 rng: _random_mod.Random) -> None:
        self.rng = rng
        self.sources = cfg.get("sources", [])
        self.components = cfg.get("component", [])
        self.keys = cfg.get("keys", [])
        self.interval = cfg.get("interval_sec", [5, 15])
        self.severity = cfg.get("severity", "low")
        self.tags = ";".join(cfg.get("tags", []))
        self.devices = devices
        # per-source next-fire time (as offset in seconds from sim start)
        self._next_fire: dict[str, float] = {
            s: rng.uniform(0, self.interval[1]) for s in self.sources
        }

    def generate(self, t: datetime, offset_sec: float) -> list[Event]:
        events: list[Event] = []
        for src in self.sources:
            if offset_sec < self._next_fire[src]:
                continue
            # schedule next
            self._next_fire[src] = offset_sec + self.rng.uniform(
                self.interval[0], self.interval[1])
            key_spec = _pick(self.rng, self.keys)
            k = key_spec["key"]
            dev = self.devices.get(src)
            comp = dev.component if dev else _pick(self.rng, self.components)
            ip = dev.ip if dev else ""
            if "range" in key_spec:
                v = str(_uniform(self.rng, key_spec["range"][0], key_spec["range"][1]))
            else:
                v = str(_pick(self.rng, key_spec.get("values", [""])))
            events.append(Event(
                timestamp=_ts(t),
                source=src,
                component=comp,
                event="telemetry_read",
                key=k,
                value=v,
                severity=self.severity,
                actor="system",
                ip=ip,
                unit=key_spec.get("unit", ""),
                tags=self.tags,
            ))
        return events


# ---------------------------------------------------------------------------
# Access (HTTP) generator
# ---------------------------------------------------------------------------

class AccessGenerator:
    def __init__(self, cfg: dict[str, Any], devices: dict[str, Device],
                 rng: _random_mod.Random) -> None:
        self.rng = rng
        self.sources = cfg.get("sources", [])
        self.components = cfg.get("component", [])
        self.actors = cfg.get("actors", ["operator"])
        self.keys = cfg.get("keys", [])
        self.interval = cfg.get("interval_sec", [2, 10])
        self.severity = cfg.get("severity", "low")
        self.tags = ";".join(cfg.get("tags", []))
        self.devices = devices
        self._next_fire: dict[str, float] = {
            s: rng.uniform(0, self.interval[1]) for s in self.sources
        }

    def generate(self, t: datetime, offset_sec: float) -> list[Event]:
        events: list[Event] = []
        for src in self.sources:
            if offset_sec < self._next_fire[src]:
                continue
            self._next_fire[src] = offset_sec + self.rng.uniform(
                self.interval[0], self.interval[1])
            key_spec = _pick(self.rng, self.keys)
            dev = self.devices.get(src)
            comp = dev.component if dev else _pick(self.rng, self.components)
            actor = _pick(self.rng, self.actors)
            v = _pick(self.rng, key_spec.get("values", [""]))
            events.append(Event(
                timestamp=_ts(t),
                source=src,
                component=comp,
                event="http_request",
                key=key_spec.get("key", "endpoint"),
                value=str(v),
                severity=self.severity,
                actor=actor,
                ip=dev.ip if dev else "",
                tags=self.tags,
            ))
        return events


# ---------------------------------------------------------------------------
# Auth (successful login) generator
# ---------------------------------------------------------------------------

class AuthGenerator:
    def __init__(self, cfg: dict[str, Any], devices: dict[str, Device],
                 rng: _random_mod.Random) -> None:
        self.rng = rng
        self.sources = cfg.get("sources", [])
        self.components = cfg.get("component", [])
        self.actors = cfg.get("actors", ["operator"])
        self.keys = cfg.get("keys", [])
        self.interval = cfg.get("interval_sec", [30, 120])
        self.severity = cfg.get("severity", "low")
        self.tags = ";".join(cfg.get("tags", []))
        self.devices = devices
        self._next_fire: dict[str, float] = {
            s: rng.uniform(0, self.interval[1]) for s in self.sources
        }

    def generate(self, t: datetime, offset_sec: float) -> list[Event]:
        events: list[Event] = []
        for src in self.sources:
            if offset_sec < self._next_fire[src]:
                continue
            self._next_fire[src] = offset_sec + self.rng.uniform(
                self.interval[0], self.interval[1])
            key_spec = _pick(self.rng, self.keys)
            dev = self.devices.get(src)
            comp = dev.component if dev else _pick(self.rng, self.components)
            actor = _pick(self.rng, self.actors)
            v = _pick(self.rng, key_spec.get("values", ["password"]))
            events.append(Event(
                timestamp=_ts(t),
                source=src,
                component=comp,
                event="auth_success",
                key=key_spec.get("key", "method"),
                value=str(v),
                severity=self.severity,
                actor=actor,
                ip=dev.ip if dev else "",
                tags=self.tags,
            ))
        return events


# ---------------------------------------------------------------------------
# System health generator
# ---------------------------------------------------------------------------

class SystemHealthGenerator:
    def __init__(self, cfg: dict[str, Any], devices: dict[str, Device],
                 rng: _random_mod.Random) -> None:
        self.rng = rng
        self.sources = cfg.get("sources", [])
        self.components = cfg.get("component", [])
        self.keys = cfg.get("keys", [])
        self.interval = cfg.get("interval_sec", [30, 60])
        self.severity = cfg.get("severity", "low")
        self.tags = ";".join(cfg.get("tags", []))
        self.devices = devices
        self._next_fire: dict[str, float] = {
            s: rng.uniform(0, self.interval[1]) for s in self.sources
        }

    def generate(self, t: datetime, offset_sec: float) -> list[Event]:
        events: list[Event] = []
        for src in self.sources:
            if offset_sec < self._next_fire[src]:
                continue
            self._next_fire[src] = offset_sec + self.rng.uniform(
                self.interval[0], self.interval[1])
            key_spec = _pick(self.rng, self.keys)
            dev = self.devices.get(src)
            comp = dev.component if dev else _pick(self.rng, self.components)
            v = _pick(self.rng, key_spec.get("values", ["healthy"]))
            events.append(Event(
                timestamp=_ts(t),
                source=src,
                component=comp,
                event="service_status",
                key=key_spec.get("key", "status"),
                value=str(v),
                severity=self.severity,
                actor="system",
                ip=dev.ip if dev else "",
                tags=self.tags,
            ))
        return events
