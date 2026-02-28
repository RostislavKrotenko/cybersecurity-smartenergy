"""Base class for all attack scenarios."""

from __future__ import annotations

import abc
import logging
import random as _random_mod
from datetime import datetime, timedelta
from typing import Any

from src.contracts.event import Event
from src.emulator.devices import Device

log = logging.getLogger(__name__)


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _pick(rng: _random_mod.Random, seq: list[Any]) -> Any:
    return seq[rng.randint(0, len(seq) - 1)]


def _uniform(rng: _random_mod.Random, lo: float, hi: float) -> float:
    return round(rng.uniform(lo, hi), 2)


def _randint_range(rng: _random_mod.Random, r: list[int]) -> int:
    """Return random int from a two-element [lo, hi] list."""
    return rng.randint(int(r[0]), int(r[1]))


class BaseScenario(abc.ABC):
    """Abstract base class for injectable attack scenarios.

    Each scenario reads its definition from the ``attacks`` section of
    ``scenarios.yaml`` and pre-generates a batch of ``Event`` objects
    that will be merged into the main timeline by the engine.
    """

    name: str = "base"

    def __init__(
        self,
        cfg: dict[str, Any],
        devices: dict[str, Device],
        rng: _random_mod.Random,
        sim_start: datetime,
        sim_duration_sec: int,
    ) -> None:
        self.cfg = cfg
        self.devices = devices
        self.rng = rng
        self.sim_start = sim_start
        self.sim_duration_sec = sim_duration_sec

        sched = cfg.get("schedule", {})
        self.start_offset = _randint_range(rng, sched.get("start_offset_sec", [60, 120]))
        self.duration = _randint_range(rng, sched.get("duration_sec", [30, 60]))
        self.correlation_prefix = cfg.get("correlation_prefix", "COR")
        self.target_sources: list[str] = cfg.get("target_sources", [])
        self.target_components: list[str] = cfg.get("target_components", [])

    # Concrete scenarios implement this
    @abc.abstractmethod
    def generate(self) -> list[Event]:
        """Return a list of attack events sorted by timestamp."""
        ...

    # helpers available to subclasses
    def _resolve_ip(self, source: str) -> str:
        dev = self.devices.get(source)
        return dev.ip if dev else ""

    def _resolve_component(self, source: str) -> str:
        dev = self.devices.get(source)
        if dev:
            return dev.component
        if self.target_components:
            return _pick(self.rng, self.target_components)
        return "unknown"

    def _attack_start(self) -> datetime:
        return self.sim_start + timedelta(seconds=self.start_offset)

    def _cor_id(self, seq: int) -> str:
        return f"{self.correlation_prefix}-{seq:03d}"

    def _severity_for_index(
        self, idx: int, progression: list[dict[str, Any]] | None, fallback: str = "medium"
    ) -> str:
        if not progression:
            return fallback
        sev = fallback
        for p in progression:
            if idx >= p.get("threshold", 0):
                sev = p["severity"]
        return sev
