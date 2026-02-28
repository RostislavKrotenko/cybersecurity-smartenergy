"""Сценарій: Несанкціоноване виконання команд."""

from __future__ import annotations

import logging
from datetime import timedelta

from src.contracts.event import Event
from src.emulator.scenarios.base import (
    BaseScenario,
    _pick,
    _randint_range,
    _ts,
)

log = logging.getLogger(__name__)


class UnauthorizedCmdScenario(BaseScenario):
    name = "unauthorized_command"

    def generate(self) -> list[Event]:
        events: list[Event] = []
        injections = self.cfg.get("injection", [])
        cor_seq = self.rng.randint(1, 50)
        cor_id = self._cor_id(cor_seq)
        t = self._attack_start()

        for phase in injections:
            ev_type: str = phase["event"]

            count_spec = phase.get("count", [2, 5])
            if isinstance(count_spec, list):
                count = _randint_range(self.rng, count_spec)
            else:
                count = int(count_spec)

            interval_ms = phase.get("interval_ms", [2000, 10000])
            actor_pool = phase.get("actor_pool", ["unknown"])
            ip_pool = phase.get("ip_pool", ["0.0.0.0"])
            keys_list = phase.get("keys", [])
            static_severity = phase.get("severity", "critical")
            tags_str = ";".join(phase.get("tags", []))

            for i in range(count):
                target = _pick(self.rng, self.target_sources)
                comp = self._resolve_component(target)
                actor = _pick(self.rng, actor_pool)
                ip = _pick(self.rng, ip_pool)

                key_spec = (
                    _pick(self.rng, keys_list)
                    if keys_list
                    else {"key": "command", "values": ["unknown_cmd"]}
                )
                k = key_spec.get("key", "command")
                v = _pick(self.rng, key_spec.get("values", ["unknown"]))

                events.append(
                    Event(
                        timestamp=_ts(t),
                        source=target,
                        component=comp,
                        event=ev_type,
                        key=k,
                        value=str(v),
                        severity=static_severity,
                        actor=actor,
                        ip=ip,
                        tags=tags_str,
                        correlation_id=cor_id,
                    )
                )
                t = t + timedelta(milliseconds=self.rng.uniform(interval_ms[0], interval_ms[1]))

        log.info(
            "unauthorized_command: generated %d events, offset=%ds", len(events), self.start_offset
        )
        return events
