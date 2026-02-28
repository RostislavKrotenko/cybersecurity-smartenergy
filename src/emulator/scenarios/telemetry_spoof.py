"""Сценарій: Підробка телеметрії."""

from __future__ import annotations

import logging
from datetime import timedelta

from src.contracts.event import Event
from src.emulator.scenarios.base import (
    BaseScenario,
    _pick,
    _randint_range,
    _ts,
    _uniform,
)

log = logging.getLogger(__name__)


class TelemetrySpoofScenario(BaseScenario):
    name = "telemetry_spoofing"

    def generate(self) -> list[Event]:
        events: list[Event] = []
        injections = self.cfg.get("injection", [])
        cor_seq = self.rng.randint(1, 50)
        cor_id = self._cor_id(cor_seq)
        t = self._attack_start()

        for phase in injections:
            ev_type: str = phase["event"]
            actor = phase.get("actor", "system")

            count_spec = phase.get("count", [5, 15])
            if isinstance(count_spec, list):
                count = _randint_range(self.rng, count_spec)
            else:
                count = int(count_spec)

            interval_ms = phase.get("interval_ms", [500, 2000])
            keys_list = phase.get("keys", [])
            static_severity = phase.get("severity", "low")
            tags_str = ";".join(phase.get("tags", []))

            for i in range(count):
                target = _pick(self.rng, self.target_sources)
                comp = self._resolve_component(target)
                ip = self._resolve_ip(target)

                key_spec = (
                    _pick(self.rng, keys_list)
                    if keys_list
                    else {"key": "voltage", "range": [500, 1200], "unit": "V"}
                )
                k = key_spec["key"]
                if "range" in key_spec:
                    v = str(_uniform(self.rng, key_spec["range"][0], key_spec["range"][1]))
                else:
                    v = str(_pick(self.rng, key_spec.get("values", ["0"])))

                events.append(
                    Event(
                        timestamp=_ts(t),
                        source=target,
                        component=comp,
                        event=ev_type,
                        key=k,
                        value=v,
                        severity=static_severity,
                        actor=actor,
                        ip=ip,
                        unit=key_spec.get("unit", ""),
                        tags=tags_str,
                        correlation_id=cor_id,
                    )
                )
                t = t + timedelta(milliseconds=self.rng.uniform(interval_ms[0], interval_ms[1]))

        log.info(
            "telemetry_spoofing: generated %d events, offset=%ds", len(events), self.start_offset
        )
        return events
