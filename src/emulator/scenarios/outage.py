"""Сценарій: Відключення / пошкодження БД."""

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


class OutageScenario(BaseScenario):
    name = "outage_db_corruption"

    def generate(self) -> list[Event]:
        events: list[Event] = []
        injections = self.cfg.get("injection", [])
        cor_seq = self.rng.randint(1, 50)
        cor_id = self._cor_id(cor_seq)
        t = self._attack_start()

        # Track phase end times so delays reference them
        phase_end_times: list[float] = []

        for phase_idx, phase in enumerate(injections):
            ev_type: str = phase["event"]
            probability = phase.get("probability", 1.0)

            if probability < 1.0 and self.rng.random() > probability:
                phase_end_times.append(t.timestamp())
                continue

            # Handle inter-phase delays
            delay_key = [k for k in phase if k.startswith("delay_after_phase")]
            if delay_key:
                d = phase[delay_key[0]]
                if isinstance(d, list):
                    t = t + timedelta(seconds=self.rng.uniform(d[0], d[1]))
                else:
                    t = t + timedelta(seconds=float(d))

            count_spec = phase.get("count", [1, 3])
            if isinstance(count_spec, list):
                count = _randint_range(self.rng, count_spec)
            else:
                count = int(count_spec)

            interval_ms = phase.get("interval_ms", [1000, 5000])
            source_single = phase.get("source", None)
            source_pool = phase.get("source_pool", self.target_sources)
            keys_list = phase.get("keys", [])
            sev_prog = phase.get("severity_progression", None)
            static_severity = phase.get("severity", "high")
            tags_str = ";".join(phase.get("tags", []))

            for i in range(count):
                sev = self._severity_for_index(i, sev_prog, static_severity)

                if source_single:
                    target = source_single
                else:
                    target = _pick(self.rng, source_pool)

                comp = self._resolve_component(target)
                ip = self._resolve_ip(target)

                key_spec = (
                    _pick(self.rng, keys_list)
                    if keys_list
                    else {"key": "status", "values": ["down"]}
                )
                k = key_spec.get("key", "status")
                if "range" in key_spec:
                    v = str(_uniform(self.rng, key_spec["range"][0], key_spec["range"][1]))
                else:
                    v = str(_pick(self.rng, key_spec.get("values", ["error"])))

                events.append(
                    Event(
                        timestamp=_ts(t),
                        source=target,
                        component=comp,
                        event=ev_type,
                        key=k,
                        value=v,
                        severity=sev,
                        actor="system",
                        ip=ip,
                        tags=tags_str,
                        correlation_id=cor_id,
                    )
                )
                t = t + timedelta(milliseconds=self.rng.uniform(interval_ms[0], interval_ms[1]))

            phase_end_times.append(t.timestamp())

        log.info(
            "outage_db_corruption: generated %d events, offset=%ds", len(events), self.start_offset
        )
        return events
