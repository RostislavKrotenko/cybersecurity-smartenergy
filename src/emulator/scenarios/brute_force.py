"""Сценарій: Брутфорс-атака автентифікації."""

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


class BruteForceScenario(BaseScenario):
    name = "brute_force"

    def generate(self) -> list[Event]:
        events: list[Event] = []
        injections = self.cfg.get("injection", [])
        cor_seq = self.rng.randint(1, 50)
        cor_id = self._cor_id(cor_seq)
        t = self._attack_start()

        for phase_idx, phase in enumerate(injections):
            ev_type: str = phase["event"]
            probability = phase.get("probability", 1.0)

            # phase-2 might not fire
            if probability < 1.0 and self.rng.random() > probability:
                log.debug("brute_force phase %d skipped (prob=%.2f)", phase_idx, probability)
                continue

            # delay from previous phase
            delay_key = [k for k in phase if k.startswith("delay_after_phase")]
            if delay_key:
                d = phase[delay_key[0]]
                if isinstance(d, list):
                    t = t + timedelta(seconds=self.rng.uniform(d[0], d[1]))
                else:
                    t = t + timedelta(seconds=float(d))

            count_spec = phase.get("count", [1, 1])
            if isinstance(count_spec, list):
                count = _randint_range(self.rng, count_spec)
            else:
                count = int(count_spec)

            interval_ms = phase.get("interval_ms", [500, 1500])
            ip_pool = phase.get("ip_pool", ["0.0.0.0"])
            actor = phase.get("actor", "unknown")
            keys_list = phase.get("keys", [])
            sev_prog = phase.get("severity_progression", None)
            static_severity = phase.get("severity", "medium")
            tags_raw = phase.get("tags", [])
            tags_str = ";".join(tags_raw)

            target = _pick(self.rng, self.target_sources)
            comp = self._resolve_component(target)
            ip = _pick(self.rng, ip_pool)

            for i in range(count):
                sev = self._severity_for_index(i, sev_prog, static_severity)
                # after threshold=10 append ";escalated"
                ev_tags = tags_str
                if sev_prog and i >= 10 and "escalated" not in ev_tags:
                    ev_tags = ev_tags + ";escalated"

                key_spec = (
                    _pick(self.rng, keys_list)
                    if keys_list
                    else {"key": "username", "values": ["admin"]}
                )
                k = key_spec.get("key", "username")
                v = _pick(self.rng, key_spec.get("values", ["admin"]))

                events.append(
                    Event(
                        timestamp=_ts(t),
                        source=target,
                        component=comp,
                        event=ev_type,
                        key=k,
                        value=str(v),
                        severity=sev,
                        actor=actor,
                        ip=ip,
                        tags=ev_tags,
                        correlation_id=cor_id,
                    )
                )
                t = t + timedelta(milliseconds=self.rng.uniform(interval_ms[0], interval_ms[1]))

        log.info(
            "brute_force: generated %d events, offset=%ds, dur=%ds",
            len(events),
            self.start_offset,
            self.duration,
        )
        return events
