"""Scenario 2: DDoS / API-abuse flood."""

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


class DDoSAbuseScenario(BaseScenario):
    name = "ddos_abuse"

    def generate(self) -> list[Event]:
        events: list[Event] = []
        injections = self.cfg.get("injection", [])
        cor_seq = self.rng.randint(1, 50)
        cor_id = self._cor_id(cor_seq)
        t = self._attack_start()

        for phase_idx, phase in enumerate(injections):
            ev_type: str = phase["event"]

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

            interval_ms = phase.get("interval_ms", [100, 500])
            ip_pool = phase.get("ip_pool", ["203.0.113.10"])
            actor = phase.get("actor", "unknown")
            keys_list = phase.get("keys", [])
            sev_prog = phase.get("severity_progression", None)
            static_severity = phase.get("severity", "high")
            tags_raw = phase.get("tags", [])
            tags_str = ";".join(tags_raw)
            source_pool = phase.get("source_pool", self.target_sources)

            for i in range(count):
                sev = self._severity_for_index(i, sev_prog, static_severity)
                ev_tags = tags_str
                if sev_prog and sev == "critical" and "escalated" not in ev_tags:
                    ev_tags = ev_tags + ";escalated"

                target = _pick(self.rng, source_pool)
                comp = self._resolve_component(target)
                ip = _pick(self.rng, ip_pool) if ip_pool else ""

                key_spec = _pick(self.rng, keys_list) if keys_list else {"key": "status", "values": ["degraded"]}
                k = key_spec.get("key", "status")
                if "range" in key_spec:
                    v = str(_uniform(self.rng, key_spec["range"][0], key_spec["range"][1]))
                else:
                    v = str(_pick(self.rng, key_spec.get("values", [""])))

                events.append(Event(
                    timestamp=_ts(t),
                    source=target,
                    component=comp,
                    event=ev_type,
                    key=k,
                    value=v,
                    severity=sev,
                    actor=actor,
                    ip=ip,
                    unit=key_spec.get("unit", ""),
                    tags=ev_tags,
                    correlation_id=cor_id,
                ))
                t = t + timedelta(milliseconds=self.rng.uniform(
                    interval_ms[0], interval_ms[1]))

        log.info("ddos_abuse: generated %d events, offset=%ds", len(events), self.start_offset)
        return events
