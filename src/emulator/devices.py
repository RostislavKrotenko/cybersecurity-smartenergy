"""Infrastructure model — builds device/IP lookup from components.yaml."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Device:
    """One infrastructure instance (meter, gateway, DB server …)."""
    id: str
    ip: str
    component: str          # edge | api | db | …
    protocols: list[str]


def build_device_index(components_cfg: dict[str, Any]) -> dict[str, Device]:
    """Parse ``components`` section and return a dict keyed by device id."""
    comps: dict[str, Any] = components_cfg.get("components", {})
    index: dict[str, Device] = {}
    for comp_name, comp in comps.items():
        for inst in comp.get("instances", []):
            dev = Device(
                id=inst["id"],
                ip=str(inst.get("ip", "0.0.0.0")),
                component=comp_name,
                protocols=inst.get("protocols", []),
            )
            index[dev.id] = dev
    log.info("Device index built: %d devices across %d components",
             len(index), len(comps))
    return index
