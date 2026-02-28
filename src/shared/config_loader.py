"""Load and merge YAML configuration files."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)


def load_yaml(path: str | Path) -> dict[str, Any]:
    """Read a single YAML file and return its contents as a dict."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    log.debug("Loaded config %s (%d top-level keys)", p.name, len(data or {}))
    return data or {}
