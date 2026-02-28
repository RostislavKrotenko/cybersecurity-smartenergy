"""Налаштування логування."""

from __future__ import annotations

import logging
import sys


def setup_logging(level: str = "INFO") -> None:
    """Налаштовує стандартний логер з лаконічним форматом.

    Args:
        level: Рівень логування (DEBUG, INFO, WARNING, ERROR).
    """
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
        force=True,
    )
