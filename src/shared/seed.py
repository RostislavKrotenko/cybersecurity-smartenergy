"""Deterministic seed initialisation for reproducible experiments."""

from __future__ import annotations

import logging
import random

log = logging.getLogger(__name__)


def init_seed(seed: int) -> random.Random:
    """Set the global random seed and return a dedicated Random instance.

    We also seed the *global* ``random`` module so that any library code
    relying on ``random.random()`` behaves deterministically.
    """
    random.seed(seed)
    rng = random.Random(seed)
    log.info("Random seed initialised: %d", seed)
    return rng
