"""Ініціалізація seed для відтворюваності експериментів."""

from __future__ import annotations

import logging
import random

log = logging.getLogger(__name__)


def init_seed(seed: int) -> random.Random:
    """Встановлює глобальний seed та повертає екземпляр Random.

    Args:
        seed: Значення seed.

    Returns:
        Екземпляр random.Random з встановленим seed.
    """
    random.seed(seed)
    rng = random.Random(seed)
    log.info("Random seed initialised: %d", seed)
    return rng
