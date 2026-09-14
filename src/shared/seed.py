"""Ініціалізація seed для відтворюваності експериментів."""

from __future__ import annotations

import logging
import random

log = logging.getLogger(__name__)


def init_seed(seed: int) -> random.Random:
    """Встановлює глобальний seed та повертає екземпляр Random.

    Аргументи:
        seed: Значення seed.

    Повертає:
        Екземпляр random.Random з встановленим seed.
    """
    random.seed(seed)
    rng = random.Random(seed)
    log.info("Seed генератора випадковості ініціалізовано: %d", seed)
    return rng
