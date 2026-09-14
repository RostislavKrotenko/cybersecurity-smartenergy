"""Гібридне виконання — поєднання симуляції з реальним виконанням.

Модуль поєднує симульований WorldState із виконанням дій у реальній
інфраструктурі. Він дозволяє:

1. Використовувати емулятор для генерації подій і сценаріїв атак.
2. Виконувати реагування в реальній інфраструктурі (firewall, rate limiter тощо).

Приклад:
    EXECUTION_MODE=real          # увімкнути реальне виконання
    DRY_RUN=true                # тест без змін в інфраструктурі
    FIREWALL_BACKEND=iptables   # або paloalto, aws_sg
    RATE_LIMIT_BACKEND=kong     # або aws_waf
    RATE_LIMIT_API_URL=http://kong:8001

    from src.emulator.hybrid import create_hybrid_executor, apply_action_hybrid

    executor = create_hybrid_executor()
    events = apply_action_hybrid(state, action, executor)
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from src.contracts.action import Action
from src.contracts.event import Event
from src.emulator.world import WorldState, apply_action

if TYPE_CHECKING:
    from src.contracts.interfaces import ActionExecutor

log = logging.getLogger(__name__)

EXECUTION_MODE = os.environ.get("EXECUTION_MODE", "simulated")


def create_hybrid_executor() -> ActionExecutor | None:
    """Створює реальний ActionExecutor з env-змінних.

    Основні змінні:
        EXECUTION_MODE: "simulated" або "real"
        DRY_RUN: "true" або "false" для тесту без змін
        FIREWALL_BACKEND: "iptables", "paloalto", "aws_sg" (типово: iptables)
        RATE_LIMIT_BACKEND: "kong", "aws_waf" (типово: kong)
        RATE_LIMIT_API_URL: URL адміністративного API Kong
        NETWORK_BACKEND: "kubernetes", "docker" (типово: docker)
    """
    if EXECUTION_MODE != "real":
        log.info("EXECUTION_MODE=%s -> чиста симуляція", EXECUTION_MODE)
        return None

    log.info("EXECUTION_MODE=real -> створення реальних executor")

    try:
        from src.adapters.real_executors import (
            CompositeExecutor,
            ExecutorConfig,
            FirewallExecutor,
            NetworkIsolationExecutor,
            RateLimitExecutor,
        )
    except ImportError as e:
        log.warning("Не вдалося імпортувати real executor: %s", e)
        return None

    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"
    config = ExecutorConfig(enabled=True, dry_run=dry_run)

    executors = []

    firewall_backend = os.environ.get("FIREWALL_BACKEND", "iptables")
    executors.append(
        FirewallExecutor(
            backend=firewall_backend,
            api_url=os.environ.get("FIREWALL_API_URL") or None,
            api_key=os.environ.get("FIREWALL_API_KEY") or None,
            config=config,
        )
    )
    log.info("  FirewallExecutor: %s", firewall_backend)

    rate_backend = os.environ.get("RATE_LIMIT_BACKEND", "kong")
    rate_url = os.environ.get("RATE_LIMIT_API_URL", "http://localhost:8001")
    executors.append(
        RateLimitExecutor(
            backend=rate_backend,
            api_url=rate_url,
            config=config,
        )
    )
    log.info("  RateLimitExecutor: %s @ %s", rate_backend, rate_url)

    net_backend = os.environ.get("NETWORK_BACKEND", "docker")
    executors.append(
        NetworkIsolationExecutor(
            backend=net_backend,
            namespace=os.environ.get("NETWORK_NAMESPACE", "smartenergy"),
            config=config,
        )
    )
    log.info("  NetworkIsolationExecutor: %s", net_backend)

    if dry_run:
        log.info("  DRY_RUN=true -> тільки логування, без реального виконання")

    return CompositeExecutor(executors)


def apply_action_hybrid(
    state: WorldState,
    action: Action,
    executor: ActionExecutor | None = None,
) -> list[Event]:
    """Застосовує дію з опційним реальним виконанням.

    Спочатку оновлюється WorldState для UI/трекінгу, після чого дія може бути
    виконана в реальній інфраструктурі, якщо executor налаштований.
    """
    sim_events = apply_action(state, action)

    if executor is None:
        return sim_events

    if not executor.supports_action(action.action):
        log.debug("Дія %s не підтримується executor, виконується лише симуляція", action.action)
        return sim_events

    result = executor.execute(action)

    if result.success:
        log.info("HYBRID: %s -> реальне виконання SUCCESS", action.action)
        return result.state_events if result.state_events else sim_events
    else:
        log.warning(
            "HYBRID: %s -> реальне виконання FAILED: %s (симуляцію все одно застосовано)",
            action.action,
            result.error,
        )
        return sim_events


_global_executor: ActionExecutor | None = None
_executor_initialized = False


def get_executor() -> ActionExecutor | None:
    """Повертає глобальний executor з lazy-ініціалізацією з env-змінних."""
    global _global_executor, _executor_initialized
    if not _executor_initialized:
        _global_executor = create_hybrid_executor()
        _executor_initialized = True
    return _global_executor
