"""Hybrid execution module - combines simulation with real execution.

This module provides integration between the simulated WorldState and
real infrastructure execution. It allows you to:

1. Keep using the emulator for event generation (attacks simulation)
2. Execute responses on REAL infrastructure (firewall, rate limiter, etc.)

Usage:
    # In Docker environment, set these env vars:
    EXECUTION_MODE=real          # Enable real execution
    DRY_RUN=true                # Test without changes
    FIREWALL_BACKEND=iptables   # or paloalto, aws_sg
    RATE_LIMIT_BACKEND=kong     # or aws_waf
    RATE_LIMIT_API_URL=http://kong:8001

    # In code:
    from src.emulator.hybrid import create_hybrid_executor, apply_action_hybrid

    executor = create_hybrid_executor()  # Creates from env vars
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

# Execution mode from environment
EXECUTION_MODE = os.environ.get("EXECUTION_MODE", "simulated")


def create_hybrid_executor() -> ActionExecutor | None:
    """Create a real ActionExecutor from environment variables.

    Environment variables:
        EXECUTION_MODE: "simulated" (default) or "real"
        DRY_RUN: "true" or "false" - log actions without executing
        FIREWALL_BACKEND: "iptables", "paloalto", "aws_sg" (default: iptables)
        RATE_LIMIT_BACKEND: "kong", "aws_waf" (default: kong)
        RATE_LIMIT_API_URL: Kong admin API URL
        NETWORK_BACKEND: "kubernetes", "docker" (default: docker)

    Returns:
        CompositeExecutor if EXECUTION_MODE=real, None otherwise.

    Example:
        # In docker-compose.yml:
        environment:
          EXECUTION_MODE: "real"
          DRY_RUN: "true"
          FIREWALL_BACKEND: "iptables"
    """
    if EXECUTION_MODE != "real":
        log.info("EXECUTION_MODE=%s -> pure simulation", EXECUTION_MODE)
        return None

    log.info("EXECUTION_MODE=real -> creating real executors")

    try:
        from src.adapters.real_executors import (
            CompositeExecutor,
            ExecutorConfig,
            FirewallExecutor,
            NetworkIsolationExecutor,
            RateLimitExecutor,
        )
    except ImportError as e:
        log.warning("Could not import real executors: %s", e)
        return None

    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"
    config = ExecutorConfig(enabled=True, dry_run=dry_run)

    executors = []

    # Firewall
    firewall_backend = os.environ.get("FIREWALL_BACKEND", "iptables")
    executors.append(FirewallExecutor(
        backend=firewall_backend,
        api_url=os.environ.get("FIREWALL_API_URL") or None,
        api_key=os.environ.get("FIREWALL_API_KEY") or None,
        config=config,
    ))
    log.info("  FirewallExecutor: %s", firewall_backend)

    # Rate limiting
    rate_backend = os.environ.get("RATE_LIMIT_BACKEND", "kong")
    rate_url = os.environ.get("RATE_LIMIT_API_URL", "http://localhost:8001")
    executors.append(RateLimitExecutor(
        backend=rate_backend,
        api_url=rate_url,
        config=config,
    ))
    log.info("  RateLimitExecutor: %s @ %s", rate_backend, rate_url)

    # Network isolation
    net_backend = os.environ.get("NETWORK_BACKEND", "docker")
    executors.append(NetworkIsolationExecutor(
        backend=net_backend,
        namespace=os.environ.get("NETWORK_NAMESPACE", "smartenergy"),
        config=config,
    ))
    log.info("  NetworkIsolationExecutor: %s", net_backend)

    if dry_run:
        log.info("  DRY_RUN=true -> logging only, no real execution")

    return CompositeExecutor(executors)


def apply_action_hybrid(
    state: WorldState,
    action: Action,
    executor: ActionExecutor | None = None,
) -> list[Event]:
    """Apply action with optional real execution.

    This combines simulation with real infrastructure execution:
    1. Always updates WorldState (for UI/tracking)
    2. Optionally executes on real infrastructure

    Args:
        state: WorldState to update.
        action: Action to apply.
        executor: Optional real executor (from create_hybrid_executor).

    Returns:
        List of state-change events.

    Examples:
        # Pure simulation
        events = apply_action_hybrid(state, action)

        # Hybrid: simulation + real
        executor = create_hybrid_executor()
        events = apply_action_hybrid(state, action, executor)
    """
    # Always run simulation for state tracking
    sim_events = apply_action(state, action)

    # No executor = pure simulation
    if executor is None:
        return sim_events

    # Try real execution if supported
    if not executor.supports_action(action.action):
        log.debug("Action %s not supported by executor, simulation only", action.action)
        return sim_events

    # Execute on real infrastructure
    result = executor.execute(action)

    if result.success:
        log.info("HYBRID: %s -> real execution SUCCESS", action.action)
        # Return real events if available, otherwise simulated
        return result.state_events if result.state_events else sim_events
    else:
        log.warning("HYBRID: %s -> real execution FAILED: %s (simulation still applied)",
                   action.action, result.error)
        return sim_events


# Singleton executor (created once from env)
_global_executor: ActionExecutor | None = None
_executor_initialized = False


def get_executor() -> ActionExecutor | None:
    """Get the global executor (lazy initialization from env vars).

    This is a convenience function for getting a single executor instance.
    """
    global _global_executor, _executor_initialized
    if not _executor_initialized:
        _global_executor = create_hybrid_executor()
        _executor_initialized = True
    return _global_executor
