"""Примітиви надійності для зовнішніх інтеграційних контурів.

Модуль містить:
- парсинг режиму інтеграції (dry-run/shadow/active)
- політики retry і timeout
- інжекцію idempotency key для дій
- дедуплікацію ACK
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum

from src.contracts.action import Action, ActionAck
from src.contracts.interfaces import ActionSink


class IntegrationMode(str, Enum):
    DRY_RUN = "dry-run"
    SHADOW = "shadow"
    ACTIVE = "active"


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    initial_backoff_sec: float = 0.5
    backoff_multiplier: float = 2.0
    max_backoff_sec: float = 5.0


@dataclass(frozen=True)
class TimeoutPolicy:
    emit_batch_timeout_sec: float = 10.0


@dataclass(frozen=True)
class ReliabilityPolicy:
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    timeout: TimeoutPolicy = field(default_factory=TimeoutPolicy)
    ack_dedup_max_entries: int = 50000


def parse_integration_mode(
    raw_value: str | None,
    default_mode: IntegrationMode = IntegrationMode.ACTIVE,
) -> IntegrationMode:
    """Парсить режим інтеграції з рядка CLI/env."""
    if raw_value is None:
        return default_mode

    normalized = raw_value.strip().lower()
    for mode in IntegrationMode:
        if normalized == mode.value:
            return mode

    allowed = ", ".join(mode.value for mode in IntegrationMode)
    raise ValueError(f"Непідтримуваний режим інтеграції: '{raw_value}'. Дозволено: {allowed}")


def build_reliability_policy_from_env() -> ReliabilityPolicy:
    """Формує політику надійності з env-параметрів із безпечними дефолтами."""

    def _read_int(name: str, default: int) -> int:
        with_value = os.environ.get(name)
        if with_value is None:
            return default
        try:
            return max(1, int(with_value))
        except ValueError:
            return default

    def _read_float(name: str, default: float) -> float:
        with_value = os.environ.get(name)
        if with_value is None:
            return default
        try:
            return max(0.0, float(with_value))
        except ValueError:
            return default

    retry = RetryPolicy(
        max_attempts=_read_int("SMARTENERGY_ACTION_EMIT_MAX_RETRIES", 3),
        initial_backoff_sec=_read_float("SMARTENERGY_ACTION_RETRY_INITIAL_SEC", 0.5),
        backoff_multiplier=_read_float("SMARTENERGY_ACTION_RETRY_MULTIPLIER", 2.0),
        max_backoff_sec=_read_float("SMARTENERGY_ACTION_RETRY_MAX_BACKOFF_SEC", 5.0),
    )

    timeout = TimeoutPolicy(
        emit_batch_timeout_sec=_read_float("SMARTENERGY_ACTION_EMIT_TIMEOUT_SEC", 10.0),
    )

    return ReliabilityPolicy(
        retry=retry,
        timeout=timeout,
        ack_dedup_max_entries=_read_int("SMARTENERGY_ACK_DEDUP_MAX_ENTRIES", 50000),
    )


def ensure_action_idempotency_key(action: Action) -> str:
    """Гарантує, що дія має стабільний idempotency key у params."""
    params = action.params
    existing = str(params.get("idempotency_key", "")).strip()
    if existing:
        return existing

    if action.action_id:
        key = action.action_id
    else:
        raw = "|".join(
            [
                action.ts_utc,
                action.action,
                action.target_component,
                action.target_id,
                action.correlation_id,
                str(sorted(action.params.items())),
            ]
        )
        key = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    params["idempotency_key"] = key
    return key


def emit_actions_with_retry(
    action_sink: ActionSink,
    actions: list[Action],
    policy: ReliabilityPolicy | None = None,
    logger: logging.Logger | None = None,
) -> list[str]:
    """Емітить дії з урахуванням retry і timeout політик.

    Timeout перевіряється після кожної спроби та трактується як помилка,
    якщо перевищено задане значення.
    """
    if not actions:
        return []

    active_policy = policy or ReliabilityPolicy()
    log = logger or logging.getLogger(__name__)

    for action in actions:
        ensure_action_idempotency_key(action)

    attempt = 0
    delay_sec = active_policy.retry.initial_backoff_sec
    last_error: Exception | None = None

    while attempt < active_policy.retry.max_attempts:
        attempt += 1
        started = time.monotonic()
        try:
            tracking_ids = action_sink.emit_batch(actions)
            elapsed = time.monotonic() - started

            if elapsed > active_policy.timeout.emit_batch_timeout_sec:
                raise TimeoutError(
                    "Емісія дій перевищила timeout "
                    f"({elapsed:.2f}s > {active_policy.timeout.emit_batch_timeout_sec:.2f}s)"
                )

            if len(tracking_ids) != len(actions):
                raise RuntimeError(
                    "ActionSink повернув неочікувану кількість tracking ID "
                    f"({len(tracking_ids)} != {len(actions)})"
                )

            return tracking_ids

        except Exception as exc:
            last_error = exc
            if attempt >= active_policy.retry.max_attempts:
                break

            log.warning(
                "Спроба емісії дій %d/%d завершилась помилкою: %s. Повтор через %.2fs",
                attempt,
                active_policy.retry.max_attempts,
                exc,
                delay_sec,
            )
            if delay_sec > 0:
                time.sleep(delay_sec)
            delay_sec = min(
                max(delay_sec * active_policy.retry.backoff_multiplier, 0.0),
                active_policy.retry.max_backoff_sec,
            )

    raise RuntimeError(
        f"Емісія дій завершилась помилкою після retry (attempts={active_policy.retry.max_attempts})"
    ) from last_error


class AckDeduplicator:
    """Невеликий in-memory дедуплікатор для записів ActionAck."""

    def __init__(self, max_entries: int = 50000):
        self.max_entries = max(1, max_entries)
        self._seen: set[str] = set()
        self._order: deque[str] = deque()

    @staticmethod
    def _fingerprint(ack: ActionAck) -> str:
        raw = "|".join(
            [
                ack.action_id,
                ack.correlation_id,
                ack.result,
                ack.state_event,
                ack.applied_ts_utc,
                ack.error,
            ]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def is_new(self, ack: ActionAck) -> bool:
        fingerprint = self._fingerprint(ack)
        if fingerprint in self._seen:
            return False

        self._seen.add(fingerprint)
        self._order.append(fingerprint)

        while len(self._order) > self.max_entries:
            oldest = self._order.popleft()
            self._seen.discard(oldest)

        return True

    def filter_new(self, acks: list[ActionAck]) -> list[ActionAck]:
        """Повертає лише ті підтвердження, які ще не зустрічались."""
        return [ack for ack in acks if self.is_new(ack)]
