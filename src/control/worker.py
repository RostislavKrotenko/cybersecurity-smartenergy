"""Worker для виконання дій Analyzer через захисний Gateway."""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.contracts.action import Action, ActionAck as ContractActionAck
from src.control.dispatcher import ActionDispatcher
from src.control.gateway_control import GatewayControlSettings, HttpGatewayControl
from src.control.idempotency import IdempotencyStore
from src.control.models import ActionStatus, ActionType, SecurityAction

log = logging.getLogger(__name__)


def _utc_now() -> str:
    """Повертає поточний час у форматі ISO-8601 UTC."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class WorkerSettings:
    """Налаштування worker керувальних команд."""

    actions_path: Path
    applied_path: Path
    idempotency_path: Path
    poll_interval_sec: float
    gateway_service_id: str
    default_rate_per_second: float
    default_burst_capacity: int
    allowed_isolation_components: frozenset[str]

    @classmethod
    def from_env(cls) -> "WorkerSettings":
        """Створює налаштування зі змінних середовища."""
        try:
            poll_interval_sec = float(os.getenv("CONTROL_POLL_INTERVAL_SEC", "0.5"))
            default_rate_per_second = float(os.getenv("CONTROL_DEFAULT_RATE_PER_SECOND", "25"))
            default_burst_capacity = int(os.getenv("CONTROL_DEFAULT_BURST_CAPACITY", "50"))
        except ValueError as error:
            raise ValueError("Числові параметри control worker некоректні") from error

        allowed_components = frozenset(
            item.strip()
            for item in os.getenv(
                "CONTROL_ALLOWED_ISOLATION_COMPONENTS",
                "gateway,api,edge,iot-gateway",
            ).split(",")
            if item.strip()
        )

        if poll_interval_sec <= 0:
            raise ValueError("CONTROL_POLL_INTERVAL_SEC має бути більше нуля")

        return cls(
            actions_path=Path(os.getenv("CONTROL_ACTIONS_PATH", "/work/data/integration/actions.jsonl")),
            applied_path=Path(os.getenv("CONTROL_APPLIED_PATH", "/work/data/integration/actions_applied.jsonl")),
            idempotency_path=Path(os.getenv("CONTROL_IDEMPOTENCY_PATH", "/work/data/integration/control/idempotency.sqlite3")),
            poll_interval_sec=poll_interval_sec,
            gateway_service_id=os.getenv("CONTROL_GATEWAY_SERVICE_ID", "iot-gateway").strip(),
            default_rate_per_second=default_rate_per_second,
            default_burst_capacity=default_burst_capacity,
            allowed_isolation_components=allowed_components,
        )


class ActionTailSource:
    """Читає нові Action із JSONL-файла Analyzer."""

    def __init__(self, path: str | Path) -> None:
        """Ініціалізує tail-читання файла дій."""
        self._path = Path(path)
        self._offset = 0
        self._inode: int | None = None

    def read_batch(self, limit: int = 1000) -> list[Action]:
        """Зчитує пакет нових дій після поточного offset."""
        if not self._path.exists() or limit < 1:
            return []

        try:
            stat = self._path.stat()
        except OSError:
            return []

        if self._inode is not None and self._inode != stat.st_ino:
            self._offset = 0

        if stat.st_size < self._offset:
            self._offset = 0

        self._inode = stat.st_ino
        actions: list[Action] = []

        try:
            with self._path.open("r", encoding="utf-8") as stream:
                stream.seek(self._offset)

                while len(actions) < limit:
                    line_start = stream.tell()
                    line = stream.readline()

                    if not line:
                        break

                    if not line.endswith("\n"):
                        stream.seek(line_start)
                        break

                    stripped = line.strip()
                    if not stripped:
                        continue

                    try:
                        action = Action.from_json(stripped)
                    except (ValueError, TypeError, KeyError):
                        log.exception("Пропущено некоректний Action")
                        continue

                    actions.append(action)

                self._offset = stream.tell()

        except OSError:
            log.exception("Не вдалося прочитати файл дій %s", self._path)

        return actions


class ActionAckWriter:
    """Записує підтвердження дій у JSONL для Analyzer."""

    def __init__(self, path: str | Path) -> None:
        """Ініціалізує вихідний файл ACK."""
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, ack: ContractActionAck) -> None:
        """Додає одне підтвердження до JSONL-файла."""
        with self._path.open("a", encoding="utf-8") as stream:
            stream.write(ack.to_json())
            stream.write("\n")
            stream.flush()


class GatewayActionWorker:
    """Передає дозволені дії Analyzer до нашого Gateway."""

    def __init__(
        self,
        *,
        settings: WorkerSettings,
        dispatcher: ActionDispatcher,
    ) -> None:
        """Створює worker активного реагування."""
        self._settings = settings
        self._dispatcher = dispatcher
        self._source = ActionTailSource(settings.actions_path)
        self._ack_writer = ActionAckWriter(settings.applied_path)

    async def run(self, stop_event: asyncio.Event) -> None:
        """Обробляє нові дії до отримання сигналу завершення."""
        log.info("Control worker читає дії з %s", self._settings.actions_path)

        while not stop_event.is_set():
            actions = self._source.read_batch()

            for action in actions:
                if action.status not in {"pending", "emitted"}:
                    continue

                ack = await self._process_action(action)
                self._ack_writer.write(ack)

                log.info(
                    "Action %s завершено з результатом %s",
                    action.action_id,
                    ack.result,
                )

            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=self._settings.poll_interval_sec,
                )
            except TimeoutError:
                pass

    async def close(self) -> None:
        """Закриває Dispatcher та HTTP-клієнт."""
        await self._dispatcher.close()

    async def _process_action(self, action: Action) -> ContractActionAck:
        """Перетворює Action і виконує дозволену команду."""
        try:
            security_action = self._map_action(action)
        except (ValueError, TypeError) as error:
            return self._failed_ack(action, str(error))

        if security_action is None:
            return self._failed_ack(
                action,
                "Дія не належить до повноважень Cybersecurity Gateway",
            )

        gateway_ack = await self._dispatcher.dispatch(security_action)
        success = gateway_ack.status == ActionStatus.APPLIED
        state_event = str(gateway_ack.gateway_response.get("action", "")) if gateway_ack.gateway_response else ""

        return ContractActionAck(
            action_id=action.action_id,
            correlation_id=action.correlation_id,
            target_component=action.target_component,
            action=action.action,
            applied_ts_utc=_utc_now(),
            result="success" if success else "failed",
            error="" if success else gateway_ack.message,
            state_event=state_event,
        )

    def _map_action(self, action: Action) -> SecurityAction | None:
        """Перетворює універсальний Action на команду Gateway."""
        params = action.params or {}
        reason = action.reason.strip() or f"Автоматична дія {action.action}"

        if action.action == "enable_rate_limit":
            return SecurityAction(
                action_id=action.action_id,
                action_type=ActionType.SET_RATE_LIMIT,
                target=self._settings.gateway_service_id,
                service_id=self._settings.gateway_service_id,
                reason=reason,
                ttl_seconds=self._optional_duration(params),
                parameters={
                    "enabled": True,
                    "rate_per_second": params.get("rps", self._settings.default_rate_per_second),
                    "burst_capacity": params.get("burst", self._settings.default_burst_capacity),
                },
            )

        if action.action == "disable_rate_limit":
            return SecurityAction(
                action_id=action.action_id,
                action_type=ActionType.SET_RATE_LIMIT,
                target=self._settings.gateway_service_id,
                service_id=self._settings.gateway_service_id,
                reason=reason,
                parameters={
                    "enabled": False,
                    "rate_per_second": self._settings.default_rate_per_second,
                    "burst_capacity": self._settings.default_burst_capacity,
                },
            )

        if action.action in {"isolate_component", "release_isolation"}:
            if action.target_component not in self._settings.allowed_isolation_components:
                return None

            action_type = (
                ActionType.ISOLATE_SERVICE
                if action.action == "isolate_component"
                else ActionType.RESTORE_SERVICE
            )

            return SecurityAction(
                action_id=action.action_id,
                action_type=action_type,
                target=action.target_id or action.target_component,
                service_id=self._settings.gateway_service_id,
                reason=reason,
                ttl_seconds=(
                    self._optional_duration(params)
                    if action_type == ActionType.ISOLATE_SERVICE
                    else None
                ),
            )

        if action.action in {"block_actor", "unblock_actor"}:
            identity = str(
                params.get("ip") or params.get("actor") or action.target_id or ""
            ).strip()

            if not identity:
                raise ValueError("Для блокування не визначено actor або IP")

            action_type = (
                ActionType.BLOCK_SOURCE
                if action.action == "block_actor"
                else ActionType.UNBLOCK_SOURCE
            )

            return SecurityAction(
                action_id=action.action_id,
                action_type=action_type,
                target=identity,
                service_id=self._settings.gateway_service_id,
                reason=reason,
                ttl_seconds=(
                    self._optional_duration(params, default=600.0)
                    if action_type == ActionType.BLOCK_SOURCE
                    else None
                ),
            )

        return None

    @staticmethod
    def _optional_duration(params: dict[str, Any], default: float | None = None) -> float | None:
        """Читає тривалість дії з її параметрів."""
        raw_value = params.get("duration_sec", params.get("ttl_sec", default))

        if raw_value is None:
            return None

        duration = float(raw_value)

        if duration <= 0:
            raise ValueError("Тривалість дії має бути більше нуля")

        return duration

    @staticmethod
    def _failed_ack(action: Action, message: str) -> ContractActionAck:
        """Створює негативне підтвердження без зовнішньої дії."""
        return ContractActionAck(
            action_id=action.action_id,
            correlation_id=action.correlation_id,
            target_component=action.target_component,
            action=action.action,
            applied_ts_utc=_utc_now(),
            result="failed",
            error=message,
        )


def create_worker(settings: WorkerSettings) -> GatewayActionWorker:
    """Створює worker з HTTP GatewayControl та ідемпотентністю."""
    control = HttpGatewayControl(GatewayControlSettings.from_env())
    idempotency_store = IdempotencyStore(settings.idempotency_path)
    
    dispatcher = ActionDispatcher(
        gateway_control=control,
        idempotency_store=idempotency_store,
    )

    return GatewayActionWorker(
        settings=settings,
        dispatcher=dispatcher,
    )