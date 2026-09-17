"""Worker для виконання дій Analyzer через захисний Gateway."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.contracts.action import Action, ActionAck as ContractActionAck
from src.control.dispatcher import ActionDispatcher
from src.control.gateway_control import GatewayControlSettings, HttpGatewayControl
from src.control.idempotency import IdempotencyStore
from src.control.models import ActionStatus, ActionType, SecurityAction
from src.shared.file_utils import atomic_write, load_offset_checkpoint, save_offset_checkpoint

log = logging.getLogger(__name__)

_GATEWAY_ACTION_TO_STATE_EVENT: dict[str, str] = {
    "block_actor": "actor_blocked",
    "unblock_actor": "actor_unblocked",
    "enable_rate_limit": "rate_limit_enabled",
    "disable_rate_limit": "rate_limit_disabled",
    "isolate_component": "isolation_enabled",
    "release_isolation": "isolation_released",
}


def _utc_now() -> str:
    """Повертає поточний час у форматі ISO-8601 UTC."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class WorkerSettings:
    """Налаштування worker керувальних команд."""

    actions_path: Path
    applied_path: Path
    idempotency_path: Path
    actions_checkpoint_path: Path
    recovery_schedule_path: Path
    poll_interval_sec: float
    gateway_service_id: str
    default_rate_per_second: float
    default_burst_capacity: int
    allowed_isolation_components: frozenset[str]
    accept_generic_actions: bool

    @classmethod
    def from_env(cls) -> "WorkerSettings":
        """Створює налаштування зі змінних середовища."""
        try:
            poll_interval_sec = float(os.getenv("CONTROL_POLL_INTERVAL_SEC", "0.5"))
            default_rate_per_second = float(os.getenv("CONTROL_DEFAULT_RATE_PER_SECOND", "25"))
            default_burst_capacity = int(os.getenv("CONTROL_DEFAULT_BURST_CAPACITY", "50"))
        except ValueError as error:
            raise ValueError("Числові параметри control worker некоректні") from error

        if poll_interval_sec <= 0:
            raise ValueError("CONTROL_POLL_INTERVAL_SEC має бути більше нуля")

        if default_rate_per_second <= 0:
            raise ValueError("CONTROL_DEFAULT_RATE_PER_SECOND має бути більше нуля")

        if default_burst_capacity < 1:
            raise ValueError("CONTROL_DEFAULT_BURST_CAPACITY має бути не менше 1")

        allowed_components = frozenset(
            item.strip()
            for item in os.getenv(
                "CONTROL_ALLOWED_ISOLATION_COMPONENTS",
                "gateway,api,edge,iot-gateway",
            ).split(",")
            if item.strip()
        )

        accept_generic_actions = os.getenv(
            "CONTROL_ACCEPT_GENERIC_ACTIONS",
            "true",
        ).strip().lower() in {"1", "true", "yes", "on"}

        return cls(
            actions_path=Path(
                os.getenv("CONTROL_ACTIONS_PATH", "/work/data/integration/actions.jsonl")
            ),
            applied_path=Path(
                os.getenv("CONTROL_APPLIED_PATH", "/work/data/integration/actions_applied.jsonl")
            ),
            idempotency_path=Path(
                os.getenv(
                    "CONTROL_IDEMPOTENCY_PATH",
                    "/work/data/integration/control/idempotency.sqlite3",
                )
            ),
            actions_checkpoint_path=Path(
                os.getenv(
                    "CONTROL_ACTIONS_CHECKPOINT_PATH",
                    "/work/data/integration/checkpoints/control-actions.json",
                )
            ),
            recovery_schedule_path=Path(
                os.getenv(
                    "CONTROL_RECOVERY_SCHEDULE_PATH",
                    os.getenv(
                        "CONTROL_ISOLATION_SCHEDULE_PATH",
                        "/work/data/integration/control/recovery-schedule.json",
                    ),
                )
            ),
            poll_interval_sec=poll_interval_sec,
            gateway_service_id=os.getenv("CONTROL_GATEWAY_SERVICE_ID", "iot-gateway").strip(),
            default_rate_per_second=default_rate_per_second,
            default_burst_capacity=default_burst_capacity,
            allowed_isolation_components=allowed_components,
            accept_generic_actions=accept_generic_actions,
        )


class ActionTailSource:
    """Читає нові Action із JSONL-файла Analyzer.

    Позиція читання зберігається лише після успішного
    оброблення всього пакета дій.
    """

    def __init__(self, path: str | Path, checkpoint_path: str | Path) -> None:
        """Ініціалізує tail-читання та відновлює offset."""
        self._path = Path(path)
        self._checkpoint_path = Path(checkpoint_path)
        self._offset, self._inode = load_offset_checkpoint(self._checkpoint_path, self._path)

    def read_batch(self, limit: int = 1000) -> list[Action]:
        """Зчитує пакет нових дій після поточного offset."""
        if limit < 1 or not self._path.exists():
            return []

        try:
            source_stat = self._path.stat()
        except OSError:
            log.exception("Не вдалося отримати стан файла дій %s", self._path)
            return []

        if self._inode is not None and self._inode != source_stat.st_ino:
            log.info("Файл дій %s було замінено — offset скинуто", self._path)
            self._offset = 0

        if source_stat.st_size < self._offset:
            log.info("Файл дій %s було скорочено — offset скинуто", self._path)
            self._offset = 0

        self._inode = source_stat.st_ino
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
                    except (json.JSONDecodeError, ValueError, TypeError, KeyError) as error:
                        log.warning("Пропущено некоректний Action: %s", error)
                        continue

                    actions.append(action)

                self._offset = stream.tell()

        except OSError:
            log.exception("Не вдалося прочитати файл дій %s", self._path)

        return actions

    def commit(self) -> None:
        """Зберігає позицію після успішного оброблення пакета."""
        save_offset_checkpoint(self._checkpoint_path, self._path, self._offset, self._inode)


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


@dataclass(slots=True)
class ScheduledRecovery:
    """Персистентна автоматична дія відновлення Gateway."""

    recovery_type: str
    source_action_id: str
    target_component: str
    target_id: str
    correlation_id: str
    due_at_epoch: float
    params: dict[str, Any]
    attempt: int = 0

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ScheduledRecovery":
        """Створює автоматичне відновлення з JSON-словника."""
        recovery_type = str(value.get("recoveryType", "")).strip()
        source_action_id = str(value.get("sourceActionId", "")).strip()
        target_component = str(value.get("targetComponent", "")).strip()
        target_id = str(value.get("targetId", "")).strip()
        correlation_id = str(value.get("correlationId", "")).strip()
        due_at_epoch = float(value.get("dueAtEpoch", 0.0))
        attempt = max(0, int(value.get("attempt", 0)))
        params = value.get("params") or {}

        if recovery_type not in {"release_isolation", "restore_rate_limit"}:
            raise ValueError("Невідомий тип автоматичного відновлення")
        if not source_action_id:
            raise ValueError("Розклад не містить sourceActionId")
        if not target_component:
            raise ValueError("Розклад не містить targetComponent")
        if due_at_epoch <= 0:
            raise ValueError("Розклад містить некоректний dueAtEpoch")
        if not isinstance(params, dict):
            raise ValueError("Параметри розкладу мають бути JSON-об'єктом")

        return cls(
            recovery_type=recovery_type,
            source_action_id=source_action_id,
            target_component=target_component,
            target_id=target_id or target_component,
            correlation_id=correlation_id,
            due_at_epoch=due_at_epoch,
            params=dict(params),
            attempt=attempt,
        )

    def to_dict(self) -> dict[str, Any]:
        """Перетворює автоматичне відновлення на JSON-словник."""
        return {
            "recoveryType": self.recovery_type,
            "sourceActionId": self.source_action_id,
            "targetComponent": self.target_component,
            "targetId": self.target_id,
            "correlationId": self.correlation_id,
            "dueAtEpoch": self.due_at_epoch,
            "params": self.params,
            "attempt": self.attempt,
        }

    def action_id(self) -> str:
        """Формує стабільний actionId для поточної спроби."""
        digest = hashlib.sha256(
            (
                f"{self.recovery_type}:{self.source_action_id}:"
                f"{self.attempt}"
            ).encode("utf-8")
        ).hexdigest()[:20]
        return f"AUTO-RECOVERY-{digest}"

    def to_action(self, gateway_service_id: str) -> Action:
        """Створює керувальну дію для відповідного відновлення."""
        common_params = {
            "scheduled_from": self.source_action_id,
            "scheduled_recovery": self.recovery_type,
            "gateway_service_id": gateway_service_id,
            "attempt": self.attempt,
        }

        if self.recovery_type == "release_isolation":
            action_name = "release_isolation"
            params = common_params
            reason = (
                "Автоматичне зняття ізоляції після завершення "
                f"TTL дії {self.source_action_id}"
            )
        else:
            action_name = "enable_rate_limit"
            params = {**common_params, **self.params}
            reason = (
                "Автоматичне повернення базового rate limit після "
                f"дії {self.source_action_id}"
            )

        return Action(
            action_id=self.action_id(),
            ts_utc=_utc_now(),
            action=action_name,
            target_component=self.target_component,
            target_id=self.target_id,
            params=params,
            reason=reason,
            correlation_id=self.correlation_id,
            status="emitted",
        )


class RecoveryScheduleStore:
    """Зберігає персистентні відкладені відновлення одного Gateway."""

    def __init__(self, path: str | Path) -> None:
        """Ініціалізує сховище та завантажує розклад із диска."""
        self._path = Path(path)
        self._scheduled = self._load()

    def schedule(
        self,
        *,
        recovery_type: str,
        action: Action,
        duration_sec: float,
        params: dict[str, Any] | None = None,
        now_epoch: float | None = None,
    ) -> ScheduledRecovery:
        """Створює або оновлює одну відкладену дію відновлення."""
        if duration_sec <= 0:
            raise ValueError("Тривалість відновлення має бути більше нуля")

        current = self._scheduled.get(recovery_type)
        if current is not None and current.source_action_id == action.action_id:
            return current

        effective_now = time.time() if now_epoch is None else float(now_epoch)
        scheduled = ScheduledRecovery(
            recovery_type=recovery_type,
            source_action_id=action.action_id,
            target_component=action.target_component,
            target_id=action.target_id or action.target_component,
            correlation_id=action.correlation_id,
            due_at_epoch=effective_now + duration_sec,
            params=dict(params or {}),
        )
        self._scheduled[recovery_type] = scheduled
        self._save()
        return scheduled

    def get_due(
        self,
        *,
        now_epoch: float | None = None,
    ) -> list[ScheduledRecovery]:
        """Повертає всі відновлення, строк яких уже настав."""
        effective_now = time.time() if now_epoch is None else float(now_epoch)
        return [
            scheduled
            for scheduled in self._scheduled.values()
            if scheduled.due_at_epoch <= effective_now
        ]

    def postpone(
        self,
        recovery_type: str,
        source_action_id: str,
        delay_sec: float,
        *,
        now_epoch: float | None = None,
    ) -> None:
        """Переносить невдалу спробу автоматичного відновлення."""
        scheduled = self._scheduled.get(recovery_type)
        if scheduled is None or scheduled.source_action_id != source_action_id:
            return

        effective_now = time.time() if now_epoch is None else float(now_epoch)
        scheduled.attempt += 1
        scheduled.due_at_epoch = effective_now + max(1.0, delay_sec)
        self._save()

    def clear(
        self,
        recovery_type: str,
        source_action_id: str | None = None,
    ) -> None:
        """Видаляє виконане або скасоване відновлення."""
        scheduled = self._scheduled.get(recovery_type)
        if scheduled is None:
            return
        if source_action_id is not None and scheduled.source_action_id != source_action_id:
            return

        self._scheduled.pop(recovery_type, None)
        self._save()

    def _load(self) -> dict[str, ScheduledRecovery]:
        """Завантажує розклад і підтримує попередній формат ізоляції."""
        if not self._path.exists():
            return {}

        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Файл розкладу має містити JSON-об'єкт")

            raw_schedules = payload.get("schedules")
            if isinstance(raw_schedules, dict):
                result: dict[str, ScheduledRecovery] = {}
                for recovery_type, raw_schedule in raw_schedules.items():
                    if not isinstance(raw_schedule, dict):
                        continue
                    enriched = {**raw_schedule, "recoveryType": recovery_type}
                    scheduled = ScheduledRecovery.from_dict(enriched)
                    result[scheduled.recovery_type] = scheduled
                return result

            legacy_release = payload.get("release")
            if isinstance(legacy_release, dict):
                scheduled = ScheduledRecovery.from_dict(
                    {
                        **legacy_release,
                        "recoveryType": "release_isolation",
                        "params": {},
                    }
                )
                return {scheduled.recovery_type: scheduled}
            return {}
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
            log.warning("Не вдалося завантажити розклад відновлення %s: %s", self._path, error)
            return {}

    def _save(self) -> None:
        """Атомарно зберігає всі заплановані відновлення."""
        payload = {
            "version": 2,
            "schedules": {
                recovery_type: scheduled.to_dict()
                for recovery_type, scheduled in self._scheduled.items()
            },
        }
        atomic_write(
            str(self._path),
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
        )


class GatewayActionWorker:
    """Передає дозволені дії Analyzer до захисного Gateway."""

    def __init__(self, *, settings: WorkerSettings, dispatcher: ActionDispatcher) -> None:
        """Створює worker активного реагування."""
        self._settings = settings
        self._dispatcher = dispatcher

        self._source = ActionTailSource(
            settings.actions_path,
            settings.actions_checkpoint_path,
        )
        self._ack_writer = ActionAckWriter(settings.applied_path)
        self._recovery_schedule = RecoveryScheduleStore(
            settings.recovery_schedule_path
        )

    async def run(self, stop_event: asyncio.Event) -> None:
        """Обробляє дії до отримання сигналу завершення."""
        log.info("Control worker читає дії з %s", self._settings.actions_path)

        while not stop_event.is_set():
            await self._process_due_recoveries()

            actions = self._source.read_batch()

            for action in actions:
                if action.status not in {"pending", "emitted"}:
                    continue

                if not self._targets_this_gateway(action):
                    continue

                ack = await self._process_action(action)
                self._ack_writer.write(ack)

                self._update_recovery_schedule(action, ack)

                log.info(
                    "Action %s завершено з результатом %s",
                    action.action_id,
                    ack.result,
                )

            self._source.commit()

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

    async def _process_due_recoveries(self) -> None:
        """Виконує всі прострочені автоматичні відновлення Gateway."""
        for scheduled in self._recovery_schedule.get_due():
            action = scheduled.to_action(self._settings.gateway_service_id)
            ack = await self._process_action(action)
            self._ack_writer.write(ack)

            if ack.result == "success":
                self._recovery_schedule.clear(
                    scheduled.recovery_type,
                    scheduled.source_action_id,
                )
                log.info(
                    "Автоматичне відновлення %s для дії %s виконано",
                    scheduled.recovery_type,
                    scheduled.source_action_id,
                )
                continue

            retry_delay = min(
                60.0,
                float(2 ** min(scheduled.attempt + 1, 6)),
            )
            self._recovery_schedule.postpone(
                scheduled.recovery_type,
                scheduled.source_action_id,
                retry_delay,
            )
            log.warning(
                "Автоматичне відновлення %s не виконано; "
                "наступна спроба через %.1f с",
                scheduled.recovery_type,
                retry_delay,
            )

    def _update_recovery_schedule(
        self,
        action: Action,
        ack: ContractActionAck,
    ) -> None:
        """Оновлює розклад після успішної керувальної дії."""
        if ack.result != "success":
            return

        if action.action == "isolate_component":
            duration_sec = self._optional_duration(action.params or {}, default=60.0)

            if duration_sec is not None:
                self._recovery_schedule.schedule(
                    recovery_type="release_isolation",
                    action=action,
                    duration_sec=duration_sec,
                )
                log.info(
                    "Заплановано автоматичне зняття ізоляції %s через %.1f с",
                    action.action_id,
                    duration_sec,
                )

        elif action.action == "release_isolation":
            self._recovery_schedule.clear("release_isolation")

        elif action.action == "enable_rate_limit":
            params = action.params or {}
            if params.get("scheduled_recovery") == "restore_rate_limit":
                self._recovery_schedule.clear("restore_rate_limit")
                return

            duration_sec = self._optional_duration(params)
            if duration_sec is None:
                return

            self._recovery_schedule.schedule(
                recovery_type="restore_rate_limit",
                action=action,
                duration_sec=duration_sec,
                params={
                    "rps": self._settings.default_rate_per_second,
                    "burst": self._settings.default_burst_capacity,
                },
            )
            log.info(
                "Заплановано повернення базового rate limit після %s "
                "через %.1f с",
                action.action_id,
                duration_sec,
            )

        elif action.action == "disable_rate_limit":
            self._recovery_schedule.clear("restore_rate_limit")

    async def _process_action(self, action: Action) -> ContractActionAck:
        """Перетворює Action та виконує дозволену команду."""
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

        gateway_action = (
            str(gateway_ack.gateway_response.get("action", "")).strip()
            if gateway_ack.gateway_response
            else ""
        )

        state_event = _GATEWAY_ACTION_TO_STATE_EVENT.get(gateway_action, "") if success else ""

        return ContractActionAck(
            action_id=action.action_id,
            correlation_id=action.correlation_id,
            target_component=action.target_component,
            action=action.action,
            applied_ts_utc=_utc_now(),
            result="success" if success else "failed",
            error="" if success else gateway_ack.message,
            state_event=state_event,
            service_id=self._settings.gateway_service_id,
            details=dict(action.params or {}),
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
                    self._optional_duration(params, default=60.0)
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

    def _targets_this_gateway(self, action: Action) -> bool:
        """Перевіряє, чи адресовано дію поточному Gateway."""

        params = action.params or {}
        explicit_service_id = str(
            params.get("gateway_service_id")
            or params.get("service_id")
            or ""
        ).strip()

        if explicit_service_id:
            return explicit_service_id == self._settings.gateway_service_id

        if action.action in {
            "enable_rate_limit",
            "disable_rate_limit",
            "isolate_component",
            "release_isolation",
        }:
            target_id = action.target_id.strip()
            if target_id == self._settings.gateway_service_id:
                return True
            if target_id and target_id not in {"gateway", "api"}:
                return False

        return self._settings.accept_generic_actions

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
            service_id=self._settings.gateway_service_id,
            details=dict(action.params or {}),
        )


def create_worker(settings: WorkerSettings) -> GatewayActionWorker:
    """Створює worker з HTTP-клієнтом та ідемпотентністю."""
    control = HttpGatewayControl(GatewayControlSettings.from_env())
    idempotency_store = IdempotencyStore(settings.idempotency_path)
    dispatcher = ActionDispatcher(gateway_control=control, idempotency_store=idempotency_store)

    return GatewayActionWorker(settings=settings, dispatcher=dispatcher)
