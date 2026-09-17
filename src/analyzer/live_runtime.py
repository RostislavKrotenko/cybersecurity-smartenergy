"""Персистентний потоковий runtime аналізатора SmartEnergy.

Модуль відновлює інциденти, дії та стан компонентів із CSV-файлів
після перезапуску Analyzer. Checkpoint-и JSONL при цьому відповідають
лише за позицію читання і не використовуються як сховище runtime-стану.
"""

from __future__ import annotations

import csv
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.analyzer.decision import decide, write_actions_csv
from src.analyzer.pipeline import (
    _apply_acks,
    _apply_restore_lock,
    _confirm_actions,
    _incremental_detect,
    _mark_actions_planned,
    _resolve_action_plan_path,
    _throttle_actions,
    _write_live_output,
)
from src.analyzer.policy_engine import get_modifiers, list_policy_names, load_policies
from src.analyzer.state_store import ComponentStateStore
from src.contracts.action import Action
from src.contracts.event import Event
from src.contracts.incident import Incident
from src.contracts.interfaces import ActionFeedback, ActionSink, EventSource
from src.shared.config_loader import load_yaml
from src.shared.reliability import (
    AckDeduplicator,
    IntegrationMode,
    build_reliability_policy_from_env,
    emit_actions_with_retry,
    parse_integration_mode,
)
from src.shared.time_utils import parse_iso_ts

log = logging.getLogger(__name__)

_INCIDENT_NUMBER_RE = re.compile(r"(\d+)$")
_AUTH_ACTORS_RE = re.compile(r"actors=(\d+)")
_AUTH_IPS_RE = re.compile(r"ips=(\d+)")


@dataclass(slots=True)
class AnalyzerRuntimeState:
    """Відновлений оперативний стан Analyzer."""

    incidents: list[Incident]
    actions: list[Action]
    incident_counter: int
    acted_incidents: set[str]


def _utc_now() -> datetime:
    """Повертає поточний час UTC."""
    return datetime.now(tz=timezone.utc)


def _parse_float(value: Any, default: float = 0.0) -> float:
    """Безпечно перетворює значення на число."""
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _parse_int(value: Any, default: int = 0) -> int:
    """Безпечно перетворює значення на ціле число."""
    try:
        if value in (None, ""):
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _parse_utc_timestamp(value: str) -> datetime | None:
    """Перетворює ISO-8601 timestamp на timezone-aware UTC."""
    if not value:
        return None

    try:
        parsed = parse_iso_ts(value)
    except (TypeError, ValueError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _detection_window_seconds(
    rules_cfg: dict[str, Any],
    policies_cfg: dict[str, Any],
    selected_policies: list[str],
) -> float:
    """Повертає найбільше часове вікно активних правил і політик."""
    largest_window = 1.0

    for rule in rules_cfg.get("rules", []):
        if not rule.get("enabled", True):
            continue

        base_window = max(1.0, float(rule.get("window_sec", 60)))
        threat_type = str(rule.get("threat_type", "unknown"))

        for policy_name in selected_policies:
            modifiers = get_modifiers(policies_cfg, policy_name)
            threat_modifiers = modifiers.get(threat_type, {})
            multiplier = max(
                0.1,
                float(threat_modifiers.get("window_multiplier", 1.0)),
            )
            largest_window = max(largest_window, base_window * multiplier)

    return largest_window


def _extend_detection_window(
    buffered_events: list[Event],
    new_events: list[Event],
    window_seconds: float,
) -> list[Event]:
    """Додає нові події та залишає лише актуальне вікно детекції."""
    timestamped_events: list[tuple[Event, datetime]] = []

    for event in [*buffered_events, *new_events]:
        parsed_timestamp = _parse_utc_timestamp(event.timestamp)
        if parsed_timestamp is not None:
            timestamped_events.append((event, parsed_timestamp))

    if not timestamped_events:
        return []

    latest_timestamp = max(timestamp for _, timestamp in timestamped_events)
    cutoff = latest_timestamp - timedelta(seconds=max(1.0, window_seconds))
    return [
        event
        for event, timestamp in timestamped_events
        if timestamp >= cutoff
    ]


def _incident_identity(incident: Incident) -> tuple[str, str, str, str, str]:
    """Повертає стабільну ознаку інциденту для дедуплікації."""
    return (
        incident.policy,
        incident.threat_type,
        incident.component,
        incident.source,
        incident.start_ts,
    )


def _incident_number(incident_id: str) -> int:
    """Отримує числову частину ідентифікатора інциденту."""
    match = _INCIDENT_NUMBER_RE.search(incident_id.strip())
    if match is None:
        return 0
    return int(match.group(1))


def _load_incidents(path: Path, rolling_window_sec: float) -> list[Incident]:
    """Завантажує активні інциденти з CSV."""
    if not path.exists():
        return []

    cutoff: datetime | None = None
    if rolling_window_sec > 0:
        cutoff = _utc_now() - timedelta(seconds=rolling_window_sec)

    incidents_by_id: dict[str, Incident] = {}

    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)

            for row in reader:
                incident_id = str(row.get("incident_id", "")).strip()
                if not incident_id:
                    continue

                start_ts = str(row.get("start_ts", "")).strip()
                parsed_start = _parse_utc_timestamp(start_ts)

                if cutoff is not None and parsed_start is not None and parsed_start < cutoff:
                    continue

                incident = Incident(
                    incident_id=incident_id,
                    policy=str(row.get("policy", "")),
                    threat_type=str(row.get("threat_type", "")),
                    severity=str(row.get("severity", "")),
                    component=str(row.get("component", "")),
                    event_count=_parse_int(row.get("event_count")),
                    start_ts=start_ts,
                    detect_ts=str(row.get("detect_ts", "")),
                    recover_ts=str(row.get("recover_ts", "")),
                    mttd_sec=_parse_float(row.get("mttd_sec")),
                    mttr_sec=_parse_float(row.get("mttr_sec")),
                    impact_score=_parse_float(row.get("impact_score")),
                    description=str(row.get("description", "")),
                    response_action=str(row.get("response_action", "")),
                    source=str(row.get("source", "")),
                )
                incidents_by_id[incident_id] = incident

    except (OSError, csv.Error) as error:
        log.warning("Не вдалося відновити інциденти з %s: %s", path, error)
        return []

    incidents = list(incidents_by_id.values())
    log.info("Відновлено %d активних інцидентів із %s", len(incidents), path)
    return incidents


def _load_actions(path: Path) -> list[Action]:
    """Завантажує історію дій Analyzer із CSV."""
    if not path.exists():
        return []

    actions_by_id: dict[str, Action] = {}

    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)

            for line_number, row in enumerate(reader, start=2):
                try:
                    action = Action.from_dict(row)
                except (TypeError, ValueError, KeyError) as error:
                    log.warning(
                        "Пропущено некоректну дію в %s:%d: %s",
                        path,
                        line_number,
                        error,
                    )
                    continue

                if not action.action_id:
                    continue

                actions_by_id[action.action_id] = action

    except (OSError, csv.Error) as error:
        log.warning("Не вдалося відновити дії з %s: %s", path, error)
        return []

    actions = list(actions_by_id.values())
    log.info("Відновлено %d дій із %s", len(actions), path)
    return actions


def load_runtime_state(out_dir: str | Path, rolling_window_sec: float) -> AnalyzerRuntimeState:
    """Відновлює оперативний стан Analyzer із директорії результатів.

    Лічильник інцидентів визначається не лише за incidents.csv,
    а й за correlation_id дій. Це запобігає повторному використанню
    старих ідентифікаторів після рестарту.
    """
    output_path = Path(out_dir)

    incidents = _load_incidents(output_path / "incidents.csv", rolling_window_sec)
    actions = _load_actions(output_path / "actions.csv")

    incident_counter = 0
    for incident in incidents:
        incident_counter = max(incident_counter, _incident_number(incident.incident_id))

    acted_incidents: set[str] = set()
    for action in actions:
        correlation_id = action.correlation_id.strip()
        if not correlation_id:
            continue

        acted_incidents.add(correlation_id)
        incident_counter = max(incident_counter, _incident_number(correlation_id))

    return AnalyzerRuntimeState(
        incidents=incidents,
        actions=actions,
        incident_counter=incident_counter,
        acted_incidents=acted_incidents,
    )


def restore_component_state(state_store: ComponentStateStore, path: str | Path) -> None:
    """Відновлює стан компонентів із state.csv."""
    state_path = Path(path)
    if not state_path.exists():
        return

    rows_by_component = {
        "gateway": state_store.gateway,
        "api": state_store.api,
        "auth": state_store.auth,
        "db": state_store.db,
        "network": state_store.network,
    }

    try:
        with state_path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)

            for source_row in reader:
                component = str(source_row.get("component", "")).strip()
                target_row = rows_by_component.get(component)
                if target_row is None:
                    continue

                target_row.status = (
                    str(source_row.get("status", "healthy")).strip() or "healthy"
                )
                target_row.details = str(source_row.get("details", ""))
                target_row.ttl_sec = max(0.0, _parse_float(source_row.get("ttl_sec")))
                target_row.expires_at_utc = str(source_row.get("expires_at_utc", "")).strip()
                target_row.last_updated = str(source_row.get("timestamp_utc", "")).strip()

                if component == "auth":
                    actors_match = _AUTH_ACTORS_RE.search(target_row.details)
                    ips_match = _AUTH_IPS_RE.search(target_row.details)

                    state_store._blocked_actors = (
                        int(actors_match.group(1)) if actors_match is not None else 0
                    )
                    state_store._blocked_ips = (
                        int(ips_match.group(1)) if ips_match is not None else 0
                    )

    except (OSError, csv.Error) as error:
        log.warning("Не вдалося відновити стан компонентів із %s: %s", state_path, error)
        return

    state_store.tick()
    log.info("Відновлено стан компонентів із %s", state_path)


def _index_actions(actions: list[Action]) -> tuple[dict[str, list[Action]], dict[str, Action]]:
    """Створює індекси дій за correlation_id та action_id."""
    by_correlation: dict[str, list[Action]] = {}
    by_id: dict[str, Action] = {}

    for action in actions:
        by_id[action.action_id] = action
        if action.correlation_id:
            by_correlation.setdefault(action.correlation_id, []).append(action)

    return by_correlation, by_id


def _restore_action_cooldowns(actions: list[Action]) -> dict[str, float]:
    """Відновлює приблизний cooldown нещодавніх дій.

    Монотонний час не можна зберігати між процесами, тому він
    відновлюється на основі UTC timestamp дії.
    """
    now_utc = _utc_now()
    now_monotonic = time.monotonic()
    restored: dict[str, float] = {}

    for action in actions:
        action_time = _parse_utc_timestamp(action.ts_utc)
        if action_time is None:
            continue

        age_sec = (now_utc - action_time).total_seconds()
        if age_sec < 0 or age_sec > 120:
            continue

        key = (
            f"{action.action}|"
            f"{action.target_component}|"
            f"{action.target_id}|"
            f"{action.params}"
        )
        restored[key] = now_monotonic - age_sec

    return restored


def _expire_incidents(
    incidents: list[Incident], rolling_window_sec: float
) -> tuple[list[Incident], int]:
    """Видаляє інциденти, що вийшли за межі рухомого вікна."""
    if rolling_window_sec <= 0 or not incidents:
        return incidents, 0

    cutoff = _utc_now() - timedelta(seconds=rolling_window_sec)
    active: list[Incident] = []

    for incident in incidents:
        start_time = _parse_utc_timestamp(incident.start_ts)
        if start_time is None or start_time >= cutoff:
            active.append(incident)

    expired_count = len(incidents) - len(active)
    if expired_count:
        log.info("Завершено строк відображення %d старих інцидентів", expired_count)

    return active, expired_count


def watch_pipeline_with_recovery(
    event_source: EventSource,
    out_dir: str = "out",
    policy_names: list[str] | None = None,
    config_dir: str = "config",
    horizon_days: float | None = None,
    poll_interval_sec: float = 1.0,
    rolling_window_min: float = 5.0,
    state_event_source: EventSource | None = None,
    action_sink: ActionSink | None = None,
    action_feedback: ActionFeedback | None = None,
    integration_mode: str = "active",
    shadow_actions_path: str | None = None,
) -> None:
    """Запускає потоковий Analyzer із відновленням після рестарту."""
    rules_cfg = load_yaml(f"{config_dir}/rules.yaml")
    policies_cfg = load_policies(config_dir)
    available = list_policy_names(policies_cfg)

    if policy_names is None or policy_names == ["all"]:
        selected = available
    else:
        selected = [policy for policy in policy_names if policy in available]

    mode = parse_integration_mode(integration_mode, default_mode=IntegrationMode.ACTIVE)
    reliability_policy = build_reliability_policy_from_env()
    ack_deduplicator = AckDeduplicator(max_entries=reliability_policy.ack_dedup_max_entries)

    rolling_sec = max(0.0, rolling_window_min * 60.0)
    detection_window_sec = _detection_window_seconds(
        rules_cfg,
        policies_cfg,
        selected,
    )
    detection_events: list[Event] = []

    if horizon_days is not None and horizon_days > 0:
        horizon_sec = horizon_days * 86400
    else:
        horizon_sec = max(rolling_sec, 3600.0)

    output_path = Path(out_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    restored = load_runtime_state(output_path, rolling_sec)
    incident_counter = restored.incident_counter
    all_incidents = restored.incidents
    all_actions = restored.actions
    acted_incidents = restored.acted_incidents

    actions_by_correlation, actions_by_id = _index_actions(all_actions)
    last_action_emit_ts = _restore_action_cooldowns(all_actions)

    state_store = ComponentStateStore()
    restore_component_state(state_store, output_path / "state.csv")

    write_actions_csv(all_actions, str(output_path / "actions.csv"))
    state_store.write_csv(str(output_path / "state.csv"))
    _write_live_output(
        all_incidents,
        selected,
        policies_cfg,
        horizon_sec,
        output_path,
        actions_count=len(all_actions),
    )

    iteration = 0
    tick_counter = 0
    feedback_offset: Any = None
    warned_no_action_sink = False

    print("Analyzer watch mode (checkpoint + runtime recovery)")
    print(f"  poll interval: {poll_interval_sec:.1f}s")
    print(f"  rolling window: {rolling_window_min:.0f} min")
    print(f"  policies: {', '.join(selected)}")
    print(f"  integration mode: {mode.value}")
    print(f"  restored incidents: {len(all_incidents)}")
    print(f"  restored actions: {len(all_actions)}")

    if action_sink is not None and mode == IntegrationMode.ACTIVE:
        print("  actions -> ActionSink")
    if action_feedback is not None and mode == IntegrationMode.ACTIVE:
        print("  applied <- ActionFeedback")
    if state_event_source is not None:
        print("  state <- EventSource (state stream)")
    if mode != IntegrationMode.ACTIVE:
        print("  безпечний режим: дії лише плануються")
    print("  Press Ctrl+C to stop.")

    event_iterator = event_source.read_stream(poll_interval_sec=poll_interval_sec)
    state_iterator = (
        state_event_source.read_stream(poll_interval_sec=poll_interval_sec)
        if state_event_source is not None
        else None
    )

    try:
        while True:
            tick_counter += 1
            new_events = next(event_iterator)
            state_events = next(state_iterator) if state_iterator is not None else []

            if mode == IntegrationMode.ACTIVE and action_feedback is not None:
                acknowledgements, feedback_offset = action_feedback.read_acks(since=feedback_offset)
                if acknowledgements:
                    unique_acknowledgements = ack_deduplicator.filter_new(acknowledgements)
                    duplicate_count = len(acknowledgements) - len(unique_acknowledgements)
                    if duplicate_count:
                        log.info("ACK DEDUP: відфільтровано %d повторних ACK", duplicate_count)

                    actions_changed = _apply_acks(
                        unique_acknowledgements,
                        actions_by_id,
                        all_actions,
                        state_store,
                    )
                    if actions_changed:
                        write_actions_csv(all_actions, str(output_path / "actions.csv"))

                    if unique_acknowledgements:
                        state_store.tick()
                        state_store.write_csv(str(output_path / "state.csv"))

            if state_events:
                state_store.process_events(state_events)
                if actions_by_correlation and _confirm_actions(
                    state_events,
                    actions_by_correlation,
                ):
                    write_actions_csv(all_actions, str(output_path / "actions.csv"))

            new_incidents: list[Incident] = []

            if new_events:
                iteration += 1
                state_store.process_events(new_events)

                detection_events = _extend_detection_window(
                    detection_events,
                    new_events,
                    detection_window_sec,
                )

                if actions_by_correlation and _confirm_actions(
                    new_events,
                    actions_by_correlation,
                ):
                    write_actions_csv(all_actions, str(output_path / "actions.csv"))

                (
                    incident_counter,
                    detected_incidents,
                ) = _incremental_detect(
                    detection_events,
                    rules_cfg,
                    policies_cfg,
                    selected,
                    incident_counter,
                    known_incidents={
                        _incident_identity(incident)
                        for incident in all_incidents
                    },
                )

                new_incidents = detected_incidents
                all_incidents.extend(detected_incidents)

                if detected_incidents:
                    new_actions = decide(detected_incidents, acted_incidents)
                    new_actions = _throttle_actions(new_actions, last_action_emit_ts)
                    new_actions = _apply_restore_lock(new_actions, all_actions)

                    if new_actions:
                        if mode == IntegrationMode.ACTIVE:
                            if action_sink is None:
                                if not warned_no_action_sink:
                                    log.warning("Активний режим не має ActionSink")
                                    warned_no_action_sink = True
                            else:
                                tracking_ids = emit_actions_with_retry(
                                    action_sink,
                                    new_actions,
                                    policy=reliability_policy,
                                    logger=log,
                                )

                                for action, tracking_id in zip(new_actions, tracking_ids):
                                    action.action_id = tracking_id

                                all_actions.extend(new_actions)

                                for action in new_actions:
                                    actions_by_id[action.action_id] = action
                                    if action.correlation_id:
                                        actions_by_correlation.setdefault(
                                            action.correlation_id, []
                                        ).append(action)

                                write_actions_csv(all_actions, str(output_path / "actions.csv"))
                                log.info(
                                    "Емітовано %d нових дій, разом %d",
                                    len(new_actions),
                                    len(all_actions),
                                )
                        else:
                            _mark_actions_planned(new_actions)
                            all_actions.extend(new_actions)

                            plan_path = _resolve_action_plan_path(
                                output_path,
                                mode,
                                shadow_actions_path,
                            )
                            write_actions_csv(all_actions, str(plan_path))

            all_incidents, expired_count = _expire_incidents(all_incidents, rolling_sec)
            state_store.tick()

            if new_events or state_events:
                state_store.write_csv(str(output_path / "state.csv"))

            if new_events or expired_count:
                _write_live_output(
                    all_incidents,
                    selected,
                    policies_cfg,
                    horizon_sec,
                    output_path,
                    actions_count=len(all_actions),
                )

            if new_events:
                log.info(
                    "[tick %d] iter %d: +%d events, +%d state, +%d incidents, %d active, %d actions",
                    tick_counter,
                    iteration,
                    len(new_events),
                    len(state_events),
                    len(new_incidents),
                    len(all_incidents),
                    len(all_actions),
                )
            elif state_events:
                log.info("[tick %d] state-only: +%d подій стану", tick_counter, len(state_events))
            elif tick_counter % 10 == 0:
                state_store.write_csv(str(output_path / "state.csv"))
                log.info(
                    "[tick %d] Heartbeat: %d active incidents, %d actions",
                    tick_counter,
                    len(all_incidents),
                    len(all_actions),
                )

    except KeyboardInterrupt:
        print(
            f"\nAnalyzer зупинено. Активних інцидентів: {len(all_incidents)}, "
            f"дій: {len(all_actions)}"
        )
    finally:
        event_source.close()
        if state_event_source is not None:
            state_event_source.close()
        if action_feedback is not None:
            action_feedback.close()
        if action_sink is not None:
            action_sink.close()
