"""Action Contract -- commands from Analyzer to Emulator."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum


class ActionType(str, Enum):
    ENABLE_RATE_LIMIT = "enable_rate_limit"
    DISABLE_RATE_LIMIT = "disable_rate_limit"
    ISOLATE_COMPONENT = "isolate_component"
    RELEASE_ISOLATION = "release_isolation"
    BLOCK_ACTOR = "block_actor"
    UNBLOCK_ACTOR = "unblock_actor"
    BACKUP_DB = "backup_db"
    RESTORE_DB = "restore_db"
    DEGRADE_NETWORK = "degrade_network"
    RESET_NETWORK = "reset_network"
    CORRUPT_DB = "corrupt_db"


ACTION_CSV_COLUMNS = [
    "action_id",
    "ts_utc",
    "action",
    "target_component",
    "target_id",
    "params",
    "reason",
    "correlation_id",
    "status",
]


def _gen_action_id() -> str:
    return f"ACT-{uuid.uuid4().hex[:8]}"


@dataclass(slots=True)
class Action:
    """Command emitted by the Analyzer for the Emulator to apply."""

    ts_utc: str
    action: str
    target_component: str
    target_id: str = ""
    params: dict = field(default_factory=dict)
    reason: str = ""
    correlation_id: str = ""
    status: str = "pending"
    action_id: str = field(default_factory=_gen_action_id)

    def to_json(self) -> str:
        d = asdict(self)
        return json.dumps(d, ensure_ascii=False, separators=(",", ":"))

    def to_csv_row(self) -> str:
        params_str = json.dumps(self.params, ensure_ascii=False, separators=(",", ":"))
        vals = [
            self.action_id,
            self.ts_utc,
            self.action,
            self.target_component,
            self.target_id,
            params_str,
            self.reason,
            self.correlation_id,
            self.status,
        ]
        # Escape commas in fields
        escaped = []
        for v in vals:
            s = str(v)
            if "," in s or '"' in s:
                s = '"' + s.replace('"', '""') + '"'
            escaped.append(s)
        return ",".join(escaped)

    @staticmethod
    def csv_header() -> str:
        return ",".join(ACTION_CSV_COLUMNS)

    @classmethod
    def from_dict(cls, d: dict) -> Action:
        params = d.get("params", {})
        if isinstance(params, str):
            params = json.loads(params)
        return cls(
            ts_utc=d.get("ts_utc", ""),
            action=d.get("action", ""),
            target_component=d.get("target_component", ""),
            target_id=d.get("target_id", ""),
            params=params,
            reason=d.get("reason", ""),
            correlation_id=d.get("correlation_id", ""),
            status=d.get("status", "pending"),
            action_id=d.get("action_id", _gen_action_id()),
        )

    @classmethod
    def from_json(cls, line: str) -> Action:
        return cls.from_dict(json.loads(line))


# ═══════════════════════════════════════════════════════════════════════════
#  ActionAck -- confirmation written by the Emulator after apply_action
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class ActionAck:
    """Acknowledgement emitted by the Emulator after applying an action."""

    action_id: str
    correlation_id: str
    target_component: str
    action: str
    applied_ts_utc: str
    result: str  # "success" or "failed"
    error: str = ""
    state_event: str = ""  # e.g. "rate_limit_enabled"

    def to_json(self) -> str:
        d = asdict(self)
        return json.dumps(d, ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, line: str) -> ActionAck:
        d = json.loads(line)
        return cls(
            action_id=d.get("action_id", ""),
            correlation_id=d.get("correlation_id", ""),
            target_component=d.get("target_component", ""),
            action=d.get("action", ""),
            applied_ts_utc=d.get("applied_ts_utc", ""),
            result=d.get("result", ""),
            error=d.get("error", ""),
            state_event=d.get("state_event", ""),
        )
