"""Action Contract -- commands from Analyzer to Emulator."""

from __future__ import annotations

import json
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


ACTION_CSV_COLUMNS = [
    "ts_utc",
    "action",
    "target_component",
    "target_id",
    "params",
    "reason",
    "correlation_id",
    "status",
]


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

    def to_json(self) -> str:
        d = asdict(self)
        return json.dumps(d, ensure_ascii=False, separators=(",", ":"))

    def to_csv_row(self) -> str:
        params_str = json.dumps(self.params, ensure_ascii=False, separators=(",", ":"))
        vals = [
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
        )

    @classmethod
    def from_json(cls, line: str) -> Action:
        return cls.from_dict(json.loads(line))
