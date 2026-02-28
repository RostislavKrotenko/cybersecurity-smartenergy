"""Canonical enumerations for the Event Contract."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Component(str, Enum):
    EDGE = "edge"
    API = "api"
    DB = "db"
    UI = "ui"
    COLLECTOR = "collector"
    INVERTER = "inverter"
    NETWORK = "network"


class EventType(str, Enum):
    TELEMETRY_READ = "telemetry_read"
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    HTTP_REQUEST = "http_request"
    RATE_EXCEEDED = "rate_exceeded"
    CMD_EXEC = "cmd_exec"
    SERVICE_STATUS = "service_status"
    DB_ERROR = "db_error"
    PORT_STATUS = "port_status"
    POWER_OUTPUT = "power_output"
    RAW_LOG = "raw_log"
