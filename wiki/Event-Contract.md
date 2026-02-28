# Event Contract

All modules in SmartEnergy exchange data through a single normalised event schema defined in `src/contracts/event.py`.

## Event fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | string | yes | ISO-8601 datetime in **UTC** (must end with `Z` or `+00:00`) |
| `source` | string | yes | Identifier of the originating device or service (e.g. `api-gw-01`) |
| `component` | string | yes | Logical component: `edge`, `api`, `db`, `ui`, `collector`, `inverter`, `network` |
| `event` | string | yes | Event type (see below) |
| `key` | string | yes | Metric or log key (e.g. `message`, `voltage`, `status`) |
| `value` | string | yes | Payload value (numeric or textual) |
| `severity` | string | yes | `low`, `medium`, `high`, or `critical` |
| `actor` | string | no | Username or service account performing the action |
| `ip` | string | no | Source IP address |
| `unit` | string | no | Unit of measurement (e.g. `V`, `ms`, `req/s`) |
| `tags` | string | no | Semicolon-separated free-form tags |
| `correlation_id` | string | no | Identifier linking related events (format: `COR-XXXX`) |

## Event types

Defined in `src/contracts/enums.py`:

| Value | Meaning |
|-------|---------|
| `telemetry_read` | Sensor or inverter reading |
| `auth_failure` | Failed authentication attempt |
| `auth_success` | Successful authentication |
| `http_request` | HTTP API call |
| `rate_exceeded` | Rate limit exceeded |
| `cmd_exec` | Command execution on a device |
| `service_status` | Service health status change |
| `db_error` | Database error |
| `port_status` | Network port status change |
| `power_output` | Power generation reading |
| `raw_log` | Unstructured log line |

## Timestamp convention

**Storage:** all timestamps are in UTC. The emulator generates them with a `Z` suffix. The normaliser preserves UTC. CSV and JSONL output files contain only UTC timestamps.

**Display:** the dashboard converts UTC timestamps to the timezone selected in the sidebar (default: `Europe/Kyiv`) for chart axes and table columns. This conversion is applied in `src/dashboard/ui/charts.py` (function `incidents_per_minute`) and `src/dashboard/data_access.py` (pandas `utc=True` parsing). No other module performs timezone conversion.

**Why UTC:** storing everything in UTC eliminates ambiguity when correlating events across components and avoids daylight-saving-time edge cases.

## Serialisation formats

| Format | Location | Notes |
|--------|----------|-------|
| CSV | `data/events.csv`, `data/live/events.csv` | Comma-separated, header row, fields in column order above |
| JSONL | `data/live/events.jsonl` | One JSON object per line, keys match field names above |

## Alert and Incident contracts

Events flow into the detector, which produces `Alert` objects (see `src/contracts/alert.py`). The correlator groups alerts into `Incident` objects (see `src/contracts/incident.py`). Both contracts store timestamps in UTC following the same convention.
