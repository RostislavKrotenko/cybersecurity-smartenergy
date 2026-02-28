# Metrics

Resilience metrics are computed by `src/analyzer/metrics.py` for each security policy. The input is a list of `Incident` objects produced by the correlator.

## Downtime definition

**Downtime = `detect_ts` to `recover_ts`** for every incident with severity >= high.

This interval covers only MTTR (time from detection to full recovery). MTTD (time before the incident is detected) is **not** counted as downtime because the system is not yet confirmed to be impaired until detection occurs. MTTD and MTTR are computed independently and reported as separate metrics.

Overlapping intervals across concurrent incidents are **merged** before summing, so the same wall-clock second is never counted twice.

Incidents that lack a `detect_ts` or `recover_ts` value are **skipped** for downtime calculation but still counted in `incidents_total`.

```
total_downtime = SUM(recover_ts - detect_ts)   # after merging overlaps
```

Only incidents with `severity` in {`high`, `critical`} contribute to downtime. Incidents rated `low` or `medium` are tracked but do not reduce availability.

## Formulas

| Metric | Formula | Unit |
|--------|---------|------|
| `availability_pct` | `(1 - total_downtime / horizon) * 100` | % |
| `total_downtime_hr` | merged sum of `(recover_ts - detect_ts)` for severity >= high | hours |
| `mean_mttd_min` | `avg(mttd_sec) / 60` across all incidents | minutes |
| `mean_mttr_min` | `avg(mttr_sec) / 60` across all incidents | minutes |
| `incidents_total` | count of all incidents | -- |

### Incident timing (set by the correlator)

For each incident the correlator computes three timestamps and two durations:

| Field | Meaning |
|-------|---------|
| `start_ts` | Timestamp of the first event that triggered the alert group |
| `detect_ts` | `start_ts + MTTD` (simulated detection latency) |
| `recover_ts` | `detect_ts + MTTR` (simulated recovery time) |
| `mttd_sec` | `base_mttd * mttd_multiplier` (seconds) |
| `mttr_sec` | `base_mttr * mttr_multiplier` (seconds) |

`mttd_multiplier` and `mttr_multiplier` come from the active policy (see [[Policies]]).

## Horizon

The analysis horizon (`horizon_sec`) is the total time window over which availability is calculated. It is typically set to the duration covered by the event dataset (e.g. `--horizon-days 1` = 86400 seconds). When `horizon_sec` is zero, availability defaults to 100%.

## Interval merging

If two high/critical incidents overlap in time, their `[detect_ts, recover_ts)` intervals are merged into one continuous block:

```
INC-001:  |-------|
INC-002:      |---------|
merged:   |-------------|
```

This prevents double-counting of the same downtime period.

## Timestamps and timezones

All timestamps stored in CSV and JSONL files use **UTC** (ISO-8601 with `Z` or `+00:00` suffix). No conversion to local time occurs during metrics computation.

The dashboard converts timestamps to the user-selected display timezone (default: `Europe/Kyiv`) **only for chart rendering and table display**. The timezone selector is in the sidebar. This conversion is purely cosmetic and does not affect any computed metric value.
