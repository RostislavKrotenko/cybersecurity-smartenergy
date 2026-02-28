# SmartEnergy Cyber-Resilience Analyzer

> Master's thesis prototype — a reproducible experimental pipeline for
> evaluating the impact of cybersecurity policy levels on smart-grid
> infrastructure resilience.

```
┌──────────┐    ┌────────────┐    ┌──────────┐    ┌───────────┐
│ Emulator │───▶│ Normalizer │───▶│ Analyzer │───▶│ Dashboard │
└──────────┘    └────────────┘    └──────────┘    └───────────┘
  data/events.csv                   out/*           :8501
```

---

## Table of Contents

1. [Modules Overview](#modules-overview)
2. [Quick Start — Local (venv)](#quick-start--local-venv)
3. [Quick Start — Docker](#quick-start--docker)
4. [Configuration Reference](#configuration-reference)
5. [Extending the System](#extending-the-system)
6. [Interpreting Results](#interpreting-results)
7. [Testing & Quality](#testing--quality)
8. [Makefile Targets](#makefile-targets)
9. [Troubleshooting](#troubleshooting)
10. [Project Structure](#project-structure)

---

## Modules Overview

### 1. Emulator (`src/emulator/`)

Deterministic synthetic event generator for smart-grid infrastructure.
Takes `config/scenarios.yaml` and `config/components.yaml`, outputs a
flat CSV file (`data/events.csv`) conforming to the 12-field Event Contract.

- **Seed-based reproducibility**: `--seed 42` always produces exactly 4 507 events.
- **Background traffic**: telemetry reads, HTTP access, auth success, system health.
- **5 attack scenarios**: brute-force, DDoS/API flood, telemetry spoofing,
  unauthorized command execution, cascading outage/DB corruption.
- Each attack has its own `correlation_prefix` (e.g. `COR-BF-*`) enabling
  downstream correlation.

```bash
python -m src.emulator --seed 42          # → data/events.csv
```

### 2. Normalizer (`src/normalizer/`)

Converts heterogeneous raw log files (syslog, JSON-like, ISO timestamps)
into the unified Event Contract CSV — used when real log data is available
instead of synthetic events.

- **3 built-in profiles**: `api` (ISO-space timestamps), `auth` (syslog),
  `edge` (ISO-T timestamps). Configured in `config/mapping.yaml`.
- **Quarantine**: lines that fail parsing go to `out/quarantine.csv` with a
  reason tag (no regex match, missing required fields, etc.).
- **Deduplication**: fingerprint-based sliding-window dedup (default 2 s window).

```bash
python -m src.normalizer --mapping config/mapping.yaml \
    --log-dir logs/ --output data/events.csv
```

### 3. Analyzer (`src/analyzer/`)

Light SIEM-like analytics module — the core of the prototype.
Reads `data/events.csv`, runs 5 detection rules, correlates alerts into
incidents, computes availability/downtime metrics **per policy level**, and
generates CSV/TXT/HTML/PNG reports.

- **Detection** (5 rule groups, defined in `config/rules.yaml`):
  brute-force (sliding window), DDoS (rate + impact), telemetry spoofing
  (bounds + delta), unauthorized command (actor allowlist), outage (status check).
- **Correlation**: groups alerts by `correlation_id` → time-adjacent clusters →
  merged incidents with computed MTTD / MTTR.
- **Policy comparison**: evaluates each incident under all 3 policies (minimal /
  baseline / standard) using multipliers from `config/policies.yaml`.
- **Metrics**: Availability %, Downtime (hr), Mean MTTD (min), Mean MTTR (min).
- **Reports**: `results.csv`, `incidents.csv`, `report.txt`, `report.html`,
  and 3 comparative bar charts in `out/plots/`.

```bash
python -m src.analyzer --input data/events.csv --horizon-days 1
```

### 4. Dashboard (`src/dashboard/`)

Interactive Streamlit web UI for exploring analysis results.

- **Overview tab**: KPI cards (availability, downtime, MTTD, MTTR) + bar charts.
- **Incidents tab**: filterable list with severity badges and expandable details.
- **Data tab**: raw event browser with summary statistics.
- Sidebar: run analysis on-demand, upload custom CSV/JSONL, select policies, set horizon.
- **Live mode**: auto-refresh toggle (requires `streamlit-autorefresh`).

```bash
streamlit run src/dashboard/app.py        # → http://localhost:8501
```

---

## Quick Start — Local (venv)

**Prerequisites**: Python 3.11+ and `make` (or run commands manually).

```bash
# 1. Create virtual environment & install dependencies
make install
# Equivalent to:
#   python3 -m venv .venv
#   .venv/bin/pip install -r requirements.txt

# 2. Generate synthetic events (seed=42, 4 507 events)
make generate
# Expected output:
#   data/events.csv  (4 509 lines including header)

# 3. Run Analyzer (default: --horizon-days 1, all 3 policies)
make analyze
# Expected output files:
#   out/results.csv      — 1 row per policy (3 rows)
#   out/incidents.csv    — 42 incidents across 3 policies
#   out/report.txt       — human-readable summary
#   out/report.html      — HTML version
#   out/plots/availability.png
#   out/plots/downtime.png
#   out/plots/mttd_mttr.png

# 4. Launch interactive Dashboard
make ui
# Open http://localhost:8501

# Or run the full pipeline in one command:
make demo-local         # generate → analyze → ui
```

### Live Demo — Local

Run the Emulator in **live (streaming) mode** and the Analyzer in **watch mode**
so events flow continuously through the pipeline.

```bash
# Terminal 1: Emulator streams events to JSONL with 500 ms delays
python -m src.emulator --live --live-interval-ms 500 \
    --out data/events_live.jsonl

# Terminal 2: Analyzer tails the JSONL and re-analyses on new data
python -m src.analyzer --input data/events_live.jsonl --watch \
    --poll-interval-ms 1000

# Terminal 3: Dashboard with auto-refresh enabled in sidebar
streamlit run src/dashboard/app.py
```

In the dashboard sidebar enable **Live mode > Auto-refresh** to see
results update automatically every few seconds.

### JSONL Input

The Analyzer auto-detects file format by extension (`.csv` or `.jsonl`).
You can also explicitly produce JSONL from the Emulator in batch mode:

```bash
python -m src.emulator --format jsonl --out data/events.jsonl
python -m src.analyzer --input data/events.jsonl
```

---

## Quick Start — Docker

**Prerequisites**: Docker Engine 24.0+, Docker Compose v2.20+.

```bash
# One-command demo (build → emulate → analyze → dashboard)
make demo
# → opens http://localhost:8501 (press Ctrl+C to stop)

# Or step-by-step:
docker compose build
docker compose run --rm emulator        # → data/events.csv
docker compose run --rm analyzer        # → out/*
docker compose up ui                    # → :8501
```

**Alternative — Normalizer path** (real log files):

```bash
# Place .log files in logs/
docker compose run --rm normalizer      # → data/events.csv + out/quarantine.csv
docker compose run --rm analyzer
docker compose up ui
```

| Service      | Type     | Profile          | Input → Output                    |
|-------------|----------|-----------------|-----------------------------------|
| `emulator`   | one-shot | generate, demo  | config/ → data/events.csv         |
| `normalizer` | one-shot | normalize       | logs/*.log → data/events.csv      |
| `analyzer`   | one-shot | analyze, demo   | data/events.csv → out/*           |
| `ui`         | long-run | ui, demo        | out/* → http://localhost:8501      |

All services share bind-mounted volumes (`data/`, `out/`, `config/`, `logs/`)
so files persist on the host.

```bash
make docker-down        # stop all containers
make docker-clean       # stop + remove images & volumes
```

---

## Configuration Reference

All configuration lives in `config/` as human-readable YAML files.

### `components.yaml` — Infrastructure Topology

Defines the smart-grid components used by the Emulator.

| Field         | Description                                       |
|---------------|---------------------------------------------------|
| `type`        | Component class: `gateway`, `meter`, `inverter`, etc. |
| `criticality` | `low` / `medium` / `high` / `critical`            |
| `zone`        | Network zone: `scada`, `dmz`, `corporate`          |
| `instances`   | List of `{id, ip, protocols}`                      |
| `depends_on`  | Dependency links for cascading-failure modelling    |

### `scenarios.yaml` — Simulation & Attack Scenarios

Controls the Emulator's behaviour.

- **`simulation`**: `duration_sec` (default 3600), `seed` (default 42),
  `start_time`.
- **`background`**: 4 traffic generators (telemetry, access, auth,
  system_health) with `interval_sec`, `keys`, `severity`.
- **`attacks`**: 5 named scenarios — each defines `schedule`
  (start/duration), `injection` phases (events, rates, severity
  progression), and a `correlation_prefix`.

### `rules.yaml` — Detection Rules

Maps event patterns to alert types. The Analyzer's `Detector` loads these.

| Rule ID       | Name               | Threat Type          | Window | Threshold |
|---------------|--------------------|----------------------|--------|-----------|
| RULE-BF-001   | Brute-Force        | credential_attack    | 60 s   | ≥ 5       |
| RULE-DDOS-001 | DDoS / API Flood   | availability_attack  | 30 s   | ≥ 10      |
| RULE-SPOOF-001| Telemetry Spoofing | integrity_attack     | 60 s   | ≥ 3       |
| RULE-UCMD-001 | Unauthorized Cmd   | integrity_attack     | 120 s  | ≥ 1       |
| RULE-OUT-001  | Service Outage     | outage               | 60 s   | ≥ 1       |
| RULE-OUT-002  | DB Corruption      | outage               | 120 s  | ≥ 2       |

### `policies.yaml` — Security Policy Levels

Three policy profiles compared side-by-side during analysis:

| Policy     | Controls Enabled              | Philosophy                    |
|-----------|-------------------------------|-------------------------------|
| **minimal**  | monitoring, logging           | Worst-case: no active defence |
| **baseline** | all 7 (soft thresholds)       | Typical small-enterprise setup|
| **standard** | all 7 (strict + auto-block)   | Production-ready hardened     |

Each policy defines **6 multipliers** per `threat_type` that modify
detection/response timing:

| Multiplier             | Effect                                         |
|------------------------|-------------------------------------------------|
| `prob_multiplier`      | Attack success probability scaling              |
| `impact_multiplier`    | Blast radius scaling                            |
| `mttd_multiplier`      | Mean Time To Detect — lower = faster detection  |
| `mttr_multiplier`      | Mean Time To Recover — lower = faster recovery  |
| `threshold_multiplier` | Rule threshold scaling (lower = more sensitive)  |
| `window_multiplier`    | Rule time-window scaling (higher = wider context)|

### `mapping.yaml` — Normalizer Profiles

Defines how raw log lines are parsed into Event Contract fields.

| Profile | File pattern     | Timestamp format        | Example source |
|---------|-----------------|-------------------------|----------------|
| `api`   | `*_api.log`     | ISO-8601 with space     | API gateway    |
| `auth`  | `*_auth.log`    | Syslog (`Feb 26 …`)    | Auth subsystem |
| `edge`  | `*_edge.log`    | ISO-8601 with `T`      | IoT gateways   |

---

## Extending the System

### Adding a New Attack Scenario

1. **Define the scenario** in `config/scenarios.yaml` under `attacks:`:

   ```yaml
   attacks:
     my_new_attack:
       enabled: true
       description: "Description of the new attack"
       threat_type: integrity_attack    # or credential_attack, availability_attack, outage
       target_components: [api]
       target_sources: [api-gw-01]
       schedule:
         start_offset_sec: [600, 900]
         duration_sec: [60, 120]
       injection:
         - event: suspicious_event
           keys:
             - { key: payload, values: [malicious_data] }
           interval_ms: [500, 2000]
           count: [5, 20]
           severity: high
           tags: ["attack", "custom"]
       correlation_prefix: "COR-NEW"
   ```

2. **Create a scenario class** in `src/emulator/scenarios/`:

   ```python
   # src/emulator/scenarios/my_new_attack.py
   from src.emulator.scenarios.base import BaseScenario

   class MyNewAttackScenario(BaseScenario):
       SCENARIO_KEY = "my_new_attack"
       # implement generate() method
   ```

3. **Register** the scenario in `src/emulator/scenarios/__init__.py`.

### Adding a New Detection Rule

1. **Add rule definition** to `config/rules.yaml`:

   ```yaml
   rules:
     - id: RULE-NEW-001
       name: "My New Rule"
       threat_type: integrity_attack
       detector: my_new_check
       window_sec: 60
       threshold: 3
       severity: high
   ```

2. **Implement the detector method** in `src/analyzer/detector.py`:

   ```python
   def _detect_my_new_check(self, events, rule):
       # Filter relevant events, apply window/threshold logic
       # Return list of Alert objects
       ...
   ```

3. **Add policy multipliers** (optional) — if the rule uses a new
   `threat_type`, add corresponding multiplier entries in
   `config/policies.yaml` under each policy's `modifiers:` section.

---

## Interpreting Results

### `out/results.csv` — Policy Comparison Table

Each row represents one policy evaluation. Key columns:

| Column              | Meaning                                                        |
|---------------------|----------------------------------------------------------------|
| `policy`            | Policy name (`minimal`, `baseline`, `standard`)                |
| `availability_pct`  | System availability = $(1 - \frac{\text{downtime}}{\text{horizon}}) \times 100\%$ |
| `total_downtime_hr` | Cumulative downtime in hours (merged overlapping severity ≥ high intervals) |
| `mean_mttd_min`     | **Mean Time To Detect** — average minutes from incident start to first alert |
| `mean_mttr_min`     | **Mean Time To Recover** — average minutes from detection to service restoration |
| `incidents_total`   | Number of distinct incidents under this policy                 |
| `incidents_critical`| Count of incidents with critical severity                      |
| `by_*`              | Breakdown by threat type (credential/availability/integrity/outage) |

**Example output** (seed=42, horizon=1 day):

| Policy   | Avail % | Downtime (hr) | MTTD (min) | MTTR (min) | Incidents |
|----------|---------|---------------|------------|------------|-----------|
| minimal  | 95.39   | 1.11          | 1.83       | 13.04      | 13        |
| baseline | 98.37   | 0.39          | 0.69       | 4.07       | 15        |
| standard | 99.39   | 0.15          | 0.32       | 1.55       | 14        |

**How to read**: *standard* achieves 99.39 % availability with a mean
detection time of only 19 seconds (0.32 min) and recovery in 1.55 min.
*minimal* detects threats 5.7× slower and recovers 8.4× slower, dropping
availability to 95.39 %.

> **Note**: *baseline* may report more incidents than *minimal* — this is
> expected because lower thresholds (more sensitive rules) detect events
> that *minimal* misses entirely.

### `out/incidents.csv` — Incident Details

One row per incident per policy. Key fields:

| Field           | Meaning                                          |
|-----------------|--------------------------------------------------|
| `incident_id`   | Unique ID (e.g. `INC-001`)                       |
| `mttd_sec`      | Seconds from `start_ts` to `detect_ts`           |
| `mttr_sec`      | Seconds from `detect_ts` to `recover_ts`         |
| `impact_score`  | 0.0–1.0 normalized impact (1.0 = maximum)        |
| `response_action` | Recommended action: `block_ip`, `notify_oncall`, etc. |

### `out/plots/` — Comparative Charts

| File                | Description                                      |
|---------------------|--------------------------------------------------|
| `availability.png`  | Bar chart: availability % per policy             |
| `downtime.png`      | Bar chart: total downtime (hours) per policy     |
| `mttd_mttr.png`     | Grouped bar chart: MTTD vs MTTR per policy       |

### `out/report.txt` — Human-Readable Summary

Text report with per-policy metrics, cross-policy comparison
(best/worst availability, best/worst MTTR), and a ranked list of the
most effective control sets with effectiveness scores.

---

## Testing & Quality

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all fast tests (207 tests)
make test

# Run seed reproducibility tests (full emulator, marked @slow)
make test-slow

# Tests with coverage report
make test-cov

# Lint with ruff
make lint

# Auto-format with ruff
make format
```

### Test Coverage

| Test file | Module | Tests | What is tested |
|---|---|---|---|
| `test_emulator.py` | emulator | 18 | Seed reproducibility (SHA-256 hash), device index, writers, engine init |
| `test_detector.py` | analyzer.detector | 28 | Brute-force, DDoS, telemetry-spoof, unauthorized-cmd, outage detection |
| `test_metrics.py` | analyzer.metrics | 14 | `_merge_intervals`, `compute()` availability/downtime formulas, CSV serialisation |
| `test_correlator.py` | analyzer.correlator | 18 | COR-ID grouping, time-window grouping, impact score, MTTD/MTTR timing |
| `test_normalizer.py` | normalizer | 13 | Parser success/quarantine, dedup, validation |
| `test_parser.py` | normalizer.parser | 20 | Profile build/select, line parsing, severity/component detection, IP/actor/KV extraction |
| `test_filters.py` | normalizer.filters | 18 | Deduplication window, fingerprint, validation rules |
| `test_normalizer_pipeline.py` | normalizer.pipeline | 6 | End-to-end pipeline, quarantine, dedup, timezone |
| `test_contracts.py` | contracts | 13 | Event/Alert/Incident fields, CSV/JSON round-trips, enums |
| `test_policy_engine.py` | policy_engine | 10 | Modifiers, metadata, ranking, effectiveness |
| `test_integration.py` | E2E pipeline | 4 | detect → correlate → metrics flow, mixed attacks, policy comparison |

### CI

GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push and PR:
- Ruff lint + format check
- Full test suite with coverage (Python 3.11 / 3.12 / 3.13)
- Seed-reproducibility tests

The workflow file is located at `.github/workflows/ci.yml`.

---

## Makefile Targets

```
make help               # Show all available targets
```

| Target            | Description                               |
|-------------------|-------------------------------------------|
| `install`         | Create venv + install dependencies        |
| `generate`        | Local: run emulator (seed=42)             |
| `normalize`       | Local: run normalizer on logs/            |
| `analyze`         | Local: run analyzer (horizon=1 day)       |
| `ui`              | Local: start Streamlit dashboard          |
| `demo-local`      | Local: generate → analyze → ui            |
| `demo`            | Docker: build → generate → analyze → ui   |
| `docker-build`    | Build Docker image                        |
| `docker-generate` | Docker: run emulator                      |
| `docker-normalize`| Docker: run normalizer                    |
| `docker-analyze`  | Docker: run analyzer                      |
| `docker-ui`       | Docker: start Streamlit UI                |
| `docker-down`     | Stop all containers                       |
| `docker-clean`    | Stop + remove images & volumes            |
| `clean`           | Remove generated data & outputs           |
| `test`            | Run fast tests (207 tests)                |
| `test-slow`       | Run seed reproducibility tests            |
| `test-cov`        | Tests with coverage report                |
| `lint`            | Run ruff linter                           |
| `format`          | Auto-format code with ruff                |

---

## Troubleshooting

| Problem                                          | Fix                                                         |
|--------------------------------------------------|-------------------------------------------------------------|
| `Cannot connect to the Docker daemon`            | Start Docker Desktop / `sudo systemctl start docker`        |
| `port 8501 already in use`                       | `make docker-down` or `lsof -i :8501` and kill the process  |
| UI shows "No analysis results found"             | Run the Analyzer first: `make analyze` or click **Run analysis** in the sidebar |
| `ModuleNotFoundError: No module named 'src'`     | Run all commands from the repository root directory          |
| Negative availability (e.g. −10%)                | Use `--horizon-days 1` (or higher) to set a realistic analysis window |
| Emulator produces different event count           | Ensure `--seed 42` is used for deterministic output (4 507 events) |

---

## Project Structure

```
CyberSecurity/
├── config/
│   ├── components.yaml        # Infrastructure topology (devices, zones, IPs)
│   ├── scenarios.yaml         # Simulation params + 5 attack definitions
│   ├── rules.yaml             # 6 detection rules (thresholds, windows)
│   ├── policies.yaml          # 3 policy levels (controls + multipliers)
│   └── mapping.yaml           # Normalizer profiles (3 log formats)
├── data/
│   └── events.csv             # 12-field Event Contract CSV (generated)
├── logs/
│   ├── sample_api.log         # Example raw API logs
│   ├── sample_auth.log        # Example raw syslog auth logs
│   └── sample_edge.log        # Example raw IoT edge logs
├── out/
│   ├── results.csv            # Policy comparison metrics (1 row per policy)
│   ├── incidents.csv          # Detailed incident list (42 rows)
│   ├── report.txt             # Human-readable summary
│   ├── report.html            # HTML report
│   └── plots/
│       ├── availability.png   # Availability % bar chart
│       ├── downtime.png       # Downtime (hr) bar chart
│       └── mttd_mttr.png      # MTTD vs MTTR grouped bar chart
├── src/
│   ├── contracts/             # Shared dataclasses: Event, Alert, Incident
│   ├── emulator/              # Synthetic event generator (5 scenarios)
│   │   └── scenarios/         # BaseScenario + 5 attack implementations
│   ├── normalizer/            # Raw logs → Event Contract CSV
│   ├── analyzer/              # Detector → Correlator → Metrics → Reporter
│   └── dashboard/             # Streamlit web UI (app.py)
├── tests/                     # 207 pytest tests (11 modules)
├── docs/
│   └── EXPERIMENTS.md         # Experimental design & methodology
├── Dockerfile                 # python:3.11-slim single-stage image
├── docker-compose.yml         # 4 services with profiles
├── Makefile                   # 20+ targets (local + Docker)
├── pyproject.toml             # pytest + ruff configuration
├── requirements.txt           # Runtime dependencies
├── requirements-dev.txt       # Dev dependencies (pytest, ruff)
├── ARCHITECTURE.md            # System architecture document
├── EVENT_CONTRACT.md          # Event Contract specification
└── README.md                  # ← you are here
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

Master's thesis prototype -- Krotenko Rostislav, 2025-2026.
