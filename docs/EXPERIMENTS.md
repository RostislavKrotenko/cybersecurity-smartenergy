# Experimental Design & Methodology

> This document describes the experimental setup, threat scenarios,
> metric definitions, and result interpretation methodology used in the
> SmartEnergy Cyber-Resilience Analyzer prototype.

---

## Table of Contents

1. [Research Question](#research-question)
2. [Independent Variable — Security Policies](#independent-variable--security-policies)
3. [Dependent Variables — Resilience Metrics](#dependent-variables--resilience-metrics)
4. [Threat Model — 5 Attack Scenarios](#threat-model--5-attack-scenarios)
5. [Metric Computation Formulas](#metric-computation-formulas)
6. [Experimental Procedure](#experimental-procedure)
7. [Results Template](#results-template)
8. [Drawing Conclusions](#drawing-conclusions)

---

## Research Question

> **How does the level of cybersecurity controls (minimal / baseline /
> standard) affect the availability, detection speed, and recovery time
> of a smart-grid energy system under a fixed set of cyber-attacks?**

The experiment is a **controlled simulation**: the same event stream
(identical seed, identical attack timing) is evaluated under three
policy configurations that differ only in their security controls and
the corresponding detection/response multipliers.

---

## Independent Variable — Security Policies

The independent variable is the **policy level** applied during analysis.
All three policies process the same input event stream; they differ in
the security controls enabled and the resulting multipliers.

### Policy Summary

| Policy     | Controls (7 possible)                       | Multiplier Profile          |
|-----------|---------------------------------------------|-----------------------------|
| **minimal**  | 2/7 — monitoring + logging only             | High MTTD/MTTR (slow)      |
| **baseline** | 7/7 — all enabled, soft thresholds          | 1.0× (reference point)     |
| **standard** | 7/7 — all enabled, strict + auto-blocking   | Low MTTD/MTTR (fast)       |

### Control Matrix

| Control          | minimal | baseline | standard |
|------------------|---------|----------|----------|
| MFA              | ✗       | ✓ soft   | ✓ strict |
| RBAC             | ✗       | ✓ warn   | ✓ block  |
| Rate Limiting    | ✗       | ✓ log    | ✓ auto-block |
| Monitoring       | ✓ 30 s  | ✓ 10 s   | ✓ 2 s    |
| Logging          | ✓ basic | ✓ audit  | ✓ tamper-proof |
| Backup           | ✗       | ✓ 2 hr   | ✓ 15 min |
| Segmentation     | ✗       | ✓ 2 zones| ✓ 3 zones + micro |

### Multiplier Values (credential_attack example)

| Multiplier         | minimal | baseline | standard |
|--------------------|---------|----------|----------|
| `prob_multiplier`  | 1.50    | 1.00     | 0.30     |
| `impact_multiplier`| 1.30    | 1.00     | 0.50     |
| `mttd_multiplier`  | 2.50    | 1.00     | 0.30     |
| `mttr_multiplier`  | 3.00    | 1.00     | 0.40     |
| `threshold_mult`   | 2.00    | 1.00     | 0.60     |
| `window_multiplier`| 0.50    | 1.00     | 1.50     |

Full multiplier tables for all 4 threat types are in `config/policies.yaml`.

---

## Dependent Variables — Resilience Metrics

Four metrics are computed per policy:

| Metric               | Unit    | Interpretation                                    |
|----------------------|---------|---------------------------------------------------|
| **Availability**     | %       | Proportion of the horizon the system was operational|
| **Total Downtime**   | hours   | Cumulative time the system was impaired            |
| **Mean MTTD**        | minutes | Average time from attack start to first detection  |
| **Mean MTTR**        | minutes | Average time from detection to service restoration |

Additionally, **incident count** and **severity distribution** are tracked
per policy.

---

## Threat Model — 5 Attack Scenarios

All scenarios run within a 1-hour simulation window. The Emulator
generates events on a fixed timeline; attacks are injected at
pre-configured offsets.

### Scenario 1 — Brute-Force (credential_attack)

| Parameter         | Value                                           |
|-------------------|-------------------------------------------------|
| Correlation ID    | `COR-BF-*`                                      |
| Target            | `gateway-01`, `scada-hmi-01` (API / edge zones) |
| Offset            | 5–10 min from start                             |
| Duration          | 1–3 min                                         |
| Mechanism         | 15–50 `auth_failure` events at 200–1 500 ms intervals, escalating severity |
| Success prob.     | 30 % chance of follow-up `auth_success` (simulating successful breach) |
| Detection rule    | `RULE-BF-001` — ≥ 5 `auth_failure` in 60 s window |

### Scenario 2 — DDoS / API Flood (availability_attack)

| Parameter         | Value                                           |
|-------------------|-------------------------------------------------|
| Correlation ID    | `COR-DDOS-*`                                    |
| Target            | `api-gw-01` (DMZ)                               |
| Offset            | 15–20 min                                       |
| Duration          | 2–5 min                                         |
| Mechanism         | 100–500 `rate_exceeded` events at 50–500 ms; followed by `service_status: degraded/down` |
| Detection rule    | `RULE-DDOS-001` — ≥ 10 `rate_exceeded` in 30 s window |

### Scenario 3 — Telemetry Spoofing (integrity_attack)

| Parameter         | Value                                           |
|-------------------|-------------------------------------------------|
| Correlation ID    | `COR-SPOOF-*`                                   |
| Target            | `meter-17`, `inverter-03` (SCADA zone)          |
| Offset            | 25–30 min                                       |
| Duration          | 1–2 min                                         |
| Mechanism         | `telemetry_read` with physically impossible values: voltage 500–1 200 V (norm 220–240), power −800 to −200 kW, freq 30–45 Hz (norm 49.8–50.2). Disguised as severity=low. |
| Detection rule    | `RULE-SPOOF-001` — ≥ 3 out-of-range values in 60 s (bounds check + delta threshold) |

### Scenario 4 — Unauthorized Command (integrity_attack)

| Parameter         | Value                                           |
|-------------------|-------------------------------------------------|
| Correlation ID    | `COR-UCMD-*`                                    |
| Target            | `scada-hmi-01` (API zone)                       |
| Offset            | 35–40 min                                       |
| Duration          | 15–45 s                                         |
| Mechanism         | 2–8 `cmd_exec` events by non-allowed actors (`readonly`, `unknown`, `guest`) with critical commands (`breaker_open`, `emergency_shutdown`, etc.) |
| Detection rule    | `RULE-UCMD-001` — ≥ 1 `cmd_exec` by non-allowed actor in 120 s |

### Scenario 5 — Cascading Outage / DB Corruption (outage)

| Parameter         | Value                                           |
|-------------------|-------------------------------------------------|
| Correlation ID    | `COR-OUT-*`                                     |
| Target            | `db-primary`, `api-gw-01`, `collector-01`       |
| Offset            | 45–50 min                                       |
| Duration          | 2–5 min                                         |
| Mechanism         | Phase 1: 3–8 `db_error` events (integrity_violation, wal_corruption). Phase 2: cascading `service_status: degraded/down`. Phase 3: recovery (`recovering` → `healthy`). |
| Detection rules   | `RULE-OUT-001` (≥ 1 status event in 60 s), `RULE-OUT-002` (≥ 2 DB errors in 120 s) |

### Attack Timeline

```
 T+0    T+5m    T+10m   T+15m   T+20m   T+25m   T+30m   T+35m   T+40m   T+45m   T+50m   T+60m
  │       │───────│       │───────│       │───────│       │───────│       │───────│       │
  │       └ BruteForce    └ DDoS          └ Spoof         └ UnAuth       └ Outage        │
  │                                                                                       │
  └───────────────────────── Background traffic (telemetry, HTTP, auth, health) ──────────┘
```

---

## Metric Computation Formulas

### Availability

$$
\text{Availability} = \left(1 - \frac{D_{\text{total}}}{H}\right) \times 100\%
$$

Where:
- $D_{\text{total}}$ = total downtime in seconds (merged overlapping intervals)
- $H$ = analysis horizon in seconds (default: 86 400 s = 1 day)

Only incidents with **severity ≥ high** contribute to downtime. Overlapping
intervals are merged to avoid double-counting.

### Downtime (merged intervals)

Given a set of incidents $\{I_1, I_2, \ldots, I_n\}$ where each $I_k$ has
interval $[s_k, e_k]$ = $[\text{detect\_ts}_k, \text{recover\_ts}_k]$:

1. Sort intervals by $s_k$
2. Merge overlapping intervals: if $s_{k+1} \le e_k$, extend to $\max(e_k, e_{k+1})$
3. $D_{\text{total}} = \sum_j (e'_j - s'_j)$ over merged intervals

### Mean Time To Detect (MTTD)

$$
\text{MTTD} = \frac{1}{N} \sum_{i=1}^{N} (\text{detect\_ts}_i - \text{start\_ts}_i)
$$

Where $N$ = number of incidents. MTTD is modulated by the policy's
`mttd_multiplier`:

$$
\text{MTTD}_{\text{eff}} = \text{MTTD}_{\text{base}} \times m_{\text{mttd}}
$$

### Mean Time To Recover (MTTR)

$$
\text{MTTR} = \frac{1}{N} \sum_{i=1}^{N} (\text{recover\_ts}_i - \text{detect\_ts}_i)
$$

Similarly modulated:

$$
\text{MTTR}_{\text{eff}} = \text{MTTR}_{\text{base}} \times m_{\text{mttr}}
$$

### Policy Effectiveness Score

$$
E = 1 - \frac{\overline{m}_{\text{mttd}} + \overline{m}_{\text{mttr}}}{2}
$$

Where $\overline{m}$ is the average multiplier across all threat types.
- $E > 0$: better than baseline
- $E = 0$: baseline performance
- $E < 0$: worse than baseline

---

## Experimental Procedure

### Prerequisites

```bash
make install        # Python 3.11+ venv with dependencies
```

### Step 1 — Generate Deterministic Event Stream

```bash
make generate
# Equivalent: python -m src.emulator --seed 42
```

**Expected output**: `data/events.csv` with **4 507 events** (4 509 lines
including header and trailing newline).

Verify determinism:

```bash
sha256sum data/events.csv
# Must match on every run with the same seed
```

### Step 2 — Run Analysis

```bash
make analyze
# Equivalent: python -m src.analyzer --input data/events.csv --horizon-days 1
```

**Expected output files**:

| File                  | Content                              |
|-----------------------|--------------------------------------|
| `out/results.csv`     | 3 rows (one per policy)              |
| `out/incidents.csv`   | 42 rows (incidents × policies)       |
| `out/report.txt`      | Human-readable summary               |
| `out/report.html`     | HTML version with tables             |
| `out/plots/availability.png` | Availability bar chart        |
| `out/plots/downtime.png`    | Downtime bar chart             |
| `out/plots/mttd_mttr.png`   | MTTD vs MTTR grouped chart    |

### Step 3 — Inspect Results

```bash
cat out/report.txt
# or open http://localhost:8501 after: make ui
```

### Step 4 — Reproduce

```bash
make clean && make generate && make analyze
# Results must be identical (same seed → same events → same metrics)
```

---

## Results Template

### Table 1 — Policy Comparison (seed=42, horizon=1 day)

| Policy     | Availability (%) | Downtime (hr) | MTTD (min) | MTTR (min) | Incidents |
|-----------|-----------------|---------------|------------|------------|-----------|
| minimal   | 95.39           | 1.11          | 1.83       | 13.04      | 13        |
| baseline  | 98.37           | 0.39          | 0.69       | 4.07       | 15        |
| standard  | 99.39           | 0.15          | 0.32       | 1.55       | 14        |

### Table 2 — Incident Distribution by Severity

| Policy   | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| minimal  | 3        | 4    | 6      | 0   |
| baseline | 3        | 4    | 8      | 0   |
| standard | 3        | 4    | 7      | 0   |

### Table 3 — Incident Distribution by Threat Type

| Policy   | credential_attack | availability_attack | integrity_attack | outage |
|----------|-------------------|---------------------|------------------|--------|
| minimal  | 1                 | 1                   | 7                | 4      |
| baseline | 1                 | 1                   | 9                | 4      |
| standard | 1                 | 1                   | 8                | 4      |

### Table 4 — Effectiveness Ranking

| Rank | Policy   | Effectiveness | MTTD Factor | MTTR Factor | Active Controls |
|------|----------|---------------|-------------|-------------|-----------------|
| 1    | standard | +0.625        | ×0.40       | ×0.35       | 7/7 (strict)    |
| 2    | baseline | 0.000         | ×1.00       | ×1.00       | 7/7 (soft)      |
| 3    | minimal  | −1.688        | ×2.25       | ×3.12       | 2/7             |

### Figure Descriptions

1. **Availability Chart** (`out/plots/availability.png`):
   Three bars showing 95.39 %, 98.37 %, 99.39 % — visual gap between
   minimal and the protected policies is immediately apparent.

2. **Downtime Chart** (`out/plots/downtime.png`):
   Minimal has 1.11 hr downtime vs standard's 0.15 hr — a 7.6× reduction.

3. **MTTD & MTTR Chart** (`out/plots/mttd_mttr.png`):
   Grouped bars show that standard detects threats 5.7× faster and recovers
   8.4× faster than minimal.

---

## Drawing Conclusions

### Primary Findings

1. **Policy level has a measurable impact on system availability.**
   Standard policy improves availability by **+4.00 percentage points**
   over minimal (99.39 % vs 95.39 %).

2. **Detection speed scales with control maturity.**
   MTTD decreases from 1.83 min (minimal) to 0.32 min (standard) — a
   **5.7× improvement** attributable to real-time monitoring (2 s alert
   latency vs 30 s) and lower detection thresholds.

3. **Recovery time is the strongest differentiator.**
   MTTR drops from 13.04 min to 1.55 min — **8.4× faster** — driven by
   automated blocking, frequent backups (15-min intervals with 30 s
   rollback), and network segmentation limiting blast radius.

4. **More sensitive policies detect more incidents.**
   Baseline (15) and standard (14) detect more incidents than minimal
   (13). This is expected: lower thresholds surface events that
   minimal's relaxed rules miss entirely.

5. **Critical + high counts remain constant across policies.**
   All three policies detect 3 critical + 4 high incidents. The
   difference lies in medium-severity detections and in *how quickly*
   incidents are handled.

### Interpretation Guide

When writing the thesis, use the following structure:

```
For each metric M ∈ {Availability, Downtime, MTTD, MTTR}:
  1. State the observed value per policy (Table 1).
  2. Compute the improvement factor: M_minimal / M_standard.
  3. Link the improvement to specific controls:
     - MTTD improvement → monitoring alert_latency_sec (30→2 s)
     - MTTR improvement → backup interval (none → 15 min) + auto-block
     - Availability improvement → compound of MTTD + MTTR reductions
  4. Reference the multiplier table to show the mechanism.
```

### Threats to Validity

| Threat                     | Mitigation                                    |
|---------------------------|-----------------------------------------------|
| Synthetic data bias        | Fixed seed ensures reproducibility; scenarios model real CWE/MITRE ATT&CK patterns |
| Limited scenario set       | 5 scenarios cover 4 threat types; extensible via config |
| Single-hour simulation     | Horizon normalized to 1 day; results scale linearly |
| No real network latency    | Prototype focuses on policy impact, not network simulation |
| Multiplier calibration     | Values set by domain expertise; sensitivity analysis possible by editing `policies.yaml` |

### Extending the Experiment

- **Sensitivity analysis**: modify one multiplier at a time and re-run:
  ```bash
  # Edit config/policies.yaml → change mttr_multiplier for minimal
  make clean && make generate && make analyze
  ```

- **Different seeds**: test robustness across random seeds:
  ```bash
  for s in 42 123 999 2024 7777; do
    python -m src.emulator --seed $s
    python -m src.analyzer --input data/events.csv --horizon-days 1 \
        --out-dir "out/seed_${s}"
  done
  ```

- **Custom policies**: add a 4th policy to `config/policies.yaml` and
  re-run — the Analyzer will automatically include it.

---

*Generated as part of the SmartEnergy Cyber-Resilience Analyzer thesis prototype.*
