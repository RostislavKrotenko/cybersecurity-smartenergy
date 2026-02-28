# SmartEnergy Cyber-Resilience Analyzer — Architecture

> Магістерський прототип: аналіз кіберстійкості Smart Energy інфраструктури

---

## 1. File Tree

```
CyberSecurity/
│
├── ARCHITECTURE.md              ← цей файл
├── README.md                    ← quickstart, опис проєкту
├── pyproject.toml               ← єдиний Python-пакет (PEP 621)
├── requirements.txt             ← pinned deps
├── Makefile                     ← ярлики: make run, make test, make docker
├── .env.example                 ← шаблон змінних оточення
├── seed.env                     ← SEED=42 (фіксація відтворюваності)
│
├── docker/
│   ├── Dockerfile               ← multi-stage: builder + runtime
│   └── docker-compose.yml       ← сервіси: emulator → normalizer → analyzer → dashboard
│
├── config/
│   ├── policies/
│   │   ├── baseline.yaml        ← політика: базовий набір захисту
│   │   ├── minimal.yaml         ← політика: мінімальний захист
│   │   └── standard.yaml        ← політика: повний набір методів
│   ├── scenarios/
│   │   ├── brute_force.yaml
│   │   ├── ddos_abuse.yaml
│   │   ├── telemetry_spoofing.yaml
│   │   ├── unauthorized_command.yaml
│   │   └── outage_db_corruption.yaml
│   └── emulator.yaml            ← параметри генератора (тривалість, інтенсивність)
│
├── src/
│   ├── __init__.py
│   │
│   ├── contracts/               ← ★ Event Contract — ядро системи
│   │   ├── __init__.py
│   │   ├── event.py             ← dataclass Event (єдиний формат)
│   │   ├── alert.py             ← dataclass Alert
│   │   ├── incident.py          ← dataclass Incident
│   │   └── enums.py             ← Severity, EventType, PolicyLevel, тощо
│   │
│   ├── emulator/                ← SmartEnergy Emulator
│   │   ├── __init__.py
│   │   ├── cli.py               ← CLI entry-point
│   │   ├── engine.py            ← основний генератор подій
│   │   ├── devices.py           ← моделі IoT-пристроїв (meter, inverter, RTU…)
│   │   ├── scenarios/
│   │   │   ├── __init__.py
│   │   │   ├── base.py          ← ABC BaseScenario
│   │   │   ├── brute_force.py
│   │   │   ├── ddos_abuse.py
│   │   │   ├── telemetry_spoof.py
│   │   │   ├── unauthorized_cmd.py
│   │   │   └── outage.py
│   │   └── noise.py             ← генератор фонового «нормального» трафіку
│   │
│   ├── normalizer/              ← Normalizer (опційний шар)
│   │   ├── __init__.py
│   │   ├── cli.py               ← CLI entry-point
│   │   ├── parser.py            ← парсинг сирих логів → Event
│   │   └── filters.py           ← дедуплікація, збагачення, валідація
│   │
│   ├── analyzer/                ← Analyzer (light SIEM)
│   │   ├── __init__.py
│   │   ├── cli.py               ← CLI entry-point
│   │   ├── pipeline.py          ← оркестрація: ingest → detect → respond → report
│   │   ├── detector.py          ← rule engine: Event → Alert
│   │   ├── correlator.py        ← Alert → Incident (групування, severity)
│   │   ├── responder.py         ← Incident → Response (імітація: block IP, isolate…)
│   │   ├── policy_engine.py     ← завантаження та застосування політик
│   │   ├── metrics.py           ← Availability, Downtime, MTTD, MTTR, counts
│   │   └── reporter.py          ← генерація CSV / TXT / HTML / PNG
│   │
│   ├── dashboard/               ← UI Dashboard (Streamlit)
│   │   ├── __init__.py
│   │   ├── app.py               ← streamlit entry-point
│   │   ├── pages/
│   │   │   ├── overview.py      ← KPI-карточки, таймлайн
│   │   │   ├── incidents.py     ← таблиця інцидентів, фільтри
│   │   │   ├── metrics.py       ← графіки метрик
│   │   │   └── compare.py       ← порівняння політик side-by-side
│   │   ├── components/
│   │   │   ├── sidebar.py       ← вибір політики, сценарію, seed
│   │   │   └── charts.py        ← обгортки Plotly/Matplotlib
│   │   └── styles/
│   │       └── theme.css        ← кастомний CSS
│   │
│   └── shared/                  ← спільні утиліти
│       ├── __init__.py
│       ├── config_loader.py     ← YAML → dict, merge defaults
│       ├── logger.py            ← structlog / logging setup
│       ├── time_utils.py        ← timestamps, duration helpers
│       └── seed.py              ← ініціалізація random + numpy seed
│
├── data/                        ← вхідні / проміжні дані
│   ├── raw/                     ← сирі логи (якщо normalizer використано)
│   │   └── .gitkeep
│   └── events/                  ← нормалізовані події (JSONL)
│       └── .gitkeep
│
├── out/                         ← результати (генеруються автоматично)
│   ├── results.csv
│   ├── incidents.csv
│   ├── report.txt
│   ├── report.html              ← (опціонально)
│   └── plots/
│       ├── availability_timeline.png
│       ├── incidents_by_severity.png
│       ├── mttd_mttr_comparison.png
│       └── policy_comparison.png
│
└── tests/
    ├── __init__.py
    ├── conftest.py              ← fixtures: sample events, policies
    ├── test_contracts.py        ← валідація Event/Alert/Incident
    ├── test_emulator.py         ← сценарії генерують очікувані дані
    ├── test_normalizer.py       ← raw → Event mapping
    ├── test_detector.py         ← Event → Alert rules
    ├── test_correlator.py       ← Alert → Incident grouping
    ├── test_metrics.py          ← розрахунки MTTD/MTTR/Availability
    ├── test_reporter.py         ← вивід файлів
    └── test_e2e.py              ← повний pipeline seed=42 → golden output
```

---

## 2. Відповідальність модулів

| Модуль | Роль | Вхід | Вихід |
|--------|------|------|-------|
| **contracts** | Єдине джерело правди — data classes + enums. Не має залежностей, крім stdlib. | — | `Event`, `Alert`, `Incident`, `Severity`, … |
| **emulator** | Генерує потік подій, що імітують роботу Smart Energy мережі (нормальний трафік + атаки за сценаріями). Seed-детермінований. | `config/emulator.yaml`, `config/scenarios/*.yaml`, `seed` | `data/events/*.jsonl` |
| **normalizer** | **Опціональний.** Перетворює «сирі» різнорідні логи (CSV, syslog, JSON) в уніфіковані `Event` об'єкти за контрактом. Потрібен, якщо дані надходять із зовнішнього джерела. | `data/raw/*` | `data/events/*.jsonl` |
| **analyzer** | Ядро — SIEM-like pipeline. Приймає `Event`-потік (байдуже, звідки), застосовує detection rules, group alerts → incidents, обчислює метрики стійкості, генерує звіти. **Не залежить від emulator.** | `data/events/*.jsonl`, `config/policies/*.yaml` | `out/*` |
| **dashboard** | Streamlit UI: візуалізація результатів з `out/`, live-запуск pipeline через sidebar. | `out/*` (файли) | HTTP UI `:8501` |
| **shared** | Конфіг-лоадер, логер, seed-менеджер, time utils — використовується всіма модулями. | — | — |
| **docker** | Одним `docker compose up` піднімає весь ланцюг. | `.env`, `seed.env` | Контейнери |

---

## 3. Формати файлів

### 3.1 `data/events/*.jsonl` — Нормалізовані події

Кожен рядок — JSON-об'єкт `Event`:

```jsonc
{
  "event_id":    "evt-00042",            // унікальний ID
  "timestamp":   "2026-02-26T10:05:31Z", // ISO 8601 UTC
  "source":      "meter-17",             // device / service
  "event_type":  "AUTH_FAILURE",         // enum: AUTH_FAILURE | RATE_EXCEEDED | CMD_EXEC | TELEMETRY | SYSTEM | NETWORK
  "severity":    "medium",              // low | medium | high | critical
  "description": "Failed login attempt from 10.0.8.5",
  "metadata": {                          // вільна структура, scenario-specific
    "src_ip": "10.0.8.5",
    "username": "admin",
    "attempt": 14
  },
  "scenario_tag": "brute_force"          // (emulator-only) мітка для ground truth
}
```

### 3.2 `data/raw/*` — Сирі логи (worst-case input для normalizer)

Формати, які normalizer вміє парсити:
- `.csv` — стовпці `timestamp,level,message,source`
- `.log` — syslog-like рядки
- `.json` — довільна JSON-структура

### 3.3 `out/results.csv` — Метрики стійкості

```csv
policy,scenario,availability_pct,total_downtime_sec,mean_mttd_sec,mean_mttr_sec,incidents_total,incidents_critical,incidents_high,incidents_medium,incidents_low
baseline,brute_force,99.12,316,12.4,45.2,7,1,2,3,1
minimal,brute_force,97.55,882,28.7,102.3,12,3,4,3,2
standard,brute_force,99.87,47,4.1,12.8,3,0,1,1,1
```

### 3.4 `out/incidents.csv` — Реєстр інцидентів

```csv
incident_id,policy,scenario,severity,event_count,first_event_ts,detected_ts,resolved_ts,mttd_sec,mttr_sec,description,response_action
INC-001,baseline,brute_force,high,23,2026-02-26T10:05:00Z,2026-02-26T10:05:12Z,2026-02-26T10:05:57Z,12.0,45.0,"Brute-force on meter-17","block_ip"
```

### 3.5 `out/report.txt` — Текстовий звіт

```
=== SmartEnergy Cyber-Resilience Report ===
Generated: 2026-02-26T12:00:00Z | Seed: 42

--- Policy: baseline ---
Scenario: brute_force
  Availability:    99.12%
  Downtime:        5m 16s
  Mean MTTD:       12.4s
  Mean MTTR:       45.2s
  Incidents:       7 (crit=1 high=2 med=3 low=1)
...
--- Comparison ---
Best Availability: standard (99.87%)
Worst MTTR:        minimal (102.3s)
```

### 3.6 `out/report.html` — HTML-звіт (опціонально)

Self-contained HTML з вбудованими графіками (base64 PNG або inline SVG).

### 3.7 `out/plots/*.png`

| Файл | Що показує |
|------|------------|
| `availability_timeline.png` | Availability % по часу для кожної політики |
| `incidents_by_severity.png` | Stacked bar: кількість інцидентів за severity + policy |
| `mttd_mttr_comparison.png` | Grouped bar: MTTD / MTTR по політиках |
| `policy_comparison.png` | Radar / heatmap: усі метрики по політиках |

---

## 4. Політики безпеки

Кожна політика — YAML-файл із переліком увімкнених методів та їх параметрів:

```yaml
# config/policies/standard.yaml
name: standard
description: "Full security controls for production Smart Energy"

controls:
  mfa:
    enabled: true
    max_attempts: 3
    lockout_sec: 300

  rbac:
    enabled: true
    roles: [operator, admin, readonly]

  rate_limiting:
    enabled: true
    requests_per_sec: 100
    burst: 200

  monitoring:
    enabled: true
    alert_threshold_sec: 5     # час до спрацьовування алерту

  logging:
    enabled: true
    audit_trail: true
    retention_days: 90

  backup:
    enabled: true
    interval_sec: 3600
    rollback_available: true

  segmentation:
    enabled: true
    zones: [scada, corporate, dmz]
```

**baseline** — все enabled, але з м'якими порогами.
**minimal** — лише logging + monitoring (rate_limiting/mfa/segmentation/backup disabled).
**standard** — все enabled, жорсткі пороги.

Analyzer → `policy_engine.py` читає активну політику і модифікує параметри detection / response:
- Якщо `mfa.enabled=false` → brute-force детектується пізніше (вищий `alert_threshold`).
- Якщо `rate_limiting.enabled=false` → DDoS не блокується автоматично.
- Якщо `backup.rollback_available=false` → MTTR для db_corruption значно зростає.

---

## 5. Сценарії інцидентів

| # | Сценарій | Event-типи | Що імітує |
|---|----------|-----------|-----------|
| 1 | **Brute Force** | `AUTH_FAILURE` × N → `AUTH_SUCCESS` | Підбір паролів до IoT-gateway / SCADA HMI |
| 2 | **DDoS / API Abuse** | `RATE_EXCEEDED`, `NETWORK` | Флуд на REST API контролера або MQTT broker |
| 3 | **Telemetry Spoofing** | `TELEMETRY` з anomalous values | Підміна показників лічильника (MitM) |
| 4 | **Unauthorized Command** | `CMD_EXEC` з невалідним `role` | Виконання команди управління без авторизації |
| 5 | **Outage / DB Corruption** | `SYSTEM` (service_down, db_error) | Відмова сервісу або пошкодження БД конфігурацій |

Кожен сценарій у `config/scenarios/*.yaml` описує:
```yaml
name: brute_force
target_devices: [gateway-01, hmi-02]
duration_sec: 120
intensity: high          # low | medium | high
event_pattern:
  - type: AUTH_FAILURE
    count: [15, 50]      # range (seed-залежний)
    interval_ms: [200, 1000]
  - type: AUTH_SUCCESS
    count: [0, 1]
    delay_after_failures_sec: [1, 5]
ground_truth:
  expected_severity: high
  expected_incident: true
```

---

## 6. CLI інтерфейси

### 6.1 Emulator

```bash
python -m src.emulator.cli \
  --config config/emulator.yaml \
  --scenarios brute_force,ddos_abuse,telemetry_spoofing,unauthorized_command,outage_db_corruption \
  --policy baseline \
  --seed 42 \
  --duration 3600 \
  --output data/events/baseline_events.jsonl \
  --log-level INFO
```

| Аргумент | Default | Опис |
|----------|---------|------|
| `--config` | `config/emulator.yaml` | Файл конфігурації генератора |
| `--scenarios` | `all` | Через кому: які сценарії активувати |
| `--policy` | `baseline` | Яку політику підставити (впливає на поведінку пристроїв) |
| `--seed` | `42` | Random seed |
| `--duration` | `3600` | Тривалість симуляції (секунди модельного часу) |
| `--output` | `data/events/events.jsonl` | Шлях вихідного файлу |
| `--log-level` | `INFO` | DEBUG / INFO / WARNING |

### 6.2 Normalizer

```bash
python -m src.normalizer.cli \
  --input data/raw/ \
  --output data/events/normalized.jsonl \
  --format auto \
  --log-level INFO
```

| Аргумент | Default | Опис |
|----------|---------|------|
| `--input` | `data/raw/` | Директорія або файл із сирими логами |
| `--output` | `data/events/normalized.jsonl` | Вихідний JSONL |
| `--format` | `auto` | `auto` / `csv` / `syslog` / `json` |
| `--log-level` | `INFO` | Рівень логування |

### 6.3 Analyzer

```bash
python -m src.analyzer.cli \
  --input data/events/baseline_events.jsonl \
  --policies baseline,minimal,standard \
  --seed 42 \
  --output-dir out/ \
  --formats csv,txt,html,png \
  --log-level INFO
```

| Аргумент | Default | Опис |
|----------|---------|------|
| `--input` | `data/events/events.jsonl` | Вхідний JSONL (Event Contract) |
| `--policies` | `all` | Через кому: які політики порівняти |
| `--seed` | `42` | Seed (для stochastic response simulation) |
| `--output-dir` | `out/` | Директорія результатів |
| `--formats` | `csv,txt,png` | Які звіти генерувати |
| `--log-level` | `INFO` | Рівень логування |

### 6.4 Повний pipeline (single command)

```bash
# Локально:
make run SEED=42 POLICY=all SCENARIOS=all

# Docker:
docker compose up --build
```

---

## 7. Схема даних (Data Flow)

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────────────────────────┐
│  SmartEnergy │     │ Normalizer  │     │           Analyzer                  │
│  Emulator    │     │ (optional)  │     │                                     │
│              │     │             │     │  ┌──────────┐    ┌──────────────┐   │
│  devices +   │────▶│ raw logs ──▶│────▶│  │ Detector │───▶│  Correlator  │   │
│  scenarios   │     │ Event       │     │  │ (rules)  │    │  (grouping)  │   │
│              │     │ Contract    │     │  └──────────┘    └──────┬───────┘   │
└──────┬───────┘     └─────────────┘     │                        │           │
       │                                 │                        ▼           │
       │  data/events/*.jsonl            │  ┌──────────────────────────────┐  │
       └────────────────────────────────▶│  │       Policy Engine          │  │
                                         │  │  (applies controls config)   │  │
                Event Contract           │  └──────────┬───────────────────┘  │
                                         │             │                      │
              ┌──────────────────────────│─────────────┘                      │
              │                          │                                    │
              ▼                          │  ┌───────────┐   ┌────────────┐   │
      ┌──────────────┐                   │  │ Responder │   │  Metrics   │   │
      │  Incident    │                   │  │ (actions) │   │  Engine    │   │
      │  Registry    │──────────────────▶│  └───────────┘   └─────┬──────┘   │
      └──────────────┘                   │                        │          │
                                         │                        ▼          │
                                         │              ┌─────────────────┐  │
                                         │              │    Reporter     │  │
                                         │              │ CSV/TXT/HTML/PNG│  │
                                         │              └────────┬────────┘  │
                                         └───────────────────────┼──────────┘
                                                                 │
                                                                 ▼
                                                          out/ directory
                                                                 │
                                                                 ▼
                                                    ┌────────────────────┐
                                                    │  Streamlit         │
                                                    │  Dashboard         │
                                                    │  (reads out/*)     │
                                                    └────────────────────┘
```

### Data Model (ланцюг трансформацій)

```
Event                    Alert                    Incident                Metrics
─────                    ─────                    ────────                ───────
event_id        ───▶     alert_id                 incident_id             policy
timestamp               event_ids[]    ───▶       alert_ids[]             scenario
source                  timestamp                 severity                availability_pct
event_type              rule_name                 event_count             total_downtime_sec
severity                severity                  first_event_ts          mean_mttd_sec
description             description               detected_ts             mean_mttr_sec
metadata{}              confidence                resolved_ts             incidents_total
scenario_tag            policy                    mttd_sec                incidents_by_severity{}
                                                  mttr_sec
                                                  description
                                                  response_action
```

**Трансформації:**

```
Event ──[Detector: rule matching]──▶ Alert
       1 Event → 0..1 Alert (не кожна подія — алерт)

Alert ──[Correlator: time window + source grouping]──▶ Incident
       N Alerts → 1 Incident (кластеризація за часом і джерелом)

Incident ──[Metrics Engine: timing calculations]──▶ Metrics
       M Incidents → 1 Metrics row (агреговані метрики per policy+scenario)
```

**Формули метрик:**

| Метрика | Формула |
|---------|---------|
| **MTTD** (Mean Time To Detect) | `avg(detected_ts - first_event_ts)` для всіх інцидентів |
| **MTTR** (Mean Time To Recover) | `avg(resolved_ts - detected_ts)` для всіх інцидентів |
| **Availability** | `1 - (total_downtime / simulation_duration) × 100%` |
| **Downtime** | `sum(resolved_ts - impact_start_ts)` — час, коли сервіс degraded |

---

## 8. Detection Rules (Detector)

| Rule | Trigger | Severity |
|------|---------|----------|
| `BRUTE_FORCE` | ≥ N `AUTH_FAILURE` від одного `src_ip` за T сек | high |
| `DDOS_FLOOD` | ≥ M `RATE_EXCEEDED` за T сек | critical |
| `TELEMETRY_ANOMALY` | value за межами `[μ - 3σ, μ + 3σ]` або різкий стрибок | medium |
| `UNAUTH_CMD` | `CMD_EXEC` де `role ∉ allowed_roles` | critical |
| `SERVICE_OUTAGE` | `SYSTEM` з `status=down` | critical |
| `DB_CORRUPTION` | `SYSTEM` з `db_error=integrity` | high |

Пороги (N, M, T) — **параметризовані через config/policies** → різні політики дають різну чутливість.

---

## 9. Docker Compose Architecture

```yaml
services:
  emulator:
    build: .
    command: python -m src.emulator.cli --seed ${SEED} --scenarios all
    volumes: [./data:/app/data, ./config:/app/config]

  normalizer:                    # optional, profiles: [normalizer]
    build: .
    command: python -m src.normalizer.cli
    volumes: [./data:/app/data]
    depends_on: [emulator]

  analyzer:
    build: .
    command: python -m src.analyzer.cli --policies all
    volumes: [./data:/app/data, ./out:/app/out, ./config:/app/config]
    depends_on: [emulator]

  dashboard:
    build: .
    command: streamlit run src/dashboard/app.py --server.port 8501
    ports: ["8501:8501"]
    volumes: [./out:/app/out]
    depends_on: [analyzer]
```

**Один запуск:** `docker compose up --build` → emulator генерує → analyzer аналізує → dashboard показує.

---

## 10. Acceptance Criteria

### Функціональні

| # | Критерій | Перевірка |
|---|----------|-----------|
| F1 | Emulator генерує JSONL з ≥ 5 типами подій | `jq '.event_type' data/events/*.jsonl \| sort -u \| wc -l` ≥ 5 |
| F2 | Всі 5 сценаріїв виконуються | `jq '.scenario_tag' … \| sort -u` = 5 тегів |
| F3 | Analyzer працює з будь-яким JSONL, що відповідає Event Contract | Підставити зовнішній JSONL → pipeline не падає |
| F4 | 3 політики порівнюються в одному запуску | `out/results.csv` має рядки для baseline, minimal, standard |
| F5 | Метрики MTTD, MTTR, Availability, Downtime розраховані | Відповідні колонки в `out/results.csv` заповнені |
| F6 | Файли `out/results.csv`, `out/incidents.csv`, `out/report.txt` існують | `ls out/` перевірка |
| F7 | Графіки генеруються | `ls out/plots/*.png` ≥ 3 файли |
| F8 | Dashboard запускається і показує дані | `curl -s http://localhost:8501` → 200 OK |
| F9 | Seed = 42 дає ідентичні результати при повторному запуску | `md5sum out/results.csv` однаковий |
| F10 | Docker Compose піднімає все однією командою | `docker compose up --build` → exit code 0 для emulator + analyzer |

### Нефункціональні

| # | Критерій | Перевірка |
|---|----------|-----------|
| N1 | Analyzer не імпортує нічого з emulator | `grep -r "from src.emulator" src/analyzer/` → порожньо |
| N2 | contracts/ не має зовнішніх залежностей | Тільки stdlib imports |
| N3 | Тести проходять | `pytest tests/ -v` → 0 failures |
| N4 | Час повного pipeline < 2 хвилин (seed=42, default config) | `time make run` < 120s |
| N5 | Логування structlog з JSON output | Логи парсяться як JSON |

---

## 11. Залежності (requirements.txt)

```
# Core
pyyaml>=6.0
pydantic>=2.0          # validation для contracts (опційно dataclasses)
structlog>=23.0

# Analyzer
pandas>=2.0
numpy>=1.24

# Reporter / Plots
matplotlib>=3.7
jinja2>=3.1            # HTML report template

# Dashboard
streamlit>=1.30
plotly>=5.18

# Testing
pytest>=7.4
pytest-cov>=4.1

# CLI
click>=8.1             # або typer
```

---

## 12. Makefile Targets

```makefile
run:         ## Повний pipeline: emulate → analyze → report
test:        ## pytest з coverage
lint:        ## ruff check + mypy
format:      ## ruff format
docker:      ## docker compose up --build
clean:       ## rm -rf out/ data/events/*.jsonl
dashboard:   ## streamlit run src/dashboard/app.py
help:        ## Показати цей список
```

---

## 13. Резюме архітектурних рішень

| Рішення | Обґрунтування |
|---------|---------------|
| **JSONL як transport** | Простий, streamable, grep-friendly, ідеальний для прототипу |
| **Event Contract як окремий модуль** | Гарантує незалежність Analyzer від джерела даних |
| **YAML-конфіги політик** | Легко розширювати, readable, diffable |
| **Click CLI** | Стандарт для Python CLI, auto-help, type validation |
| **Streamlit** | Мінімум коду для interactive dashboard, zero frontend |
| **Seed-based reproducibility** | `random.seed()` + `numpy.random.seed()` globally → deterministic |
| **Single Python package** | Спрощує imports і Docker build |
| **Multi-stage Docker** | Менший image size, кеш pip install |

---

*Документ створено: 2026-02-26 | Автор: Architecture phase*
