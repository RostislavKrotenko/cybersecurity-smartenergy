# Event Contract — Специфікація формату даних

> Єдине джерело правди для всіх компонентів системи.
> Analyzer **ніколи** не імпортує модулі Emulator — взаємодія лише через цей контракт.

---

## 1. Поля Event Contract

| # | Поле | Тип | Обов'язкове | Опис | Приклад |
|---|------|-----|:-----------:|------|---------|
| 1 | `timestamp` | string (ISO 8601 UTC) | **✓** | Час події | `2026-02-26T10:05:31Z` |
| 2 | `source` | string | **✓** | ID пристрою / сервісу, що згенерував подію | `meter-17`, `api-gw-01` |
| 3 | `component` | string (enum) | **✓** | Функціональний тип компонента | `edge`, `api`, `db`, `ui`, `collector`, `inverter`, `network` |
| 4 | `event` | string | **✓** | Тип події | `auth_failure`, `telemetry_read`, `cmd_exec` |
| 5 | `actor` | string | опціональне | Хто ініціював (user/role/system) | `operator`, `unknown`, `system` |
| 6 | `ip` | string (IPv4) | опціональне | IP-адреса джерела запиту | `192.168.8.55` |
| 7 | `key` | string | **✓** | Назва параметра / метрики | `voltage`, `username`, `status` |
| 8 | `value` | string | **✓** | Значення параметра (завжди string, парсити за потреби) | `230.1`, `admin`, `down` |
| 9 | `unit` | string | опціональне | Одиниця виміру (для телеметрії) | `V`, `kW`, `Hz`, `°C`, `req/s` |
| 10 | `severity` | string (enum) | **✓** | Рівень критичності | `low`, `medium`, `high`, `critical` |
| 11 | `tags` | string | опціональне | Мітки через `;` | `auth;failure;escalated` |
| 12 | `correlation_id` | string | опціональне | ID для групування пов'язаних подій | `COR-BF-001`, `""` |

### Значення enum-полів

**component:**
`edge` · `api` · `db` · `ui` · `collector` · `inverter` · `network`

**event (типи подій):**

| event | Опис |
|-------|------|
| `telemetry_read` | Зчитування показань (voltage, power, frequency…) |
| `auth_failure` | Невдала аутентифікація |
| `auth_success` | Успішна аутентифікація |
| `http_request` | HTTP-запит до API |
| `rate_exceeded` | Перевищення rate limit |
| `cmd_exec` | Виконання команди управління |
| `service_status` | Зміна статусу сервісу (healthy/degraded/down) |
| `db_error` | Помилка бази даних |
| `port_status` | Статус мережевого порта |
| `raw_log` | Нерозпізнаний запис (fallback normalizer) |

**severity:**
`low` (info/debug) → `medium` (warning) → `high` (error) → `critical` (emergency)

---

## 2. Формат CSV

Файл: `data/events/*.csv`

- Перший рядок — header (назви полів, розділені `,`)
- Кожен наступний рядок — один Event
- Розділювач: `,` (comma)
- Рядкові значення з комами або лапками — огорнуті у `"…"`
- Порожні опціональні поля — просто пустий рядок між комами
- Encoding: UTF-8

```
timestamp,source,component,event,actor,ip,key,value,unit,severity,tags,correlation_id
```

Приклад — див. [data/events/example_events.csv](../data/events/example_events.csv) (25 рядків).

---

## 3. Формат JSONL

Файл: `data/events/*.jsonl`

- Кожен рядок — один JSON-об'єкт (Event)
- Без зовнішнього масиву (`[…]`)
- Опціональні поля з порожнім значенням → `""` (присутні, але порожні)
- Encoding: UTF-8

Приклад — див. [data/events/example_events.jsonl](../data/events/example_events.jsonl) (10 рядків).

---

## 4. Threat Types

Маппінг між типами загроз, правилами детекції та сценаріями:

| threat_type | Опис | Сценарії | Rules | Цільові events |
|-------------|------|----------|-------|----------------|
| `credential_attack` | Атака на аутентифікацію / облікові дані | `brute_force` | `RULE-BF-001`, `RULE-BF-002` | `auth_failure`, `auth_success` |
| `availability_attack` | Атака на доступність (DDoS, resource exhaustion) | `ddos_abuse` | `RULE-DDOS-001`, `RULE-DDOS-002` | `rate_exceeded`, `service_status` |
| `integrity_attack` | Підміна даних, несанкціоновані дії | `telemetry_spoofing`, `unauthorized_command` | `RULE-SPOOF-001/002`, `RULE-UCMD-001/002` | `telemetry_read`, `cmd_exec` |
| `outage` | Відмова сервісу, пошкодження даних | `outage_db_corruption` | `RULE-OUT-001/002/003` | `service_status`, `db_error` |

### Як threat_type використовується у системі

```
scenario.yaml::threat_type  ──►  rules.yaml::threat_type  ──►  policies.yaml::modifiers[threat_type]
      (emulator)                      (detector)                     (policy engine)
```

1. **Emulator** — кожен сценарій має `threat_type` для ground truth маркування
2. **Detector** — кожне правило має `threat_type` для класифікації алертів
3. **Policy Engine** — бере `threat_type` алерту і застосовує відповідні multipliers з активної політики

---

## 5. Події, що генерує Emulator для кожного сценарію

### 5.1 Brute Force (`brute_force`)

| Фаза | event | source | key | value | severity | Кількість |
|-------|-------|--------|-----|-------|----------|-----------|
| Фон | `auth_success` | gateway-01 | method | password | low | 2-5 |
| Атака | `auth_failure` | gateway-01 | username | admin/root/operator/test/guest | medium→high | 15-50 |
| Компроміс (30%) | `auth_success` | gateway-01 | username | admin | critical | 0-1 |

Особливість: severity ескалюється після 10-ої невдалої спроби. Всі події атаки мають спільний `correlation_id = COR-BF-XXX`.

### 5.2 DDoS / API Abuse (`ddos_abuse`)

| Фаза | event | source | key | value | severity | Кількість |
|-------|-------|--------|-----|-------|----------|-----------|
| Флуд | `rate_exceeded` | api-gw-01 | requests_per_sec | 800-5000 | high→critical | 100-500 |
| Деградація | `service_status` | api-gw-01 | status | degraded/down | critical | 1-3 |

Особливість: IP-адреси із пулу `203.0.113.0/24`. Severity = critical після 50-ої події.

### 5.3 Telemetry Spoofing (`telemetry_spoofing`)

| Фаза | event | source | key | value | severity | Кількість |
|-------|-------|--------|-----|-------|----------|-----------|
| Спуфінг | `telemetry_read` | meter-17 | voltage | 500-1200 (аномальне) | low | 10-30 |
| Спуфінг | `telemetry_read` | inverter-03 | power_kw | –800…–200 (від'ємне) | low | 5-15 |
| Спуфінг | `telemetry_read` | meter-17 | frequency_hz | 30-45 (аномальне) | low | 5-10 |

Особливість: **severity = low** (маскується під нормальну телеметрію!). Виявлення — тільки через `rules.yaml` bounds/delta перевірки в Analyzer.

### 5.4 Unauthorized Command (`unauthorized_command`)

| Фаза | event | source | key | value | severity | Кількість |
|-------|-------|--------|-----|-------|----------|-----------|
| Команди | `cmd_exec` | scada-hmi-01 | command | breaker_open / set_voltage / emergency_shutdown / firmware_update | critical | 2-8 |

Особливість: `actor ∈ {readonly, unknown, guest}` — жоден не має прав на `cmd_exec`. Severity одразу critical.

### 5.5 Outage / DB Corruption (`outage_db_corruption`)

| Фаза | event | source | key | value | severity | Кількість |
|-------|-------|--------|-----|-------|----------|-----------|
| DB errors | `db_error` | db-primary | error_type | integrity_violation / checksum_mismatch / wal_corruption | high→critical | 3-8 |
| Каскад | `service_status` | db-primary, api-gw-01, collector-01 | status | degraded/down | critical | 3-6 |
| Відновлення | `service_status` | db-primary | status | recovering/healthy | medium | 2 |

Особливість: каскадна відмова — DB → API → Collector. MTTR залежить від `backup.rollback_available` у політиці.

---

## 6. Ланцюг трансформацій даних

```
                   Event Contract (CSV / JSONL)
                            │
                            ▼
┌──────────────────────────────────────────────────┐
│  DETECTOR (rules.yaml)                           │
│  Event ──[rule match]──► Alert                   │
│                                                  │
│  Alert = {                                       │
│    alert_id:    "ALR-00001"                      │
│    rule_id:     "RULE-BF-001"                    │
│    threat_type: "credential_attack"              │
│    event_ids:   ["evt-015", "evt-016", …]        │
│    timestamp:   "2026-02-26T10:00:19Z"           │
│    source:      "gateway-01"                     │
│    severity:    "high"                           │
│    confidence:  0.85                             │
│    description: "Brute-force detected: 15 …"    │
│    policy:      "baseline"                       │
│  }                                               │
└──────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────┐
│  CORRELATOR                                      │
│  N Alerts ──[time window + source]──► Incident   │
│                                                  │
│  Incident = {                                    │
│    incident_id:     "INC-001"                    │
│    alert_ids:       ["ALR-001", "ALR-002"]       │
│    threat_type:     "credential_attack"          │
│    severity:        "high"                       │
│    event_count:     23                           │
│    first_event_ts:  "2026-02-26T10:00:15Z"      │
│    detected_ts:     "2026-02-26T10:00:19Z"      │
│    resolved_ts:     "2026-02-26T10:01:04Z"       │
│    mttd_sec:        4.0                          │
│    mttr_sec:        45.0                         │
│    description:     "Brute-force on gateway-01"  │
│    response_action: "block_ip"                   │
│    policy:          "baseline"                   │
│    scenario_tag:    "brute_force"                │
│  }                                               │
└──────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────┐
│  METRICS ENGINE                                  │
│  M Incidents ──[aggregate per policy+scenario]──►│
│                                                  │
│  Metrics = {                                     │
│    policy:              "baseline"               │
│    scenario:            "brute_force"            │
│    availability_pct:    99.12                    │
│    total_downtime_sec:  316                      │
│    mean_mttd_sec:       12.4                     │
│    mean_mttr_sec:       45.2                     │
│    incidents_total:     7                        │
│    incidents_critical:  1                        │
│    incidents_high:      2                        │
│    incidents_medium:    3                        │
│    incidents_low:       1                        │
│  }                                               │
└──────────────────────────────────────────────────┘
                            │
                            ▼
                    out/results.csv
                    out/incidents.csv
                    out/report.txt
                    out/plots/*.png
```

---

## 7. Конфіг-файли — зведена таблиця

| Файл | Хто читає | Що визначає |
|------|-----------|-------------|
| [config/components.yaml](../config/components.yaml) | Emulator, Dashboard | Інфраструктура: пристрої, зони, залежності |
| [config/scenarios.yaml](../config/scenarios.yaml) | Emulator | Фоновий трафік + 5 атакових сценаріїв |
| [config/rules.yaml](../config/rules.yaml) | Analyzer (Detector) | Правила детекції: event → alert |
| [config/policies.yaml](../config/policies.yaml) | Analyzer (Policy Engine) | 3 політики з multipliers для MTTD/MTTR/probability |
| [config/mapping.yaml](../config/mapping.yaml) | Normalizer | Парсинг raw logs → Event Contract |

---

*Документ створено: 2026-02-26 | Data Engineering phase*
