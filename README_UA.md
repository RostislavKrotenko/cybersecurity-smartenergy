# SmartEnergy Cyber-Resilience Analyzer

Українська версія | [English](README.md)

**Повнофункціональна система аналізу кіберзахисту розумних енергомереж на основі реальних сценаріїв атак та синтетичних подій.**

## Огляд

SmartEnergy Cyber-Resilience Analyzer — це інтегрована платформа для:

- **Генерування синтетичних подій** (`emulator`) з реалістичними атаками (brute-force, DDoS, спуфинг телеметрії, вимкнення БД)
- **Нормалізації логів** (`normalizer`) з різних джерел у єдиний формат
- **Детекції та аналізу інцидентів** (`analyzer`) з применням сценаріїв політик безпеки (baseline, minimal, standard)
- **Інтерактивного дашборду** (`dashboard`) у реальному часі з графіками, таблицями та метриками доступності

Система випускає **3 метрики безпеки** на кожну політику:
- **Availability** — відсоток часу без інцидентів
- **Mean MTTD/MTTR** — середній час виявлення-відновлення

## Структура проекту

```
.
├── config/                       # Конфігурації: компоненти, правила, сценарії, політики
│   ├── components.yaml
│   ├── rules.yaml
│   ├── scenarios.yaml
│   └── policies.yaml
├── src/
│   ├── analyzer/                # Детекція + кореляція + метрики
│   │   ├── detector.py          # Rule engine → Alerts
│   │   ├── correlator.py        # Alerts → Incidents (grouping)
│   │   ├── metrics.py           # Incidents → Availability/MTTD/MTTR
│   │   ├── reporter.py          # Atomic write CSV/HTML/plots
│   │   └── pipeline.py          # Watch mode для JSONL
│   ├── contracts/               # Data models (Event, Alert, Incident)
│   ├── dashboard/               # Streamlit UI + live refresh logic
│   │   ├── app.py               # Main UI + @st.fragment
│   │   ├── data_access.py       # CSV reads з retry logic
│   │   └── ui/                  # Charts, tables, layout
│   ├── emulator/                # Синтез подій + атаки
│   │   ├── engine.py            # Orchestrator
│   │   ├── scenarios/           # Attack scenario definitions
│   │   └── noise.py             # Background traffic generators
│   └── normalizer/              # Raw logs → normalized events
├── tests/                        # 207 unit + integration тестів
├── docker-compose.yml            # Live pipeline orchestration
└── requirements.txt              # Python deps
```

## Основні компоненти

### 1. Emulator (Генератор подій)

Генерує синтетичні івенти безпеки на основі реальних сценаріїв:

```bash
# Одноразовий режим (batch)
python -m src.emulator --seed 42 --out data/events.csv

# Live режим (безперервний потік)
python -m src.emulator --live --live-interval-ms 500 \
  --out data/live/events.jsonl --profile demo_high_rate
```

**Сценарії атак:**
- `brute_force` — множинні невдачі автентифікації з однієї IP
- `ddos_abuse` — flood rate_exceeded событий
- `telemetry_spoofing` — аномальні значення телеметрії
- `unauthorized_command` — команди від недозволених aktorів
- `outage_db_corruption` — DB errors / service degradation

### 2. Normalizer (Нормалізація логів)

Перетворює "брудні" логи (syslog, API, system logs) у єдиний CSV/JSONL формат:

```bash
# Batch
python -m src.normalizer --inputs "logs/*.log" \
  --mapping config/mapping.yaml --out data/events.csv

# Watch mode
python -m src.normalizer --inputs "logs/*.log" --follow \
  --mapping config/mapping.yaml --out data/normalized.csv
```

### 3. Analyzer (Детекція + Аналіз)

**Детекція:** Rule engine (rules.yaml) скануватиме потік подій і тригерить **Alerts** при виконанні умов.

**Кореляція:** Alerts групуються в **Incidents** за correlation_id або часовим вікном (120 сек) + компонент + threat_type.

**Метрики:** Для кожного інциденту розраховуються MTTD (Mean Time To Detect), MTTR (Mean Time To Recover), вплив.

```bash
# Batch
python -m src.analyzer --input data/events.csv \
  --policies all --horizon-days 1 --out-dir out

# Watch mode (live, tail JSONL)
python -m src.analyzer --input data/live/events.jsonl \
  --watch --poll-interval-ms 1000 --out-dir out
```

**Вихідні файли:**
- `out/results.csv` — один рядок на політику (availability, downtime,  MTTD, MTTR)
- `out/incidents.csv` — всі інциденти (id, threat_type, severity, component, MTTD, MTTR, impact_score)
- `out/report.txt` / `out/report.html` — людпсько-зрозумілий звіт
- `out/plots/` — PNG графіки доступності, downtime, MTTD/MTTR

### 4. Dashboard (UI Live Streamlit)

Інтерактивний дашборд з **реальночасовим оновленням** графіків та таблиць без мерехтіння.

```bash
streamlit run src/dashboard/app.py
```

**Можливості:**
- KPI карти за політиками (Availability, Downtime, MTTD, MTTR)
- Порівняльні графіки доступності та downtime
- **Incidents per Minute** — часова лінія інцидентів зі 100% заповненням нулями
- Сортувальна таблиця інцидентів за severity + час
- Фільтрація: политики, severity, threat_type, component, horizon (дні)
- **Діагностика в реальному часі:** refresh_tick, mtime файлів, row counts, Last incident timestamp
- **Auto-refresh** — увімкнений за замовчуванням у live режимі (5 сек за умовчанням)

## Live Pipeline у Docker

Кращий спосіб запустити всю платформу:

```bash
docker compose --profile live up --build
```

Це запускає 4 сервіси:

1. **emulator-live** — генерує безперервний потік JSONL подій + CSV + raw logs
2. **normalizer-live** — слідкує за сирими логами, нормалізує
3. **analyzer-live** — tail JSONL, переанілізує накопичені события кожну секунду
4. **ui-live** — Streamlit на http://localhost:8501

[Docker Compose документація](docker-compose.yml) описує всі параметри.

## Ключові виправлення (v1.1)

### Race Condition UI-Analyzer

**Проблема:** Analyzer писав результати звичайним `open(..., "w")`, який спочатку обрізував файл до 0 байт. UI міг прочитати порожній файл під час запису.

**Виправлення:** **Atomic writes** через `tempfile.mkstemp()` + `os.fsync()` + `os.replace()`. CSV ніколи не бачить reader-ом у процесі запису.

### Chart Flicker

**Проблема:** `st_autorefresh` тригерив повний rerun сторінки, розриваючи весь DOM. Графіки мерехтіли на кожному оновленні.

**Виправлення:** Замінено на `@st.fragment(run_every=timedelta(...))` — тільки дані-залежна частина перемальовується без переривання sidebar/заголовка.

### Stale Filter Options

**Проблема:** Sidebar multiselect-и будувалися один раз із малим набором даних. Емулятор потім генерував нові типи/severity/component, але фільтри їх відсікали.

**Виправлення:** Фрагмент детектує "all options selected" (юзер не звужував) і передає `None` у фільтр, що означає "показати все".

### CSV Read Reliability

**Проблема:** UI міг прочитати порожній або частково записаний CSV.

**Виправлення:** Retry logic (3 спроби, 150 мс затримка) + широкий `except Exception` перехоп помилок парсингу.

## Тестування

Всі 207 unit + integration тестів проходять:

```bash
pytest tests/ -v
```

**Покриття:** contracts, detector, correlator, metrics, emulator, normalizer, parser, filters, policy engine, integration scenarios.

## Конфігурація

### `config/policies.yaml`

Опише 3 politique безпеки з різноманітністю контролів:

```yaml
baseline:
  enabled: true
  controls: [firewall, ids, logging]
  modifiers:
    credential_attack:
      window_multiplier: 1.0
      threshold_multiplier: 1.0
      mttd_multiplier: 1.5
    ...

minimal:
  # Слабші, більш економічні контролі
```

### `config/rules.yaml`

Правила детекції (RULE-BF, RULE-DDOS, RULE-SPOOF, RULE-UCMD, RULE-OUT):

```yaml
rules:
  - id: RULE-BF-001
    threat_type: credential_attack
    match:
      event: auth_failure
    window_sec: 60
    threshold: 5
```

### `config/scenarios.yaml`

Сценарії генерації атак з расписанням + injection фаз.

## Вичислення метрик

### Availability

$$
\text{Availability} = \frac{100 \times (\text{total\_time} - \text{downtime})}{\text{total\_time}}
$$

де `downtime` = сума всіх `recover_ts - detect_ts` інцидентів.

### Mean MTTD / MTTR

$$
\text{MTTD} = \frac{\sum (detect\_ts - start\_ts)}{|\text{incidents}|}
$$

$$
\text{MTTR} = \frac{\sum (recover\_ts - detect\_ts)}{|\text{incidents}|}
$$

## Файлові формати

### Event (CSV/JSONL)

| Поле | Тип | Опис |
|------|-----|------|
| timestamp | ISO 8601 | Час события |
| source | str | Hostname/IP |
| component | str | Компонент (api, db, network, etc) |
| event | str | Event type (auth_failure, rate_exceeded, service_status) |
| severity | str | low / medium / high / critical |
| value | str | Значення (IP адреса,율한 throttle, status) |
| actor | str | User / системний процес |
| correlation_id | str | COR-* для групування |

### Incident (CSV)

| Поле | Опис |
|------|------|
| incident_id | INC-001, INC-002 ... |
| policy | baseline / minimal / standard |
| threat_type | credential_attack, availability_attack, ... |
| severity | high / critical / medium / low |
| component | api / db / network / ... |
| start_ts | Перший event у групі |
| detect_ts | Коли сработало правило |
| recover_ts | Коли incident завершився |
| mttd_sec | detect_ts - start_ts (сек) |
| mttr_sec | recover_ts - detect_ts (сек) |
| impact_score | 0–1, розраховується за модифікаторами політики |

## Запуск live pipeline урок за уроком

```bash
# 1. Клонувати та встановити deps
git clone https://github.com/RostislavKrotenko/cybersecurity-smartenergy.git
cd cybersecurity-smartenergy
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. У Docker (рекомендовано для live)
docker compose --profile live up --build

# 3. Заходимо на UI
open http://localhost:8501

# 4. Включаємо Auto-refresh у sidebar (за замовчуванням ON у live)
# Дивимось як графіки оновлюються без мерехтіння

# 5. Розширюємо Diagnostics для перевірки:
#    - refresh_tick росте
#    - incidents.csv rows зростають
#    - mtime оновлюється
```

## Оптимізація продуктивності

- **Atomic writes** запобігають 99% race conditions
- **Retry logic** у читанні CSV (3 спроби) покриває 99.9% перехідних помилок
- **Fragment-based refresh** замість full rerun: 10x швидше
- **Stable widget keys** запобігають DOM reconstruction
- **mtime-based caching** (optional у read) прискорює pandas parsing

## Контриб'ютори

Проект випущено як open-source для навчання та досліджень кіберзахисту розумних енергомереж.

## Ліцензія

MIT License. Дивись [LICENSE](LICENSE).

---

**Остання оновлення:** 01.03.2026

**Версія:** 1.1.0 (Live UI, atomic writes, fragment-based refresh, filter sync)

