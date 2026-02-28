# SmartEnergy Cyber-Resilience Analyzer

**Система аналізу кіберстійкості розумних енергомереж** — прототип для магістерської роботи.

## Про проєкт

SmartEnergy Cyber-Resilience Analyzer — платформа для моделювання кібератак на компоненти розумної енергомережі та оцінки ефективності різних політик безпеки.

Система складається з чотирьох модулів:

| Модуль | Опис |
|--------|------|
| **Emulator** | Генерує синтетичні події безпеки (brute-force, DDoS, спуфінг телеметрії тощо) |
| **Normalizer** | Перетворює сирі логи у єдиний нормалізований формат |
| **Analyzer** | Детекція загроз, кореляція алертів в інциденти, розрахунок метрик (Availability, MTTD, MTTR) |
| **Dashboard** | Streamlit-дашборд з графіками та таблицями в реальному часі |

Оцінювання проводиться по трьох політиках безпеки: **baseline**, **minimal**, **standard**.

## Вимоги

- Python 3.11+
- Docker та Docker Compose (для контейнеризованого запуску)

## Локальний запуск

### 1. Встановлення залежностей

```bash
git clone https://github.com/RostislavKrotenko/cybersecurity-smartenergy.git
cd cybersecurity-smartenergy
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 2. Запуск через Make (пакетний режим)

```bash
# Генерація подій → аналіз → дашборд
make demo-local
```

Або покроково:

```bash
make generate    # Емуляція подій → data/events.csv
make analyze     # Аналіз → out/results.csv, out/incidents.csv
make ui          # Дашборд → http://localhost:8501
```

### 3. Запуск у live-режимі (без Docker)

```bash
make demo-live
```

Емулятор безперервно генерує події, аналізатор обробляє їх у реальному часі, дашборд оновлюється автоматично.

### 4. Запуск через Docker Compose

```bash
# Live-режим (рекомендовано)
docker compose --profile live up --build

# Пакетний режим
make demo
```

Дашборд доступний за адресою: [http://localhost:8501](http://localhost:8501)

## Тестування

```bash
make test        # Запуск тестів
make test-cov    # Тести з покриттям
make lint        # Перевірка якості коду (ruff)
```

## Demo High-Rate профіль (швидке демо)

Профіль `demo_high_rate` генерує 1 інцидент кожні 10 секунд (3--6 інц./хв)
завдяки tick-орієнтованому потоку з періодичними attack-burst-ами.

### Параметри CLI емулятора

| Параметр | Default | Опис |
|----------|---------|------|
| `--profile demo_high_rate` | `default` | Активує high-rate потік |
| `--live-interval-ms` | `250` | Інтервал між тіками (мс) |
| `--attack-every-sec` | `10` | Секунди між burst-ін'єкціями (round-robin через 5 сценаріїв) |
| `--background-events-per-tick` | `20` | Фонових подій за тік |
| `--max-file-mb` | `50` | Ротація файлу при перевищенні (MB) |

### Запуск (Docker, рекомендовано)

```bash
docker compose --profile live up --build
```

Емулятор автоматично використовує `demo_high_rate` профіль
(див. `docker-compose.yml`, сервіс `emulator-live`).

### Запуск вручну (без Docker)

```bash
# Термінал 1 — емулятор
python -m src.emulator \
  --live \
  --profile demo_high_rate \
  --live-interval-ms 250 \
  --attack-every-sec 10 \
  --background-events-per-tick 20 \
  --max-file-mb 50 \
  --out data/live/events.jsonl \
  --raw-log-dir logs/live \
  --csv-out data/live/events.csv

# Термінал 2 — аналізатор (watch mode)
python -m src.analyzer \
  --input data/live/events.jsonl \
  --watch \
  --poll-interval-ms 1000 \
  --out-dir out \
  --policies all

# Термінал 3 — дашборд (auto-refresh 3 сек)
SMARTENERGY_LIVE_MODE=1 streamlit run src/dashboard/app.py
```

### Перевірка

За 60 секунд після старту:

```bash
# Має бути >= 3-6 інцидентів
wc -l out/incidents.csv

# Перевірити типи загроз
cut -d, -f3 out/incidents.csv | sort | uniq -c
```

Очікуваний результат: credential_attack, availability_attack,
integrity_attack, outage -- всі типи мають з'явитися протягом 50 секунд.
Метрика "Incidents per Minute" на дашборді змінюється в реальному часі.

### Як працює burst-ін'єкція

Кожні `--attack-every-sec` секунд емулятор генерує пакет подій (burst)
для одного зі сценаріїв (round-robin):

| Сценарій | Подій у burst | Правило | Поріг |
|----------|--------------|---------|-------|
| brute_force | 8 auth_failure | RULE-BF-001 | >= 5 / 60s |
| ddos_abuse | 15 rate_exceeded + 2 svc | RULE-DDOS-001 | >= 10 / 30s |
| telemetry_spoofing | 6 anomalous telemetry | RULE-SPOOF-001 | >= 3 / 60s |
| unauthorized_command | 3 cmd_exec | RULE-UCMD-001 | >= 1 |
| outage_db_corruption | 3 db_error + 2 svc | RULE-OUT-001/002 | >= 2 / 120s |

Кожен burst калібрований з запасом: кількість подій перевищує поріг
детекції, тому інцидент з'являється гарантовано.

## Ліцензія

MIT -- див. [LICENSE](LICENSE).

