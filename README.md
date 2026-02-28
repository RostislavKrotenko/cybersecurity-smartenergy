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

## Ліцензія

MIT — див. [LICENSE](LICENSE).

