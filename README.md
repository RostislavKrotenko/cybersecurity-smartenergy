# SmartEnergy Cyber-Resilience Analyzer

Контейнеризований модуль кіберзахисту та функціональної стійкості SmartEnergy:
захисний reverse proxy, near-real-time аналіз MQTT-телеметрії,
автоматичне реагування й read-only моніторинг доступності компонентів.

## Призначення

Активна інтеграція забезпечує:

- незалежний захист кількох backend-контурів окремими Gateway-екземплярами;
- виявлення та пом'якшення API flood/DDoS;
- rate limiting і автоматичне блокування джерел;
- circuit breaker, контрольовану ізоляцію та stale-cache;
- аналіз реальної MQTT-телеметрії за ключами `voltage` і `power_kw`;
- карантин усього MQTT-повідомлення, якщо його контрольований показник
  виходить за фізичні межі або містить небезпечний стрибок;
- read-only перевірки доступності HTTP/TCP компонентів;
- відновлення стану дій за допомогою ACK, idempotency і checkpoints.

Сценарії автентифікації, пошкодження БД, несанкціонованих команд і складних
мережевих атак можуть залишатися в емуляторі як дослідницькі дані, але не є
активними можливостями інтеграції `rozumnaEnergia`.

Система оцінює ефективність політик безпеки `minimal`, `baseline`, `standard` через метрики Availability / MTTD / MTTR.

## Архітектура

| Модуль | Роль |
|---|---|
| Gateway | Окремий reverse proxy для кожного `serviceId`: rate limiting, блокування, circuit breaker і stale-cache |
| Collector | Збирає розділені журнали кількох Gateway, MQTT і перевірки доступності |
| Analyzer | Виявляє DDoS, аномалії телеметрії та недоступність upstream |
| Control | Ідемпотентно застосовує підтримувані дії через Gateway |
| API | Формує агрегований snapshot для UI |
| Emulator | Окремий дослідницький генератор сценаріїв, не джерело production-даних |

## Docker профілі

| Профіль | Опис |
|---------|------|
| `live` | Повний closed-loop: Emulator → Analyzer → API + React Frontend + Postgres |
| `api` | Тільки REST API (потребує готових даних в `out/`) |

## Вимоги

- Python 3.11+
- Node.js 20+
- Docker + Docker Compose

## Швидкий старт

### Через Docker (рекомендовано)

```bash
docker compose --profile live down -v && docker compose --profile live up -d --build --force-recreate
```

Або через Makefile:

```bash
make docker-live
```

### Публікація production-образу в Docker Hub

Загальний проєкт використовує один versioned image для Gateway, Collector,
Analyzer, Control та API. На ARM-комп'ютері образ для production AMD-сервера
потрібно збирати явно для `linux/amd64`:

```bash
docker login
docker buildx create --name smartenergy-builder --use
docker buildx inspect --bootstrap
docker buildx build \
  --platform linux/amd64 \
  --tag rostyslavkrotenko/cybersecurity-smartenergy:latest \
  --push \
  .
docker buildx imagetools inspect \
  rostyslavkrotenko/cybersecurity-smartenergy:latest
```

Якщо builder `smartenergy-builder` уже існує, замість його повторного створення
використовуйте:

```bash
docker buildx use smartenergy-builder
```

Тег у `docker-compose.yaml` загального проєкту потрібно оновлювати лише після
успішної публікації нового versioned image. Реальні токени й файли `.env` у
Docker image та Git додавати не можна.

### Локально (без Docker)

```bash
# Backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .

# Frontend
cd frontend && npm install && cd ..

# Запуск
make demo-live
```

В окремому терміналі для фронтенду:

```bash
make frontend-dev
```

## Endpoints

| URL | Опис |
|-----|------|
| http://localhost:5173 | React Dashboard (основний UI) |
| http://localhost:8000/api/docs | Swagger UI (API документація) |
| http://localhost:8000/api/incidents | Інциденти |
| http://localhost:8000/api/actions | Дії |
| http://localhost:8000/api/state | Стан компонентів |
| http://localhost:8000/api/metrics | Метрики |

## REST API

API побудовано на FastAPI з автоматичною документацією.

### Основні endpoints

```
GET /api/incidents           - список інцидентів (з фільтрами)
GET /api/incidents/count     - кількість інцідентів
GET /api/actions             - список дій + статистика
GET /api/actions/summary     - статистика дій
GET /api/state               - стан усіх компонентів
GET /api/state/components/{id}     - стан конкретного компонента
GET /api/metrics             - метрики по політиках
GET /api/metrics/overall     - загальні метрики
GET /api/health              - health check
```

## Frontend (React)

Активний UI інтегровано як React Router маршрут `/cybersecurity` у репозиторії
`rozumnaEnergia`. Він показує окремі стани кожного Gateway, стан API, останню
MQTT-телеметрію та карантинні записи,
read-only доступність зовнішніх компонентів, інциденти, фактичні дії та
порівняльні метрики політик.

MTTD, MTTR і availability у таблиці політик є модельними порівняльними
показниками. Вони не подаються як фактичний час стендової реакції.

### Команди

```bash
make frontend-install   # Встановити залежності
make frontend-dev       # Dev сервер (localhost:5173)
make frontend-build     # Production build
```

## Closed-loop реагування

### Gateway / API

- `availability_attack` -> `enable_rate_limit` (Gateway)
- `availability_attack` + critical -> `isolate_component` (API)
- повторні порушення rate limit -> автоматичне блокування джерела (Gateway)
- `integrity_attack` для MQTT -> повний payload вилучається з робочої
  телеметрії, а Analyzer отримує лише службову подію карантину
- `outage` -> фіксація інциденту; circuit breaker і stale-cache виконуються
  безпосередньо Gateway

## Дані та часові мітки

- Усі timestamp зберігаються в UTC.
- Dashboard/API конвертує час лише для відображення.

Основні live-файли:
- `data/live/events.jsonl`
- `data/live/actions.jsonl`
- `data/live/actions_applied.jsonl`
- `out/incidents.csv`
- `out/actions.csv`
- `out/state.csv`

## Тести та якість

```bash
make test
make test-cov
make lint
```

Запуск по маркерах (`pytest -m`) для вибіркових прогонів:

```bash
# Компоненти
pytest -m component_api
pytest -m component_analyzer
pytest -m component_emulator

# Типи
pytest -m type_smoke
pytest -m type_integration

# Пріоритети
pytest -m priority_p0
pytest -m "priority_p1 and component_api"

# Виключити зовнішні/повільні
pytest -m "not external and not slow"
```

## Інтеграційна готовність

Пакет артефактів для підключення до реальної SmartEnergy системи винесено у wiki:
- https://github.com/RostislavKrotenko/cybersecurity-smartenergy/wiki/Integration-Readiness

Безпечні режими запуску аналізатора:

```bash
# dry-run: план дій без емісії в зовнішню систему
python -m src.analyzer --watch --input data/live/events.jsonl --integration-mode dry-run

# shadow: план дій у shadow-режимі (без емісії)
python -m src.analyzer --watch --input data/live/events.jsonl --integration-mode shadow

# active: активна емісія дій у ActionSink
python -m src.analyzer --watch --input data/live/events.jsonl --integration-mode active
```

## Ліцензія

MIT (див. LICENSE)
