# SmartEnergy Cyber-Resilience Analyzer

Прототип closed-loop системи кіберреагування для SmartEnergy: генерація подій, детекція інцидентів, автоматичні дії та live-візуалізація стану інфраструктури.

## Призначення

Проєкт моделює кібератаки і реакції на них для таких зон:
- Gateway
- API
- Auth
- Database (Postgres)
- Network

Система оцінює ефективність політик безпеки `minimal`, `baseline`, `standard` через метрики Availability / MTTD / MTTR.

## Архітектура

| Модуль | Роль |
|---|---|
| Emulator | Генерує фонові й атакуючі події, підтримує live-потік і closed-loop |
| Analyzer | Детекція -> кореляція -> інциденти -> рішення (actions) -> ACK/state update |
| API | REST API бекенд (FastAPI) |
| Frontend | React дашборд з Tailwind CSS |

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

Фронтенд побудовано на:
- React 18 + TypeScript
- Vite (збірка)
- Tailwind CSS (стилі)
- Recharts (графіки)
- TanStack Query (data fetching)

### Компоненти UI

- **Policy KPI Cards** — доступність, простій, MTTD/MTTR для кожної політики
- **Component Status Cards** — стан Gateway, API, Auth, DB, Network
- **Action Summary Card** — статус виконаних/невдалих дій
- **Charts** — Availability, Downtime, Incidents/min, Actions/min
- **Tables** — інциденти та дії з пагінацією

### Команди

```bash
make frontend-install   # Встановити залежності
make frontend-dev       # Dev сервер (localhost:5173)
make frontend-build     # Production build
```

## Closed-loop реагування

### Gateway / API / Auth

- `availability_attack` -> `enable_rate_limit` (Gateway)
- `availability_attack` + critical -> `isolate_component` (API)
- `credential_attack` -> `block_actor` (Auth)

### Database / Network

- `outage` -> `backup_db`, `restore_db`
- `network_failure` -> `degrade_network`

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

## Ліцензія

MIT (див. LICENSE)
