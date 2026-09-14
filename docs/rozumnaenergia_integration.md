# Інтеграція кіберзахисту в rozumnaEnergia

## Призначення

Модуль кіберзахисту надає окремий backend, який читає стан SmartEnergy, формує інциденти, рішення та записи диспетчера дій, а React UI показує один агрегований snapshot. UI не звертається напряму до сервісів інших учасників.

## Потік даних

1. React маршрут `cybersecurity-krotenko` звертається до `http://77.47.192.6:6049/api/cybersecurity/snapshot`.
2. FastAPI backend кіберзахисту читає власні джерела стану, інцидентів, дій і метрик.
3. Якщо увімкнено `CYBERSECURITY_EXTERNAL_READS=true`, backend виконує read-only перевірки зовнішніх сервісів SmartEnergy.
4. Backend повертає один snapshot із блоками `backend`, `api`, `readOnly`, `network`, `metrics`, `incidents`, `actions`.

## Docker service

У `rozumnaEnergia/docker-compose.yaml` додається сервіс `cybersecurity-krotenko`.

- Порт назовні: `6049`.
- Внутрішній порт контейнера: `8000`.
- Образ: `smartenergy-cybersecurity:0.1.0` або значення змінної `CYBERSECURITY_IMAGE`.
- Команда запуску: `python -m src.api --host 0.0.0.0 --port 8000`.
- Для сервера потрібно опублікувати цей самий versioned образ у Docker Registry й передати його назву через `CYBERSECURITY_IMAGE`.
- Локальні шляхи до `data`, `out`, `config` і `logs` не використовуються; runtime-стан зберігається в named volumes.

## Режими інтеграції

- `dry-run` — backend тільки моделює рішення.
- `shadow` — backend читає реальні джерела, але не виконує зовнішні керувальні команди.
- `active` — режим для майбутнього контрольованого виконання команд через dispatcher.

Поточне значення задається через `CYBERSECURITY_INTEGRATION_MODE`.

## Read-only адаптери

Backend підтримує такі джерела:

- `gateway-telemetry` — HTTP telemetry gateway.
- `bms-state` — HTTP стан Battery BMS.
- `inverter-settings` — HTTP налаштування hybrid inverter.
- `troian-advisor` — HTTP advisor функціональної стійкості.
- `history-api` — HTTP history API.
- `influxdb-health` — HTTP health InfluxDB.
- `mongodb-socket` — TCP перевірка MongoDB.
- `mqtt-broker` — TCP перевірка MQTT broker.
- `functional-stability-ws` — TCP перевірка WebSocket сервісу функціональної стійкості.

Якщо чужий сервіс не запущений або має іншу адресу, адаптер переходить у `unavailable`. Це очікуваний стан, а не помилка UI.

## Канонічні шари

Snapshot нормалізує стан у пʼять шарів:

- `gateway`
- `api`
- `auth`
- `db`
- `network`

Ці шари використовуються в UI, правилах інцидентів і рішеннях dispatcher-а.

## Dispatcher

Диспетчер дій повертає три режими:

- `applied` — локальний read-only стан або вже застосована дія.
- `recommended` — дія можлива тільки після ручного підтвердження.
- `unsupported` — автодія заблокована або не підтримується поточним режимом.

У режимі `shadow` зовнішні керувальні команди не виконуються автоматично.

## Перевірка

Backend:

```bash
.venv/bin/python -m pytest tests/test_api_endpoints.py -q
```

Локальне створення production-образу:

```bash
docker build -t smartenergy-cybersecurity:0.1.0 .
```

Frontend:

```bash
npm run build
```

Docker:

```bash
CYBERSECURITY_IMAGE=smartenergy-cybersecurity:0.1.0 docker compose up -d cybersecurity-krotenko
curl http://127.0.0.1:6049/api/health
curl "http://127.0.0.1:6049/api/cybersecurity/snapshot?incident_limit=3&action_limit=8"
```

UI:

```bash
VITE_CYBERSECURITY_API_URL=http://127.0.0.1:6049 npm run dev -- --host 127.0.0.1 --port 5174
```

Після запуску маршрут доступний за адресою `http://127.0.0.1:5174/cybersecurity-krotenko`.
