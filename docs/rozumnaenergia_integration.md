# Інтеграція кіберзахисту в `rozumnaEnergia`

## Призначення

Модуль підвищує функціональну стійкість захищеного HTTP-контуру й контуру
MQTT-телеметрії. Він не змінює код інших підсистем Smart Energy.

Один Docker image запускається сімома окремими сервісами:

- `cybersecurity-gateway-iot` — reverse proxy для Smart Energy API;
- `cybersecurity-gateway-bms` — reverse proxy для BMS;
- `cybersecurity-collector` — окремі журнали обох Gateway, MQTT і health checks;
- `cybersecurity-analyzer` — правила виявлення інцидентів;
- `cybersecurity-control-iot` — дії лише для `iot-gateway`;
- `cybersecurity-control-bms` — дії лише для `bms-gateway`;
- `cybersecurity-api` — агрегований snapshot для React UI.

## Реальний потік аналізу

1. Кожен Gateway пише власний state та журнал подій зі своїм `serviceId`.
2. Collector незалежно читає обидва журнали та підписується на MQTT topic
   `sensor/data` із QoS 1.
3. MQTT payload нормалізується в канонічні вимірювання. Якщо `voltage` або
   `power_kw` аномальні, весь пакет зберігається в окремому quarantine JSONL,
   а до Analyzer надходить лише подія `telemetry_quarantined`.
4. Analyzer перевіряє API flood, `voltage`, `power_kw` і недоступність upstream.
5. Для DDoS-інцидентів `source` визначає конкретний `serviceId`; відповідний
   Control застосовує rate limiting та контрольовану ізоляцію лише до свого
   Gateway.
6. ACK, idempotency і checkpoints запобігають повторному виконанню після restart.
7. Cybersecurity API передає результати на React Router маршрут `/cybersecurity`.

Типова затримка появи MQTT-події на UI становить кілька секунд: Collector та
Analyzer працюють із секундним poll interval, а UI оновлюється кожні 5 секунд.

## Активні правила

- `RULE-DDOS-001` — серія `rate_exceeded` від захисного Gateway;
- `RULE-SPOOF-001` — аномалії MQTT-показників `voltage` і `power_kw`;
- `RULE-OUT-001` — недоступність Gateway або захищеного upstream.

Brute force, несанкціоновані команди, пошкодження БД та складні мережеві
інциденти не є активними правилами інтеграції. Відповідні сценарії можуть
залишатися в емуляторі лише як дослідницькі матеріали.

## Read-only availability

Cybersecurity API паралельно перевіряє:

- телеметричний endpoint Gateway;
- BMS батареї;
- налаштування гібридного інвертора;
- API функціональної стійкості;
- History API;
- health endpoint InfluxDB;
- TCP-доступність MongoDB, MQTT і WebSocket endpoint.

Ці адаптери показують `ready`, `partial` або `unavailable` і затримку відповіді.
Вони не аналізують вміст БД, не доводять мережеву атаку й не надсилають команд
іншим сервісам.

## UI

Маршрут `http://localhost:5173/cybersecurity` показує:

- окремі стани `iot-gateway`, `bms-gateway` і Cybersecurity API;
- останні MQTT-показники з позначкою `аналізується` або `лише збір`;
- MQTT-повідомлення, вилучені до карантину;
- доступність зовнішніх HTTP/TCP компонентів;
- активні інциденти та фактичний журнал дій;
- модельні порівняльні MTTD, MTTR і availability для політик.

Порівняльні метрики політик не потрібно називати фактичним часом стендової
реакції. Фактичні значення можна окремо розраховувати з timestamp події,
інциденту, ACK і відновлення.

## Запуск у загальному Compose

Створіть локальний `.env` на основі `.env.example`, задайте випадковий
`GATEWAY_CONTROL_TOKEN`, а потім запустіть:

```bash
docker compose pull --ignore-buildable
docker compose up -d --build
docker compose ps
```

Основні перевірки:

```bash
curl -sS http://localhost:6066/_cybersecurity/healthz
curl -sS http://localhost:6065/_cybersecurity/healthz
curl -sS http://localhost:6049/healthz
curl -sS http://localhost:6049/api/cybersecurity/snapshot
```
