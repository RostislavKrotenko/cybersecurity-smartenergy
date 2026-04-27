# Тест-кейси для дипломної роботи

> Документ підготовлено відповідно до сценарного підходу прийому програмного забезпечення
> в рамках системи SmartEnergy (підготовлено 03.04.2026).

---

## Шаблон запису тест-кейсу

| Поле | Опис |
|------|------|
| **ID** | Унікальний ідентифікатор (N.M) |
| **Назва** | Коротка описова назва |
| **Компонент** | Модуль або підсистема |
| **Тип** | smoke / unit / integration / e2e |
| **Пріоритет** | P0 (критичний) … P3 (низький) |
| **Передумови** | Стан системи до виконання кроків |
| **Кроки** | Послідовність дій |
| **Очікуваний результат** | Що повинно відбутися |
| **Маркери pytest** | Відповідні мітки для `pytest -m` |

---

## Студент 1: Кротенко Ростислав
## Керівник 1: *(вказати ПІБ наукового керівника)*
## Тема 1: Прототип системи кіберреагування замкненого циклу для SmartEnergy

---

### 1. Модуль Emulator (генерація подій)

---

#### Тест-кейс 1.1 — Генерація фонових подій

| Поле | Значення |
|------|----------|
| **ID** | 1.1 |
| **Назва** | Генерація нормальних фонових подій |
| **Компонент** | Emulator |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | Пакет `src.emulator` встановлено; конфіг `config/scenarios.yaml` присутній |

**Кроки:**
1. Ініціалізувати `EmulatorEngine` у режимі фону (без атак).
2. Запустити генерацію на горизонт 60 секунд.
3. Зібрати згенеровані події.

**Очікуваний результат:**
- Повернуто список об'єктів `Event` з ненульовою довжиною.
- Кожна подія містить валідний ISO-8601 `timestamp` (суфікс `Z`).
- Поля `source`, `component`, `event` — непорожні рядки.
- Жодна подія не має `event` типу атаки (`auth_failure`, `rate_exceeded` тощо).

**Маркери pytest:** `component_emulator`, `type_unit`, `priority_p1`

---

#### Тест-кейс 1.2 — Генерація сценарію brute-force

| Поле | Значення |
|------|----------|
| **ID** | 1.2 |
| **Назва** | Генерація атаки методом перебору паролів (brute-force) |
| **Компонент** | Emulator → `BruteForceScenario` |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | Конфігурація сценарію `brute_force` присутня у `config/scenarios.yaml` |

**Кроки:**
1. Ініціалізувати `BruteForceScenario` з IP-пулом `["10.0.0.1"]` і цільовим вузлом `api-gw-01`.
2. Викликати метод `generate()`.
3. Перевірити структуру подій.

**Очікуваний результат:**
- Хоча б одна подія має `event == "auth_failure"`.
- Усі події мають однаковий `correlation_id` (формат `COR-XXX`).
- `ip` кожної події знаходиться в IP-пулі.
- Timestamp-и відсортовані у зростаючому порядку.

**Маркери pytest:** `component_emulator`, `type_unit`, `priority_p1`

---

#### Тест-кейс 1.3 — Генерація сценарію DDoS-атаки

| Поле | Значення |
|------|----------|
| **ID** | 1.3 |
| **Назва** | Генерація DDoS / флуду API |
| **Компонент** | Emulator → `DDoSAbuseScenario` |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | Конфігурація сценарію `ddos_abuse` присутня |

**Кроки:**
1. Ініціалізувати `DDoSAbuseScenario` з цільовим source `api-gw-01`.
2. Викликати `generate()` і зібрати події.

**Очікуваний результат:**
- Містить події `rate_exceeded` у кількості ≥ порогу правила RULE-DDOS-001 (10 подій за 30 с).
- Може додатково включати `service_status` події з `value == "degraded"` (ескалація).
- `component` подій — `"api"` або `"gateway"`.

**Маркери pytest:** `component_emulator`, `type_unit`, `priority_p1`

---

#### Тест-кейс 1.4 — Генерація сценарію спуфінгу телеметрії

| Поле | Значення |
|------|----------|
| **ID** | 1.4 |
| **Назва** | Генерація аномальних показників телеметрії (spoofing) |
| **Компонент** | Emulator → `TelemetrySpoofScenario` |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | Конфігурація сценарію `telemetry_spoof` присутня |

**Кроки:**
1. Ініціалізувати `TelemetrySpoofScenario` із стандартною конфігурацією.
2. Викликати `generate()`.
3. Перевірити значення `value` для ключа `voltage`.

**Очікуваний результат:**
- Щонайменше одна подія `telemetry_read` з `key == "voltage"` і `value` поза межами `[180.0, 280.0]` В або зі стрибком `> 50.0` В від попереднього зчитування.
- `component` — `"edge"` або схожий.

**Маркери pytest:** `component_emulator`, `type_unit`, `priority_p1`

---

#### Тест-кейс 1.5 — Генерація несанкціонованих команд

| Поле | Значення |
|------|----------|
| **ID** | 1.5 |
| **Назва** | Генерація несанкціонованого виконання команди управління |
| **Компонент** | Emulator → `UnauthorizedCmdScenario` |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | Конфігурація сценарію `unauthorized_cmd` присутня |

**Кроки:**
1. Ініціалізувати `UnauthorizedCmdScenario`.
2. Викликати `generate()`.
3. Перевірити поля `actor` і `event`.

**Очікуваний результат:**
- Щонайменше одна подія `cmd_exec`, де `actor` — НЕ `"operator"` і НЕ `"admin"`.
- `severity` — `"critical"`.

**Маркери pytest:** `component_emulator`, `type_unit`, `priority_p1`

---

#### Тест-кейс 1.6 — Генерація сценарію збою мережі

| Поле | Значення |
|------|----------|
| **ID** | 1.6 |
| **Назва** | Генерація подій деградації та відмови мережі |
| **Компонент** | Emulator → `NetworkFailureScenario` |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | Конфігурація сценарію `network_failure` присутня |

**Кроки:**
1. Ініціалізувати `NetworkFailureScenario`.
2. Викликати `generate()`.
3. Перевірити `component` і `value` подій `service_status`.

**Очікуваний результат:**
- Щонайменше одна подія `service_status` з `component == "network"`.
- `value` є одним із `["degraded", "down", "packet_loss", "timeout", "unreachable"]`.

**Маркери pytest:** `component_emulator`, `type_unit`, `priority_p1`

---

#### Тест-кейс 1.7 — Запис подій у JSONL-файл через FileEventSink

| Поле | Значення |
|------|----------|
| **ID** | 1.7 |
| **Назва** | Запис та зчитування події через файловий адаптер |
| **Компонент** | Emulator + FileAdapter |
| **Тип** | integration |
| **Пріоритет** | P1 |
| **Передумови** | Тимчасовий каталог доступний (pytest `tmp_path`) |

**Кроки:**
1. Ініціалізувати `FileEventSink` з шляхом до тимчасового файлу.
2. Записати одну подію `http_request` через `emit()`.
3. Закрити синк (`close()`).
4. Ініціалізувати `FileEventSource` з тим самим шляхом.
5. Зчитати першу партію (`read_batch(limit=10)`).

**Очікуваний результат:**
- Зчитано рівно 1 подію.
- `batch[0].event == "http_request"`.
- Файл містить валідний JSONL-рядок.

**Маркери pytest:** `component_adapters`, `component_emulator`, `type_integration`, `priority_p1`

---

### 2. Модуль Analyzer — Detector (детекція загроз)

---

#### Тест-кейс 2.1 — Детекція брутфорс-атаки (RULE-BF-001)

| Поле | Значення |
|------|----------|
| **ID** | 2.1 |
| **Назва** | Детекція N auth_failure подій з одного IP у часовому вікні |
| **Компонент** | Analyzer → Detector |
| **Тип** | unit |
| **Пріоритет** | P0 |
| **Передумови** | Правило RULE-BF-001 увімкнене (`enabled: true`); threshold=5, window=60 с |

**Кроки:**
1. Створити 5 подій `auth_failure` від IP `10.0.0.1` з інтервалами 3 с.
2. Передати події та конфіг правила до `detect(events, rules_cfg)`.
3. Перевірити результат.

**Очікуваний результат:**
- `len(alerts) >= 1`.
- `alerts[0].threat_type == "credential_attack"`.
- `alerts[0].severity == "high"`.
- `alerts[0].confidence == 0.85`.
- `alerts[0].response_hint == "block_ip"`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p0`

---

#### Тест-кейс 2.2 — Відсутність хибних спрацьовувань при малій кількості auth_failure

| Поле | Значення |
|------|----------|
| **ID** | 2.2 |
| **Назва** | Негативний тест: 4 auth_failure — нижче порогу → без алерту |
| **Компонент** | Analyzer → Detector |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | RULE-BF-001, threshold=5 |

**Кроки:**
1. Створити 4 події `auth_failure` з одного IP.
2. Передати до `detect()`.

**Очікуваний результат:**
- `len(alerts) == 0` — жодного алерту не створено.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p1`

---

#### Тест-кейс 2.3 — Детекція DDoS флуду (RULE-DDOS-001)

| Поле | Значення |
|------|----------|
| **ID** | 2.3 |
| **Назва** | Детекція масивного перевищення rate limit (DDoS) |
| **Компонент** | Analyzer → Detector |
| **Тип** | unit |
| **Пріоритет** | P0 |
| **Передумови** | RULE-DDOS-001, threshold=10, window=30 с |

**Кроки:**
1. Створити 12 подій `rate_exceeded` від `source="api-gw-01"` з інтервалами 2 с.
2. Передати до `detect()`.

**Очікуваний результат:**
- `len(alerts) >= 1`.
- `alerts[0].threat_type == "availability_attack"`.
- `alerts[0].severity == "critical"`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p0`

---

#### Тест-кейс 2.4 — Ескалація DDoS із деградацією сервісу (RULE-DDOS-002)

| Поле | Значення |
|------|----------|
| **ID** | 2.4 |
| **Назва** | DDoS + service_status degraded → ескалація severity та confidence |
| **Компонент** | Analyzer → Detector |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | RULE-DDOS-001 з sub-rule RULE-DDOS-002 |

**Кроки:**
1. Згенерувати 12 подій `rate_exceeded` від `api-gw-01`.
2. Додати одну подію `service_status` з `value="degraded"` від `api-gw-01` через 30 с після початку флуду.
3. Передати до `detect()`.

**Очікуваний результат:**
- Алерт з `confidence >= 0.98`.
- `description` містить підрядок `"+ service impact"`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p1`

---

#### Тест-кейс 2.5 — Детекція аномалій телеметрії (RULE-SPOOF-001)

| Поле | Значення |
|------|----------|
| **ID** | 2.5 |
| **Назва** | Детекція виходу напруги за допустимі межі |
| **Компонент** | Analyzer → Detector |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | RULE-SPOOF-001; bounds voltage: [180, 280]; threshold=3 |

**Кроки:**
1. Створити 3 події `telemetry_read` з `key="voltage"` і `value="350"` (поза межами).
2. Передати до `detect()`.

**Очікуваний результат:**
- `len(alerts) >= 1`.
- `alerts[0].threat_type == "integrity_attack"`.
- `alerts[0].response_hint == "flag_for_review"`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p1`

---

#### Тест-кейс 2.6 — Детекція несанкціонованої команди (RULE-UCMD-001)

| Поле | Значення |
|------|----------|
| **ID** | 2.6 |
| **Назва** | Команда управління від неавторизованого актора |
| **Компонент** | Analyzer → Detector |
| **Тип** | unit |
| **Пріоритет** | P0 |
| **Передумови** | RULE-UCMD-001; allowed_actors = [operator, admin]; threshold=1 |

**Кроки:**
1. Створити одну подію `cmd_exec` з `actor="guest"`.
2. Передати до `detect()`.

**Очікуваний результат:**
- `len(alerts) == 1`.
- `alerts[0].severity == "critical"`.
- `alerts[0].confidence >= 0.95`.
- `alerts[0].response_hint == "block_actor_and_alert"`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p0`

---

#### Тест-кейс 2.7 — Детекція відмови сервісу (RULE-OUT-001)

| Поле | Значення |
|------|----------|
| **ID** | 2.7 |
| **Назва** | Ескалація до critical при service_status = down |
| **Компонент** | Analyzer → Detector |
| **Тип** | unit |
| **Пріоритет** | P0 |
| **Передумови** | RULE-OUT-001; severity_override: [{value: down, severity: critical}] |

**Кроки:**
1. Створити одну подію `service_status` з `key="status"`, `value="down"`, `source="db-primary"`.
2. Передати до `detect()`.

**Очікуваний результат:**
- `alerts[0].threat_type == "outage"`.
- `alerts[0].severity == "critical"` (override спрацював).

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p0`

---

#### Тест-кейс 2.8 — Детекція мережевої відмови (RULE-NET-001)

| Поле | Значення |
|------|----------|
| **ID** | 2.8 |
| **Назва** | Детекція деградації мережі з ескалацією за port_status |
| **Компонент** | Analyzer → Detector |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | RULE-NET-001; component=network; threshold=2 |

**Кроки:**
1. Створити 2 події `service_status` з `component="network"`, `value="packet_loss"`.
2. Додати подію `port_status` у межах 120 с.
3. Передати до `detect()`.

**Очікуваний результат:**
- `alerts[0].threat_type == "network_failure"`.
- `alerts[0].severity == "critical"` (ескалація через port_status).
- `alerts[0].confidence >= 0.95`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p1`

---

#### Тест-кейс 2.9 — Порожній список подій

| Поле | Значення |
|------|----------|
| **ID** | 2.9 |
| **Назва** | Негативний тест: детектор з порожнім вхідним списком |
| **Компонент** | Analyzer → Detector |
| **Тип** | unit |
| **Пріоритет** | P2 |
| **Передумови** | Будь-який валідний rules_cfg |

**Кроки:**
1. Передати `detect([], rules_cfg)`.

**Очікуваний результат:**
- Функція повертає порожній список `[]` без виключень.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p2`

---

#### Тест-кейс 2.10 — Відключене правило не продукує алертів

| Поле | Значення |
|------|----------|
| **ID** | 2.10 |
| **Назва** | Деактивоване правило ігнорується детектором |
| **Компонент** | Analyzer → Detector |
| **Тип** | unit |
| **Пріоритет** | P2 |
| **Передумови** | RULE-BF-001 з `enabled: false` |

**Кроки:**
1. Встановити `enabled: false` в конфігурації RULE-BF-001.
2. Передати 10 подій `auth_failure`.
3. Викликати `detect()`.

**Очікуваний результат:**
- `len(alerts) == 0`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p2`

---

### 3. Модуль Analyzer — Correlator (кореляція)

---

#### Тест-кейс 3.1 — Кореляція одного алерту в інцидент

| Поле | Значення |
|------|----------|
| **ID** | 3.1 |
| **Назва** | Одиночний алерт → один інцидент |
| **Компонент** | Analyzer → Correlator |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | Один алерт `credential_attack` |

**Кроки:**
1. Створити один Alert з `threat_type="credential_attack"`, `severity="high"`.
2. Викликати `correlate([alert], "baseline")`.

**Очікуваний результат:**
- `len(incidents) == 1`.
- `incidents[0].threat_type == "credential_attack"`.
- `incidents[0].mttd_sec > 0` і `incidents[0].mttr_sec > 0`.
- `incidents[0].impact_score` знаходиться в діапазоні `(0.0, 1.0]`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p1`

---

#### Тест-кейс 3.2 — Групування алертів з однаковим correlation_id

| Поле | Значення |
|------|----------|
| **ID** | 3.2 |
| **Назва** | Два алерти з однаковим COR-ID об'єднуються в один інцидент |
| **Компонент** | Analyzer → Correlator |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | Два алерти з `event_ids="COR-001"` |

**Кроки:**
1. Створити два Alert з `event_ids="COR-001;COR-002"` і `event_ids="COR-001;COR-003"`.
2. Викликати `correlate(alerts, "baseline")`.

**Очікуваний результат:**
- `len(incidents) == 1` (обидва згруповані за `COR-001`).
- `incidents[0].event_count` = сума `event_count` обох алертів.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p1`

---

#### Тест-кейс 3.3 — Різні threat_type → окремі інциденти

| Поле | Значення |
|------|----------|
| **ID** | 3.3 |
| **Назва** | Алерти різних типів загроз не об'єднуються |
| **Компонент** | Analyzer → Correlator |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | Два алерти без correlation_id, різні `threat_type` |

**Кроки:**
1. Створити Alert1 (`credential_attack`, `component="auth"`) і Alert2 (`availability_attack`, `component="api"`).
2. Викликати `correlate(alerts, "baseline")`.

**Очікуваний результат:**
- `len(incidents) == 2`.
- Перший інцидент — `credential_attack`, другий — `availability_attack`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p1`

---

#### Тест-кейс 3.4 — Максимізація severity при злитті алертів

| Поле | Значення |
|------|----------|
| **ID** | 3.4 |
| **Назва** | При злитті алертів зберігається максимальна severity |
| **Компонент** | Analyzer → Correlator |
| **Тип** | unit |
| **Пріоритет** | P2 |
| **Передумови** | Два алерти з різною severity в одному COR-групі |

**Кроки:**
1. Створити Alert1 з `severity="high"`, `event_ids="COR-001"`.
2. Створити Alert2 з `severity="critical"`, `event_ids="COR-001"`.
3. Викликати `correlate()`.

**Очікуваний результат:**
- `incidents[0].severity == "critical"`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p2`

---

#### Тест-кейс 3.5 — Модифікатори політики впливають на MTTD/MTTR

| Поле | Значення |
|------|----------|
| **ID** | 3.5 |
| **Назва** | Standard policy → менший MTTD і MTTR порівняно з minimal |
| **Компонент** | Analyzer → Correlator |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | Один Alert `credential_attack` |

**Кроки:**
1. Викликати `correlate([alert], "minimal", policy_modifiers={"credential_attack": {"mttd_multiplier": 2.5, "mttr_multiplier": 3.0}})`.
2. Викликати `correlate([alert], "standard", policy_modifiers={"credential_attack": {"mttd_multiplier": 0.3, "mttr_multiplier": 0.4}})`.

**Очікуваний результат:**
- `minimal_inc.mttd_sec > standard_inc.mttd_sec`.
- `minimal_inc.mttr_sec > standard_inc.mttr_sec`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p1`

---

### 4. Модуль Analyzer — Policy Engine та Metrics

---

#### Тест-кейс 4.1 — Завантаження конфігурації політик

| Поле | Значення |
|------|----------|
| **ID** | 4.1 |
| **Назва** | Завантаження та перевірка трьох рівнів безпекових політик |
| **Компонент** | Analyzer → PolicyEngine |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | Файл `config/policies.yaml` присутній і валідний |

**Кроки:**
1. Викликати `load_policies("config")`.
2. Перевірити наявність усіх трьох рівнів.

**Очікуваний результат:**
- `"minimal"`, `"baseline"`, `"standard"` — присутні в `policies_cfg["policies"]`.
- Кожна політика містить секції `controls` і `modifiers`.
- `get_modifiers(policies_cfg, "standard")["credential_attack"]["mttd_multiplier"] < 1.0`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p1`

---

#### Тест-кейс 4.2 — Відсутня політика повертає порожні модифікатори

| Поле | Значення |
|------|----------|
| **ID** | 4.2 |
| **Назва** | Запит неіснуючої політики не падає, повертає порожній dict |
| **Компонент** | Analyzer → PolicyEngine |
| **Тип** | unit |
| **Пріоритет** | P2 |
| **Передумови** | Завантажений `policies_cfg` |

**Кроки:**
1. Викликати `get_modifiers(policies_cfg, "nonexistent_policy")`.

**Очікуваний результат:**
- Повернено `{}` без виключень.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p2`

---

#### Тест-кейс 4.3 — Обчислення метрик з нульовими інцидентами

| Поле | Значення |
|------|----------|
| **ID** | 4.3 |
| **Назва** | Нульова кількість інцидентів → availability = 100 % |
| **Компонент** | Analyzer → Metrics |
| **Тип** | unit |
| **Пріоритет** | P0 |
| **Передумови** | Горизонт аналізу 3600 с |

**Кроки:**
1. Викликати `compute([], "baseline", horizon_sec=3600)`.

**Очікуваний результат:**
- `metrics.availability_pct == 100.0`.
- `metrics.incidents_total == 0`.
- `metrics.mean_mttd_min == 0.0`.
- `metrics.mean_mttr_min == 0.0`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p0`

---

#### Тест-кейс 4.4 — Обчислення downtime та availability

| Поле | Значення |
|------|----------|
| **ID** | 4.4 |
| **Назва** | Downtime коректно обчислюється і availability < 100 % |
| **Компонент** | Analyzer → Metrics |
| **Тип** | unit |
| **Пріоритет** | P0 |
| **Передумови** | Один інцидент з `severity="high"`, `mttd_sec=30`, `mttr_sec=300`; horizon=3600 |

**Кроки:**
1. Створити один Incident з `severity="high"`, `mttd_sec=30`, `mttr_sec=300`.
2. Викликати `compute([incident], "baseline", horizon_sec=3600)`.

**Очікуваний результат:**
- `metrics.total_downtime_hr > 0`.
- `metrics.availability_pct < 100.0`.
- `metrics.availability_pct >= 0.0`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p0`

---

#### Тест-кейс 4.5 — Перекриваючі інтервали downtime об'єднуються

| Поле | Значення |
|------|----------|
| **ID** | 4.5 |
| **Назва** | Два інциденти, що перекриваються — downtime не подвоюється |
| **Компонент** | Analyzer → Metrics |
| **Тип** | unit |
| **Пріоритет** | P1 |
| **Передумови** | Два інциденти з `severity="critical"`, часові проміжки перекриваються |

**Кроки:**
1. Incident1: `detect_ts=T`, `recover_ts=T+200s`.
2. Incident2: `detect_ts=T+100s`, `recover_ts=T+300s`.
3. Викликати `compute([inc1, inc2], "baseline", horizon_sec=3600)`.

**Очікуваний результат:**
- `total_downtime = 300s`, а НЕ `400s` (інтервали злито).
- `availability_pct` відповідає `(1 - 300/3600) * 100 ≈ 91.67 %`.

**Маркери pytest:** `component_analyzer`, `type_unit`, `priority_p1`

---

#### Тест-кейс 4.6 — Порівняння ефективності політик

| Поле | Значення |
|------|----------|
| **ID** | 4.6 |
| **Назва** | Standard policy дає кращі метрики ніж minimal |
| **Компонент** | Analyzer → Metrics + PolicyEngine |
| **Тип** | integration |
| **Пріоритет** | P0 |
| **Передумови** | Однаковий набір інцидентів, різні модифікатори |

**Кроки:**
1. Обчислити `PolicyMetrics` для `"minimal"` (mttd_multiplier=2.5, mttr_multiplier=3.0).
2. Обчислити `PolicyMetrics` для `"standard"` (mttd_multiplier=0.3, mttr_multiplier=0.4).
3. Порівняти MTTD, MTTR, availability.

**Очікуваний результат:**
- `standard.mean_mttd_min < minimal.mean_mttd_min`.
- `standard.mean_mttr_min < minimal.mean_mttr_min`.
- `standard.availability_pct > minimal.availability_pct`.

**Маркери pytest:** `component_analyzer`, `type_integration`, `priority_p0`

---

### 5. Модуль API (REST endpoints)

---

#### Тест-кейс 5.1 — Health check endpoint

| Поле | Значення |
|------|----------|
| **ID** | 5.1 |
| **Назва** | `/api/health` повертає `{"status": "ok"}` |
| **Компонент** | API |
| **Тип** | smoke |
| **Пріоритет** | P0 |
| **Передумови** | FastAPI application ініціалізовано (TestClient) |

**Кроки:**
1. Виконати `GET /api/health`.

**Очікуваний результат:**
- HTTP 200.
- Тіло: `{"status": "ok"}`.

**Маркери pytest:** `component_api`, `type_smoke`, `priority_p0`

---

#### Тест-кейс 5.2 — Root endpoint повертає документацію URL

| Поле | Значення |
|------|----------|
| **ID** | 5.2 |
| **Назва** | `GET /` містить посилання на Swagger UI |
| **Компонент** | API |
| **Тип** | smoke |
| **Пріоритет** | P0 |
| **Передумови** | TestClient |

**Кроки:**
1. Виконати `GET /`.

**Очікуваний результат:**
- HTTP 200.
- `body["docs"] == "/api/docs"`.

**Маркери pytest:** `component_api`, `type_smoke`, `priority_p0`

---

#### Тест-кейс 5.3 — Отримання списку інцидентів (позитивний)

| Поле | Значення |
|------|----------|
| **ID** | 5.3 |
| **Назва** | `GET /api/incidents` повертає пагінований список із полями контракту |
| **Компонент** | API |
| **Тип** | api |
| **Пріоритет** | P0 |
| **Передумови** | Stub-провайдер із 2 інцидентами підключений до маршруту |

**Кроки:**
1. Виконати `GET /api/incidents?limit=10`.

**Очікуваний результат:**
- HTTP 200.
- `body["total"] == 2`.
- Кожен елемент містить поля: `incident_id`, `severity`, `component`, `mttd_sec`, `mttr_sec`, `details`.
- `details` є типом `dict`.

**Маркери pytest:** `component_api`, `type_api`, `priority_p0`

---

#### Тест-кейс 5.4 — Фільтрація інцидентів за severity

| Поле | Значення |
|------|----------|
| **ID** | 5.4 |
| **Назва** | Фільтр `?severity=critical` повертає тільки критичні інциденти |
| **Компонент** | API |
| **Тип** | api |
| **Пріоритет** | P1 |
| **Передумови** | 2 інциденти: один `high`, один `critical` |

**Кроки:**
1. Виконати `GET /api/incidents?severity=critical`.

**Очікуваний результат:**
- HTTP 200.
- `body["total"] == 1`.
- `body["items"][0]["incident_id"] == "INC-002"`.

**Маркери pytest:** `component_api`, `type_api`, `priority_p1`

---

#### Тест-кейс 5.5 — Невалідний параметр limit = 0 (негативний)

| Поле | Значення |
|------|----------|
| **ID** | 5.5 |
| **Назва** | `?limit=0` повертає HTTP 422 (помилка валідації) |
| **Компонент** | API |
| **Тип** | api |
| **Пріоритет** | P1 |
| **Передумови** | TestClient |

**Кроки:**
1. Виконати `GET /api/incidents?limit=0`.

**Очікуваний результат:**
- HTTP 422 Unprocessable Entity.

**Маркери pytest:** `component_api`, `type_api`, `priority_p1`

---

#### Тест-кейс 5.6 — Отримання стану компонентів

| Поле | Значення |
|------|----------|
| **ID** | 5.6 |
| **Назва** | `GET /api/state` повертає стан усіх компонентів |
| **Компонент** | API |
| **Тип** | api |
| **Пріоритет** | P0 |
| **Передумови** | Stub-провайдер з 2 компонентами (api: healthy, db: degraded) |

**Кроки:**
1. Виконати `GET /api/state`.

**Очікуваний результат:**
- HTTP 200.
- `body["components"]` містить 2 елементи.
- Компонент `api` має `status == "healthy"`.
- Компонент `db` має `status == "degraded"`.

**Маркери pytest:** `component_api`, `type_api`, `priority_p0`

---

#### Тест-кейс 5.7 — Стан конкретного компонента

| Поле | Значення |
|------|----------|
| **ID** | 5.7 |
| **Назва** | `GET /api/state/components/{id}` — знайдено і не знайдено |
| **Компонент** | API |
| **Тип** | api |
| **Пріоритет** | P1 |
| **Передумови** | Stub-провайдер |

**Кроки:**
1. Виконати `GET /api/state/components/api` → очікується HTTP 200.
2. Виконати `GET /api/state/components/unknown` → очікується HTTP 404.

**Очікуваний результат:**
- Крок 1: `body["status"] == "healthy"`.
- Крок 2: HTTP 404.

**Маркери pytest:** `component_api`, `type_api`, `priority_p1`

---

#### Тест-кейс 5.8 — Перевірка блокування актора

| Поле | Значення |
|------|----------|
| **ID** | 5.8 |
| **Назва** | `GET /api/state/actors/{actor}/blocked` повертає правильний статус |
| **Компонент** | API |
| **Тип** | api |
| **Пріоритет** | P1 |
| **Передумови** | Stub: actor `"attacker"` заблокований |

**Кроки:**
1. `GET /api/state/actors/attacker/blocked`.
2. `GET /api/state/actors/legit_user/blocked`.

**Очікуваний результат:**
- Крок 1: `body["blocked"] == true`.
- Крок 2: `body["blocked"] == false`.

**Маркери pytest:** `component_api`, `type_api`, `priority_p1`

---

#### Тест-кейс 5.9 — Endpoint метрик per-policy та overall

| Поле | Значення |
|------|----------|
| **ID** | 5.9 |
| **Назва** | `GET /api/metrics` та `GET /api/metrics/overall` повертають коректні структури |
| **Компонент** | API |
| **Тип** | api |
| **Пріоритет** | P0 |
| **Передумови** | Stub-провайдер із метриками |

**Кроки:**
1. `GET /api/metrics`.
2. `GET /api/metrics/overall`.

**Очікуваний результат:**
- Крок 1: `body["by_policy"]` — список; `body["overall"]["total_incidents"] == 2`.
- Крок 2: поля `avg_mttd_min`, `avg_mttr_min`, `avg_availability_pct` присутні.

**Маркери pytest:** `component_api`, `type_api`, `priority_p0`

---

#### Тест-кейс 5.10 — Відсутні out-файли не призводять до краша API

| Поле | Значення |
|------|----------|
| **ID** | 5.10 |
| **Назва** | `APIDataProvider` повертає safe defaults при відсутніх CSV |
| **Компонент** | API → DataProvider |
| **Тип** | resilience |
| **Пріоритет** | P1 |
| **Передумови** | Шляхи до файлів переналаштовані на неіснуючі (monkeypatch) |

**Кроки:**
1. Перенаправити `INCIDENTS_PATH`, `ACTIONS_PATH`, `RESULTS_PATH`, `STATE_PATH` на відсутні файли.
2. Викликати всі методи `APIDataProvider`.

**Очікуваний результат:**
- `get_incidents() == []`.
- `get_incident_count() == 0`.
- `get_actions() == []`.
- `get_action_summary()["total"] == 0`.
- `get_metrics() == []`.
- `get_state() == []`.
- Жодних виключень не виникло.

**Маркери pytest:** `component_api`, `type_resilience`, `priority_p1`

---

### 6. Інтеграційні тест-кейси — Closed-loop

---

#### Тест-кейс 6.1 — E2E: Brute-force → Alert → Incident → Metrics

| Поле | Значення |
|------|----------|
| **ID** | 6.1 |
| **Назва** | Повний пайплайн brute-force: Events → Detector → Correlator → Metrics |
| **Компонент** | Analyzer (pipeline) |
| **Тип** | e2e |
| **Пріоритет** | P0 |
| **Передумови** | RULE-BF-001 (threshold=5); policy `baseline` |

**Кроки:**
1. Згенерувати 10 подій `auth_failure` з IP `10.0.0.99`, інтервал 3 с.
2. `alerts = detect(events, rules_cfg)`.
3. `incidents = correlate(alerts, "baseline")`.
4. `metrics = compute(incidents, "baseline", horizon_sec=3600)`.

**Очікуваний результат:**
- `len(alerts) >= 1`.
- `alerts[0].threat_type == "credential_attack"`.
- `len(incidents) >= 1`.
- `incidents[0].mttd_sec > 0`.
- `metrics.incidents_total >= 1`.
- `metrics.incidents_by_threat["credential_attack"] >= 1`.

**Маркери pytest:** `component_analyzer`, `component_pipeline`, `type_e2e`, `priority_p0`

---

#### Тест-кейс 6.2 — E2E: DDoS → rate_limit → API стан

| Поле | Значення |
|------|----------|
| **ID** | 6.2 |
| **Назва** | DDoS на Gateway → enable_rate_limit відповідна дія |
| **Компонент** | Analyzer (pipeline) |
| **Тип** | e2e |
| **Пріоритет** | P0 |
| **Передумови** | RULE-DDOS-001; closed-loop mode; policy `baseline` |

**Кроки:**
1. Генерувати 15 подій `rate_exceeded` від `source="api-gw-01"`.
2. Запустити повний pipeline (detect → correlate → decision → actions).
3. Перевірити дії у `data/live/actions.jsonl`.

**Очікуваний результат:**
- Інцидент `availability_attack` детектовано.
- Відповідна дія `enable_rate_limit` (або `rate_limit_ip_range`) зафіксована.
- Компонент Gateway змінює стан на `rate_limited`.

**Маркери pytest:** `component_analyzer`, `component_pipeline`, `type_e2e`, `priority_p0`

---

#### Тест-кейс 6.3 — E2E: Auth credential attack → block_actor

| Поле | Значення |
|------|----------|
| **ID** | 6.3 |
| **Назва** | Атака на Auth → block_actor → /api/state/actors показує blocked=true |
| **Компонент** | Analyzer + API |
| **Тип** | e2e |
| **Пріоритет** | P0 |
| **Передумови** | Сервіс API запущено; RULE-BF-001 активний |

**Кроки:**
1. Згенерувати 5 `auth_failure` від `actor="attacker"`.
2. Запустити pipeline (detect → correlate → decision → state_store).
3. `GET /api/state/actors/attacker/blocked`.

**Очікуваний результат:**
- HTTP 200.
- `blocked == true`.

**Маркери pytest:** `component_analyzer`, `component_api`, `type_e2e`, `priority_p0`

---

#### Тест-кейс 6.4 — E2E: Database outage → backup_db → restore_db

| Поле | Значення |
|------|----------|
| **ID** | 6.4 |
| **Назва** | Відмова БД → послідовність backup_db → restore_db |
| **Компонент** | Analyzer + DB |
| **Тип** | e2e |
| **Пріоритет** | P0 |
| **Передумови** | RULE-OUT-001/002 активні; policy `standard` |

**Кроки:**
1. Генерувати подію `service_status` з `value="down"`, `source="db-primary"`.
2. Запустити decision engine.
3. Перевірити послідовність дій.

**Очікуваний результат:**
- Інцидент `outage` з `severity="critical"` зафіксовано.
- Дії `backup_db` та/або `restore_db` виконані.
- `GET /api/state/components/db` → `status` змінився (наприклад, на `restoring` → `healthy`).

**Маркери pytest:** `component_analyzer`, `component_db`, `type_e2e`, `priority_p0`

---

#### Тест-кейс 6.5 — E2E: Network failure → degrade_network

| Поле | Значення |
|------|----------|
| **ID** | 6.5 |
| **Назва** | Відмова мережі → автоматична деградація та ізоляція |
| **Компонент** | Analyzer + Network |
| **Тип** | e2e |
| **Пріоритет** | P1 |
| **Передумови** | RULE-NET-001 активний |

**Кроки:**
1. Генерувати 2 події `service_status` з `component="network"`, `value="packet_loss"`.
2. Запустити pipeline.
3. Перевірити дію `degrade_network` у `data/live/actions.jsonl`.

**Очікуваний результат:**
- Інцидент `network_failure` зафіксовано.
- Дія `degrade_network` (або `reset_network`) виконана.

**Маркери pytest:** `component_analyzer`, `component_pipeline`, `type_e2e`, `priority_p1`

---

#### Тест-кейс 6.6 — E2E: Змішані атаки — три threat types паралельно

| Поле | Значення |
|------|----------|
| **ID** | 6.6 |
| **Назва** | Одночасна brute-force + DDoS + telemetry spoof → окремі інциденти |
| **Компонент** | Analyzer (pipeline) |
| **Тип** | e2e |
| **Пріоритет** | P1 |
| **Передумови** | Всі три правила активні |

**Кроки:**
1. Сформувати набір: 6 `auth_failure` + 12 `rate_exceeded` + 4 аномальних `telemetry_read`.
2. Запустити `detect()` → `correlate()` → `compute()`.

**Очікуваний результат:**
- `len(alerts) >= 3` (мінімум один алерт на тип загрози).
- `metrics.incidents_by_threat` містить ключі `"credential_attack"`, `"availability_attack"`, `"integrity_attack"`.

**Маркери pytest:** `component_analyzer`, `component_pipeline`, `type_e2e`, `priority_p1`

---

#### Тест-кейс 6.7 — Порівняння трьох політик на однакових атаках

| Поле | Значення |
|------|----------|
| **ID** | 6.7 |
| **Назва** | minimal < baseline < standard за метриками ефективності захисту |
| **Компонент** | Analyzer (pipeline) + PolicyEngine |
| **Тип** | integration |
| **Пріоритет** | P0 |
| **Передумови** | Конфіг `config/policies.yaml` |

**Кроки:**
1. Виконати повний pipeline для однакового набору атак при кожній з трьох політик.
2. Зібрати `PolicyMetrics` для `minimal`, `baseline`, `standard`.

**Очікуваний результат:**
- `standard.mean_mttd_min ≤ baseline.mean_mttd_min ≤ minimal.mean_mttd_min`.
- `standard.mean_mttr_min ≤ baseline.mean_mttr_min ≤ minimal.mean_mttr_min`.
- `standard.availability_pct ≥ baseline.availability_pct ≥ minimal.availability_pct`.

**Маркери pytest:** `component_analyzer`, `component_pipeline`, `type_integration`, `priority_p0`

---

#### Тест-кейс 6.8 — Live JSONL-потік: запис та зчитування подій у реальному часі

| Поле | Значення |
|------|----------|
| **ID** | 6.8 |
| **Назва** | Events записуються до `data/live/events.jsonl`; analyzer зчитує новий батч |
| **Компонент** | Emulator + Analyzer (live mode) |
| **Тип** | integration |
| **Пріоритет** | P1 |
| **Передумови** | Тимчасовий JSONL-файл; `FileEventSource` у watch-режимі |

**Кроки:**
1. Записати 5 подій до JSONL-файлу через `FileEventSink`.
2. Ініціалізувати `FileEventSource` з прапором `watch=True`.
3. Зчитати партію; дочекатися обробки.

**Очікуваний результат:**
- Зчитано рівно 5 подій.
- Analyzer успішно обробляє батч (без виключень).

**Маркери pytest:** `component_analyzer`, `component_emulator`, `component_pipeline`, `type_integration`, `priority_p1`

---

### 7. Resilience та граничні умови

---

#### Тест-кейс 7.1 — Пошкоджений CSV-файл не зупиняє API

| Поле | Значення |
|------|----------|
| **ID** | 7.1 |
| **Назва** | Corrupted CSV → `APIDataProvider` повертає порожній список |
| **Компонент** | API → DataProvider |
| **Тип** | resilience |
| **Пріоритет** | P1 |
| **Передумови** | CSV-файли містять незакриті рядки |

**Кроки:**
1. Записати `'incident_id,policy\n"unterminated\n'` до incidents.csv.
2. Ініціалізувати `APIDataProvider`.
3. Викликати `get_incidents()`.

**Очікуваний результат:**
- `get_incidents() == []`.
- Жодних виключень; логується попередження.

**Маркери pytest:** `component_api`, `type_resilience`, `priority_p1`

---

#### Тест-кейс 7.2 — FileAdapter resilience: файл не існує при ініціалізації

| Поле | Значення |
|------|----------|
| **ID** | 7.2 |
| **Назва** | `FileEventSource` не падає при відсутньому файлі |
| **Компонент** | Adapters → FileEventSource |
| **Тип** | resilience |
| **Пріоритет** | P1 |
| **Передумови** | Шлях до неіснуючого файлу |

**Кроки:**
1. Ініціалізувати `FileEventSource("/nonexistent/path.jsonl")`.
2. Викликати `read_batch(limit=10)`.

**Очікуваний результат:**
- Повернено порожній список `[]`.
- Жодних виключень не виникло.

**Маркери pytest:** `component_adapters`, `type_resilience`, `priority_p1`

---

#### Тест-кейс 7.3 — Integration modes: dry-run не емітує дій назовні

| Поле | Значення |
|------|----------|
| **ID** | 7.3 |
| **Назва** | Режим dry-run — план дій формується, але не відправляється |
| **Компонент** | Analyzer (integration modes) |
| **Тип** | integration |
| **Пріоритет** | P1 |
| **Передумови** | Analyzer з `--integration-mode dry-run` |

**Кроки:**
1. Запустити analyzer у dry-run режимі з подіями brute-force.
2. Перевірити `data/live/actions.jsonl` та зовнішній ActionSink.

**Очікуваний результат:**
- `actions.jsonl` містить план дій (`planned`).
- Зовнішній ActionSink (мок) не викликався.

**Маркери pytest:** `component_analyzer`, `component_pipeline`, `component_shared`, `type_integration`, `priority_p1`

---

#### Тест-кейс 7.4 — Integration modes: shadow mode

| Поле | Значення |
|------|----------|
| **ID** | 7.4 |
| **Назва** | Shadow mode — дії записуються з позначкою shadow, без впливу на систему |
| **Компонент** | Analyzer (integration modes) |
| **Тип** | integration |
| **Пріоритет** | P2 |
| **Передумови** | Analyzer з `--integration-mode shadow` |

**Кроки:**
1. Запустити analyzer у shadow-режимі.
2. Перевірити журнал дій.

**Очікуваний результат:**
- Дії позначені як `shadow` або `emitted=false`.
- Стан системи не змінився.

**Маркери pytest:** `component_analyzer`, `component_pipeline`, `component_shared`, `type_integration`, `priority_p2`

---

### 8. Контрактні тест-кейси (схеми даних)

---

#### Тест-кейс 8.1 — Валідація контракту Event

| Поле | Значення |
|------|----------|
| **ID** | 8.1 |
| **Назва** | Об'єкт Event відповідає контракту v1 |
| **Компонент** | Contracts |
| **Тип** | contract |
| **Пріоритет** | P1 |
| **Передумови** | Клас `Event` з `src.contracts.event` |

**Кроки:**
1. Створити `Event` з мінімально необхідними полями.
2. Перевірити серіалізацію у JSON.
3. Десеріалізувати та звірити поля.

**Очікуваний результат:**
- Об'єкт успішно серіалізується і десеріалізується.
- Поля `timestamp`, `source`, `component`, `event` — непорожні.
- `timestamp` відповідає формату ISO-8601.

**Маркери pytest:** `component_contracts`, `type_contract`, `priority_p1`

---

#### Тест-кейс 8.2 — Валідація контракту Alert

| Поле | Значення |
|------|----------|
| **ID** | 8.2 |
| **Назва** | Alert має обов'язкові поля і коректний діапазон confidence |
| **Компонент** | Contracts |
| **Тип** | contract |
| **Пріоритет** | P1 |
| **Передумови** | Клас `Alert` з `src.contracts.alert` |

**Кроки:**
1. Створити Alert з усіма обов'язковими полями.
2. Перевірити `0.0 <= confidence <= 1.0`.

**Очікуваний результат:**
- Об'єкт успішно створено.
- `confidence` знаходиться в `[0.0, 1.0]`.

**Маркери pytest:** `component_contracts`, `type_contract`, `priority_p1`

---

#### Тест-кейс 8.3 — Валідація контракту Incident

| Поле | Значення |
|------|----------|
| **ID** | 8.3 |
| **Назва** | Incident має коректні часові поля та impact_score |
| **Компонент** | Contracts |
| **Тип** | contract |
| **Пріоритет** | P1 |
| **Передумови** | Клас `Incident` з `src.contracts.incident` |

**Кроки:**
1. Створити Incident з `mttd_sec=30`, `mttr_sec=120`, `impact_score=0.6`.
2. Перевірити поля.

**Очікуваний результат:**
- `start_ts < detect_ts < recover_ts` (хронологічний порядок).
- `0.0 < impact_score <= 1.0`.
- `mttd_sec > 0`, `mttr_sec > 0`.

**Маркери pytest:** `component_contracts`, `type_contract`, `priority_p1`

---

#### Тест-кейс 8.4 — Integration contract v1: повна round-trip серіалізація

| Поле | Значення |
|------|----------|
| **ID** | 8.4 |
| **Назва** | Серіалізація Event → JSON → десеріалізація зберігає всі поля |
| **Компонент** | Contracts + Shared |
| **Тип** | contract |
| **Пріоритет** | P1 |
| **Передумови** | `src.contracts.integration_contract_v1` |

**Кроки:**
1. Серіалізувати Event у JSON.
2. Десеріалізувати з JSON.
3. Порівняти поля вхідного та вихідного об'єктів.

**Очікуваний результат:**
- Усі поля збережено без змін.
- Enum-поля коректно відновлюються.

**Маркери pytest:** `component_contracts`, `component_shared`, `type_contract`, `priority_p1`

---

### Зведена таблиця тест-кейсів

| ID | Назва (скорочено) | Компонент | Тип | Пріоритет |
|----|-------------------|-----------|-----|-----------|
| 1.1 | Фонові події emulator | Emulator | unit | P1 |
| 1.2 | Brute-force scenario | Emulator | unit | P1 |
| 1.3 | DDoS scenario | Emulator | unit | P1 |
| 1.4 | Telemetry spoof scenario | Emulator | unit | P1 |
| 1.5 | Unauthorized cmd scenario | Emulator | unit | P1 |
| 1.6 | Network failure scenario | Emulator | unit | P1 |
| 1.7 | FileEventSink/Source round-trip | Emulator+Adapters | integration | P1 |
| 2.1 | Детекція brute-force | Analyzer/Detector | unit | **P0** |
| 2.2 | Нижче порогу — без алерту | Analyzer/Detector | unit | P1 |
| 2.3 | Детекція DDoS | Analyzer/Detector | unit | **P0** |
| 2.4 | DDoS + service impact ескалація | Analyzer/Detector | unit | P1 |
| 2.5 | Детекція telemetry anomaly | Analyzer/Detector | unit | P1 |
| 2.6 | Несанкціонована команда | Analyzer/Detector | unit | **P0** |
| 2.7 | Outage severity override | Analyzer/Detector | unit | **P0** |
| 2.8 | Network failure + port ескалація | Analyzer/Detector | unit | P1 |
| 2.9 | Порожній список подій | Analyzer/Detector | unit | P2 |
| 2.10 | Відключене правило | Analyzer/Detector | unit | P2 |
| 3.1 | Один алерт → один інцидент | Analyzer/Correlator | unit | P1 |
| 3.2 | Групування за COR-ID | Analyzer/Correlator | unit | P1 |
| 3.3 | Різні threat_type — окремі | Analyzer/Correlator | unit | P1 |
| 3.4 | Максимізація severity | Analyzer/Correlator | unit | P2 |
| 3.5 | Модифікатори впливають на MTTD/MTTR | Analyzer/Correlator | unit | P1 |
| 4.1 | Завантаження policies.yaml | Analyzer/PolicyEngine | unit | P1 |
| 4.2 | Відсутня політика → порожній dict | Analyzer/PolicyEngine | unit | P2 |
| 4.3 | 0 інцидентів → 100% availability | Analyzer/Metrics | unit | **P0** |
| 4.4 | Downtime та availability | Analyzer/Metrics | unit | **P0** |
| 4.5 | Перекриваючі інтервали downtime | Analyzer/Metrics | unit | P1 |
| 4.6 | Порівняння політик | Analyzer/Metrics+PE | integration | **P0** |
| 5.1 | `/api/health` | API | smoke | **P0** |
| 5.2 | `GET /` → docs URL | API | smoke | **P0** |
| 5.3 | `GET /api/incidents` контракт | API | api | **P0** |
| 5.4 | Фільтр severity=critical | API | api | P1 |
| 5.5 | limit=0 → 422 | API | api | P1 |
| 5.6 | `GET /api/state` | API | api | **P0** |
| 5.7 | Стан конкретного компонента | API | api | P1 |
| 5.8 | Блокування актора | API | api | P1 |
| 5.9 | Метрики per-policy та overall | API | api | **P0** |
| 5.10 | Відсутні CSV → safe defaults | API/DataProvider | resilience | P1 |
| 6.1 | E2E brute-force pipeline | Analyzer/Pipeline | e2e | **P0** |
| 6.2 | E2E DDoS → rate_limit | Analyzer/Pipeline | e2e | **P0** |
| 6.3 | E2E Auth → block_actor | Analyzer+API | e2e | **P0** |
| 6.4 | E2E DB outage → backup/restore | Analyzer+DB | e2e | **P0** |
| 6.5 | E2E Network failure → degrade | Analyzer/Pipeline | e2e | P1 |
| 6.6 | E2E Mixed attacks | Analyzer/Pipeline | e2e | P1 |
| 6.7 | Порівняння 3 політик E2E | Analyzer/Pipeline | integration | **P0** |
| 6.8 | Live JSONL round-trip | Emulator+Analyzer | integration | P1 |
| 7.1 | Corrupted CSV → порожній список | API | resilience | P1 |
| 7.2 | FileSource — відсутній файл | Adapters | resilience | P1 |
| 7.3 | dry-run mode | Analyzer | integration | P1 |
| 7.4 | shadow mode | Analyzer | integration | P2 |
| 8.1 | Event contract | Contracts | contract | P1 |
| 8.2 | Alert contract | Contracts | contract | P1 |
| 8.3 | Incident contract | Contracts | contract | P1 |
| 8.4 | Round-trip серіалізація | Contracts+Shared | contract | P1 |

---

### Покриття за pytest-маркерами

```bash
# Критичні (P0) — обов'язковий запуск перед прийомом ПЗ
pytest -m "priority_p0"

# Smoke-набір CI (без зовнішніх залежностей)
pytest -m "type_smoke"

# Компонент Analyzer
pytest -m "component_analyzer"

# API тести
pytest -m "component_api"

# E2E / інтеграція
pytest -m "type_e2e or type_integration"

# Resilience
pytest -m "type_resilience"

# Без повільних зовнішніх тестів
pytest -m "not external and not slow"
```
