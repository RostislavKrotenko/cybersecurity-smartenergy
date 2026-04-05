# Пакет готовності інтеграції SmartEnergy (v1)

Цей документ визначає, що саме має бути підготовлено з нашого боку до підключення будь-якої реальної production-системи SmartEnergy.

## 1. Контракт інтеграції v1

Версія контракту: `v1.0.0`

Еталонна реалізація:
- `src/contracts/integration_contract_v1.py`

Payload-моделі:
- Event (вхід): timestamp, source, component, event, key, value, severity, correlation_id
- Action (вихід): action_id, ts_utc, action, target_component, correlation_id, status, params
- ActionAck (зворотний зв'язок): action_id, correlation_id, target_component, action, applied_ts_utc, result

Правила валідації:
- Таймстампи в форматі ISO-8601 UTC є обов'язковими для Event.timestamp, Action.ts_utc, ActionAck.applied_ts_utc.
- Значення severity має бути одним із: low, medium, high, critical.
- Значення action має належати підтримуваному переліку playbook/enum.
- Значення ACK.result має бути `success` або `failed`.
- Обов'язкові рядкові поля не можуть бути порожніми.

## 2. Базовий сертифікаційний набір тестів адаптера

Мета: будь-яка майбутня реалізація адаптера має проходити однакові перевірки сумісності.

Мінімальне покриття:
- життєвий цикл EventSource і робота з offset
- контракт емісії ActionSink
- курсорне читання ACK у ActionFeedback
- сумісність StateProvider

Еталонні тести:
- `tests/test_adapter_certification.py`

## 3. Стандарт надійності

Еталонна реалізація:
- `src/shared/reliability.py`

Обов'язкові механізми:
- retry-політика для емісії дій
- timeout-політика для емісії дій
- інжекція idempotency key (`params.idempotency_key`)
- дедуплікація ACK у циклі analyzer

Параметри через env:
- `SMARTENERGY_ACTION_EMIT_MAX_RETRIES`
- `SMARTENERGY_ACTION_RETRY_INITIAL_SEC`
- `SMARTENERGY_ACTION_RETRY_MULTIPLIER`
- `SMARTENERGY_ACTION_RETRY_MAX_BACKOFF_SEC`
- `SMARTENERGY_ACTION_EMIT_TIMEOUT_SEC`
- `SMARTENERGY_ACK_DEDUP_MAX_ENTRIES`

## 4. Безпечні режими rollout

Реалізовані режими:
- `dry-run`: detect/correlate/decide, але без емісії в зовнішній sink
- `shadow`: як dry-run, але з окремим shadow-виводом плану дій
- `active`: емісія дій у ActionSink з retry/timeout/idempotency контролями

CLI-параметри:
- `--integration-mode {dry-run,shadow,active}`
- `--shadow-actions-path <path>`

Рекомендована обов'язкова послідовність rollout:
1. dry-run
2. shadow
3. active

## 5. Операційний чекліст (до Go-Live)

Чекліст:
- Увімкнене структуроване логування для analyzer/emulator/api
- Наявний audit trail для всіх емітованих дій та отриманих ACK
- Налаштовані алерти на збої емісії дій та затримки ACK
- Визначений fallback при недоступності зовнішнього ActionSink
- Параметри retry/timeout погоджені з операційною командою
- Призначений on-call власник інтеграції
- Процедура rollback задокументована і перевірена

## 6. Критерії приймання інтеграції

Мінімальні acceptance-пороги:
- ACK latency p95 <= 15s
- ACK latency p99 <= 30s
- Action emission failure rate <= 1% за 24 години
- Відсутність побічних ефектів від дубльованих ACK після дедуплікації
- Стабільний throughput >= 50 actions/min без зростання backlog
- Нуль помилок контрактної валідації на вибірці production-трафіку (вікно 24 години)

Якщо будь-який поріг порушено, production-активація блокується до підтвердження виправлень.
