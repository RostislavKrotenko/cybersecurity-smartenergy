#!/bin/bash
# test_network_cycle.sh -- тест циклу деградації/скидання мережі
#
# Використання:
#   ./scripts/test_network_cycle.sh
#
# Передумови:
#   - docker compose --profile live_direct up --build (запущено)
#   - контейнер network-sim у healthy-стані

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}=== Тест деградації/скидання мережі SmartEnergy ===${NC}"
echo ""

# Перевірка, що контейнер network-sim запущений.
if ! docker ps --format '{{.Names}}' | grep -q 'smartenergy-network-sim'; then
    echo -e "${RED}Помилка: контейнер smartenergy-network-sim не запущений${NC}"
    echo "Запустіть: docker compose --profile live_direct up --build"
    exit 1
fi

# Допоміжні функції.
get_network_status() {
    curl -s http://localhost:8090/status 2>/dev/null || echo '{"error":"not available"}'
}

emit_action() {
    local action="$1"
    local params="$2"
    local action_id="ACT-net-$(date +%s)"
    local ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local json="{\"action_id\":\"${action_id}\",\"ts_utc\":\"${ts}\",\"action\":\"${action}\",\"target_component\":\"network\",\"target_id\":\"\",\"params\":${params},\"reason\":\"test\",\"correlation_id\":\"test-$(date +%s)\",\"status\":\"pending\"}"
    echo "$json" >> data/live/actions.jsonl
    echo "$action_id"
}

echo -e "${YELLOW}Крок 1: перевірка початкового стану мережі${NC}"
INITIAL_STATUS=$(get_network_status)
echo "  Стан мережі: $INITIAL_STATUS"

echo ""
echo -e "${YELLOW}Крок 2: тест HTTP API - POST /degrade${NC}"
DEGRADE_RESULT=$(curl -s -X POST http://localhost:8090/degrade \
    -H "Content-Type: application/json" \
    -d '{"latency_ms":150,"drop_rate":0.1,"ttl_sec":30}' 2>/dev/null)
echo "  Результат: $DEGRADE_RESULT"
sleep 1

DEGRADED_STATUS=$(get_network_status)
echo "  Стан мережі після HTTP degrade: $DEGRADED_STATUS"

# Перевірка події network_degraded.
if grep -q "network_degraded" data/live/events.jsonl 2>/dev/null; then
    echo -e "  ${GREEN}подію network_degraded знайдено${NC}"
else
    echo -e "  ${YELLOW}подію network_degraded поки не знайдено${NC}"
fi

echo ""
echo -e "${YELLOW}Крок 3: тест HTTP API - POST /reset${NC}"
RESET_RESULT=$(curl -s -X POST http://localhost:8090/reset \
    -H "Content-Type: application/json" \
    -d '{}' 2>/dev/null)
echo "  Результат: $RESET_RESULT"
sleep 1

RESET_STATUS=$(get_network_status)
echo "  Стан мережі після HTTP reset: $RESET_STATUS"

# Перевірка події network_reset_applied.
if grep -q "network_reset_applied" data/live/events.jsonl 2>/dev/null; then
    echo -e "  ${GREEN}подію network_reset_applied знайдено${NC}"
else
    echo -e "  ${YELLOW}подію network_reset_applied поки не знайдено${NC}"
fi

echo ""
echo -e "${YELLOW}Крок 4: тест action listener - дія degrade_network${NC}"
DEGRADE_ID=$(emit_action "degrade_network" '{"latency_ms":300,"drop_rate":0.2,"ttl_sec":60}')
echo "  створено action_id: $DEGRADE_ID"
sleep 3

ACTION_DEGRADED_STATUS=$(get_network_status)
echo "  Стан мережі після дії: $ACTION_DEGRADED_STATUS"

# Перевірка запису ACK.
if grep -q "$DEGRADE_ID" data/live/actions_applied.jsonl 2>/dev/null; then
    echo -e "  ${GREEN}ACK знайдено для дії $DEGRADE_ID${NC}"
    grep "$DEGRADE_ID" data/live/actions_applied.jsonl | tail -1
else
    echo -e "  ${YELLOW}ACK для дії $DEGRADE_ID поки не знайдено${NC}"
fi

echo ""
echo -e "${YELLOW}Крок 5: тест action listener - дія reset_network${NC}"
RESET_ID=$(emit_action "reset_network" '{}')
echo "  створено action_id: $RESET_ID"
sleep 3

FINAL_STATUS=$(get_network_status)
echo "  Стан мережі після reset-дії: $FINAL_STATUS"

# Перевірка запису ACK.
if grep -q "$RESET_ID" data/live/actions_applied.jsonl 2>/dev/null; then
    echo -e "  ${GREEN}ACK знайдено для дії $RESET_ID${NC}"
    grep "$RESET_ID" data/live/actions_applied.jsonl | tail -1
else
    echo -e "  ${YELLOW}ACK для дії $RESET_ID поки не знайдено${NC}"
fi

echo ""
echo -e "${YELLOW}Крок 6: перевірка подій в events.jsonl${NC}"
DEGRADE_EVENTS=$(grep -c "network_degraded" data/live/events.jsonl 2>/dev/null || echo "0")
RESET_EVENTS=$(grep -c "network_reset_applied" data/live/events.jsonl 2>/dev/null || echo "0")
echo "  подій network_degraded: $DEGRADE_EVENTS"
echo "  подій network_reset_applied: $RESET_EVENTS"

echo ""
echo -e "${YELLOW}Крок 7: перевірка ACK в actions_applied.jsonl${NC}"
ACK_COUNT=$(grep -c '"target_component":"network"' data/live/actions_applied.jsonl 2>/dev/null || echo "0")
echo "  ACK для network знайдено: $ACK_COUNT"

if [ "$ACK_COUNT" -gt "0" ]; then
    echo "  Останні ACK:"
    grep '"target_component":"network"' data/live/actions_applied.jsonl 2>/dev/null | tail -3
fi

echo ""
echo -e "${BLUE}=== Підсумок тесту ===${NC}"
echo "  Початковий стан: $INITIAL_STATUS"
echo "  Фінальний стан: $FINAL_STATUS"
echo "  Події degrade: $DEGRADE_EVENTS"
echo "  Події reset: $RESET_EVENTS"
echo "  ACK network: $ACK_COUNT"

# Перевірка, що фінальний стан healthy.
if echo "$FINAL_STATUS" | grep -q '"latency_ms":0'; then
    echo -e "${GREEN}=== ТЕСТ ЦИКЛУ МЕРЕЖІ ПРОЙДЕНО ===${NC}"
    exit 0
else
    echo -e "${RED}=== ТЕСТ ЦИКЛУ МЕРЕЖІ ПРОВАЛЕНО ===${NC}"
    exit 1
fi
