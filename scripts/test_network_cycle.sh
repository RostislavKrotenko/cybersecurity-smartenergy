#!/bin/bash
# test_network_cycle.sh -- Test Network degrade/reset cycle
#
# Usage:
#   ./scripts/test_network_cycle.sh
#
# Prerequisites:
#   - docker compose --profile live_direct up --build (running)
#   - network-sim container is healthy

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}=== SmartEnergy Network Degrade/Reset Test ===${NC}"
echo ""

# Check if network-sim container is running
if ! docker ps --format '{{.Names}}' | grep -q 'smartenergy-network-sim'; then
    echo -e "${RED}Error: smartenergy-network-sim container is not running${NC}"
    echo "Run: docker compose --profile live_direct up --build"
    exit 1
fi

# Helper functions
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

echo -e "${YELLOW}Step 1: Check initial network state${NC}"
INITIAL_STATUS=$(get_network_status)
echo "  Network status: $INITIAL_STATUS"

echo ""
echo -e "${YELLOW}Step 2: Test HTTP API - POST /degrade${NC}"
DEGRADE_RESULT=$(curl -s -X POST http://localhost:8090/degrade \
    -H "Content-Type: application/json" \
    -d '{"latency_ms":150,"drop_rate":0.1,"ttl_sec":30}' 2>/dev/null)
echo "  Result: $DEGRADE_RESULT"
sleep 1

DEGRADED_STATUS=$(get_network_status)
echo "  Network status after HTTP degrade: $DEGRADED_STATUS"

# Check for network_degraded event
if grep -q "network_degraded" data/live/events.jsonl 2>/dev/null; then
    echo -e "  ${GREEN}network_degraded event found${NC}"
else
    echo -e "  ${YELLOW}network_degraded event not found yet${NC}"
fi

echo ""
echo -e "${YELLOW}Step 3: Test HTTP API - POST /reset${NC}"
RESET_RESULT=$(curl -s -X POST http://localhost:8090/reset \
    -H "Content-Type: application/json" \
    -d '{}' 2>/dev/null)
echo "  Result: $RESET_RESULT"
sleep 1

RESET_STATUS=$(get_network_status)
echo "  Network status after HTTP reset: $RESET_STATUS"

# Check for network_reset_applied event
if grep -q "network_reset_applied" data/live/events.jsonl 2>/dev/null; then
    echo -e "  ${GREEN}network_reset_applied event found${NC}"
else
    echo -e "  ${YELLOW}network_reset_applied event not found yet${NC}"
fi

echo ""
echo -e "${YELLOW}Step 4: Test action listener - emit degrade_network action${NC}"
DEGRADE_ID=$(emit_action "degrade_network" '{"latency_ms":300,"drop_rate":0.2,"ttl_sec":60}')
echo "  emitted action_id: $DEGRADE_ID"
sleep 3

ACTION_DEGRADED_STATUS=$(get_network_status)
echo "  Network status after action: $ACTION_DEGRADED_STATUS"

# Verify ACK was written
if grep -q "$DEGRADE_ID" data/live/actions_applied.jsonl 2>/dev/null; then
    echo -e "  ${GREEN}ACK found for action $DEGRADE_ID${NC}"
    grep "$DEGRADE_ID" data/live/actions_applied.jsonl | tail -1
else
    echo -e "  ${YELLOW}ACK not found yet for action $DEGRADE_ID${NC}"
fi

echo ""
echo -e "${YELLOW}Step 5: Test action listener - emit reset_network action${NC}"
RESET_ID=$(emit_action "reset_network" '{}')
echo "  emitted action_id: $RESET_ID"
sleep 3

FINAL_STATUS=$(get_network_status)
echo "  Network status after reset action: $FINAL_STATUS"

# Verify ACK was written
if grep -q "$RESET_ID" data/live/actions_applied.jsonl 2>/dev/null; then
    echo -e "  ${GREEN}ACK found for action $RESET_ID${NC}"
    grep "$RESET_ID" data/live/actions_applied.jsonl | tail -1
else
    echo -e "  ${YELLOW}ACK not found yet for action $RESET_ID${NC}"
fi

echo ""
echo -e "${YELLOW}Step 6: Verify events in events.jsonl${NC}"
DEGRADE_EVENTS=$(grep -c "network_degraded" data/live/events.jsonl 2>/dev/null || echo "0")
RESET_EVENTS=$(grep -c "network_reset_applied" data/live/events.jsonl 2>/dev/null || echo "0")
echo "  network_degraded events: $DEGRADE_EVENTS"
echo "  network_reset_applied events: $RESET_EVENTS"

echo ""
echo -e "${YELLOW}Step 7: Verify ACKs in actions_applied.jsonl${NC}"
ACK_COUNT=$(grep -c '"target_component":"network"' data/live/actions_applied.jsonl 2>/dev/null || echo "0")
echo "  Network ACKs found: $ACK_COUNT"

if [ "$ACK_COUNT" -gt "0" ]; then
    echo "  Latest ACKs:"
    grep '"target_component":"network"' data/live/actions_applied.jsonl 2>/dev/null | tail -3
fi

echo ""
echo -e "${BLUE}=== Test Summary ===${NC}"
echo "  Initial status: $INITIAL_STATUS"
echo "  Final status: $FINAL_STATUS"
echo "  Degrade events: $DEGRADE_EVENTS"
echo "  Reset events: $RESET_EVENTS"
echo "  Network ACKs: $ACK_COUNT"

# Check if final status is healthy
if echo "$FINAL_STATUS" | grep -q '"latency_ms":0'; then
    echo -e "${GREEN}=== NETWORK CYCLE TEST PASSED ===${NC}"
    exit 0
else
    echo -e "${RED}=== NETWORK CYCLE TEST FAILED ===${NC}"
    exit 1
fi
