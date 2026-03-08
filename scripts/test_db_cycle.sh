#!/bin/bash
# test_db_cycle.sh -- Test DB backup/corrupt/restore cycle
#
# Usage:
#   ./scripts/test_db_cycle.sh
#
# Prerequisites:
#   - docker compose --profile live_direct up --build (running)
#   - PostgreSQL container is healthy

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}=== SmartEnergy DB Backup/Corrupt/Restore Test ===${NC}"
echo ""

# Check if postgres container is running
if ! docker ps --format '{{.Names}}' | grep -q 'smartenergy-postgres'; then
    echo -e "${RED}Error: smartenergy-postgres container is not running${NC}"
    echo "Run: docker compose --profile live_direct up --build"
    exit 1
fi

# Helper functions
run_psql() {
    docker exec smartenergy-postgres psql -U smartenergy -d smartenergy -t -c "$1" 2>/dev/null | tr -d ' '
}

emit_action() {
    local action="$1"
    local params="$2"
    local action_id="ACT-test-$(date +%s)"
    local ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local json="{\"action_id\":\"${action_id}\",\"ts_utc\":\"${ts}\",\"action\":\"${action}\",\"target_component\":\"db\",\"target_id\":\"\",\"params\":${params},\"reason\":\"test\",\"correlation_id\":\"test-$(date +%s)\",\"status\":\"pending\"}"
    echo "$json" >> data/live/actions.jsonl
    echo "$action_id"
}

echo -e "${YELLOW}Step 1: Check initial state${NC}"
INITIAL_MARKER=$(run_psql "SELECT marker FROM integrity_check LIMIT 1;")
INITIAL_COUNT=$(run_psql "SELECT COUNT(*) FROM telemetry;")
echo "  integrity_check marker: $INITIAL_MARKER"
echo "  telemetry row count: $INITIAL_COUNT"

if [ "$INITIAL_MARKER" != "healthy" ]; then
    echo -e "${YELLOW}  Warning: DB not in healthy state, attempting recovery...${NC}"
fi

echo ""
echo -e "${YELLOW}Step 2: Trigger backup_db action${NC}"
BACKUP_ID=$(emit_action "backup_db" '{"name":"test_backup"}')
echo "  emitted action_id: $BACKUP_ID"
sleep 3

# Wait for backup file
echo "  waiting for backup..."
for i in {1..10}; do
    if ls backups/test_backup.sql 2>/dev/null; then
        echo -e "  ${GREEN}backup file created${NC}"
        break
    fi
    sleep 1
done

BACKUP_COUNT=$(ls -1 backups/snapshot_*.sql 2>/dev/null | wc -l | tr -d ' ')
echo "  total snapshots: $BACKUP_COUNT"

echo ""
echo -e "${YELLOW}Step 3: Trigger corrupt_db action${NC}"
CORRUPT_ID=$(emit_action "corrupt_db" '{}')
echo "  emitted action_id: $CORRUPT_ID"
sleep 2

CORRUPTED_MARKER=$(run_psql "SELECT marker FROM integrity_check LIMIT 1;")
echo "  integrity_check marker after corruption: $CORRUPTED_MARKER"

if [ "$CORRUPTED_MARKER" = "CORRUPTED" ]; then
    echo -e "  ${GREEN}Corruption applied successfully${NC}"
else
    echo -e "  ${RED}Corruption failed or not detected${NC}"
fi

# Check for corruption event in events.jsonl
if grep -q "db_corruption_detected" data/live/events.jsonl 2>/dev/null; then
    echo -e "  ${GREEN}db_corruption_detected event found${NC}"
else
    echo -e "  ${YELLOW}db_corruption_detected event not found in events.jsonl${NC}"
fi

echo ""
echo -e "${YELLOW}Step 4: Trigger restore_db action${NC}"
RESTORE_ID=$(emit_action "restore_db" '{"snapshot":"latest"}')
echo "  emitted action_id: $RESTORE_ID"
echo "  waiting for restore..."
sleep 5

RESTORED_MARKER=$(run_psql "SELECT marker FROM integrity_check LIMIT 1;")
RESTORED_COUNT=$(run_psql "SELECT COUNT(*) FROM telemetry;")
echo "  integrity_check marker after restore: $RESTORED_MARKER"
echo "  telemetry row count after restore: $RESTORED_COUNT"

if [ "$RESTORED_MARKER" = "healthy" ]; then
    echo -e "  ${GREEN}Restore successful - marker is healthy${NC}"
else
    echo -e "  ${RED}Restore failed - marker is still: $RESTORED_MARKER${NC}"
fi

# Check for restore events
if grep -q "restore_completed" data/live/events.jsonl 2>/dev/null; then
    echo -e "  ${GREEN}restore_completed event found${NC}"
elif grep -q "restore_failed" data/live/events.jsonl 2>/dev/null; then
    echo -e "  ${RED}restore_failed event found${NC}"
fi

echo ""
echo -e "${YELLOW}Step 5: Verify ACKs in actions_applied.jsonl${NC}"
ACK_COUNT=$(grep -c '"target_component":"db"' data/live/actions_applied.jsonl 2>/dev/null || echo "0")
echo "  DB ACKs found: $ACK_COUNT"

if [ "$ACK_COUNT" -gt "0" ]; then
    echo "  Latest ACKs:"
    tail -5 data/live/actions_applied.jsonl 2>/dev/null | grep '"target_component":"db"' | head -3
fi

echo ""
echo -e "${BLUE}=== Test Summary ===${NC}"
echo "  Initial marker: $INITIAL_MARKER"
echo "  After corruption: $CORRUPTED_MARKER"
echo "  After restore: $RESTORED_MARKER"
echo "  Initial rows: $INITIAL_COUNT"
echo "  Final rows: $RESTORED_COUNT"

if [ "$RESTORED_MARKER" = "healthy" ]; then
    echo -e "${GREEN}=== DB CYCLE TEST PASSED ===${NC}"
    exit 0
else
    echo -e "${RED}=== DB CYCLE TEST FAILED ===${NC}"
    exit 1
fi
