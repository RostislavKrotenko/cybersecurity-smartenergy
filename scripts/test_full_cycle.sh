#!/bin/bash
# test_full_cycle.sh -- Full infrastructure test (DB + Network)
#
# Usage:
#   ./scripts/test_full_cycle.sh
#
# Prerequisites:
#   - docker compose --profile live_direct up --build (running)

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}   SmartEnergy Full Infrastructure Test${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! docker ps --format '{{.Names}}' | grep -q 'smartenergy-postgres'; then
    echo -e "${RED}Error: smartenergy-postgres container is not running${NC}"
    echo "Run: docker compose --profile live_direct up --build"
    exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q 'smartenergy-network-sim'; then
    echo -e "${RED}Error: smartenergy-network-sim container is not running${NC}"
    echo "Run: docker compose --profile live_direct up --build"
    exit 1
fi

echo -e "${GREEN}All containers running${NC}"
echo ""

# Ensure data directories exist
mkdir -p data/live

# Run DB test
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}   Part 1: Database Backup/Corrupt/Restore Cycle${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

DB_RESULT=0
if bash "$SCRIPT_DIR/test_db_cycle.sh"; then
    echo -e "${GREEN}DB test passed${NC}"
else
    echo -e "${RED}DB test failed${NC}"
    DB_RESULT=1
fi

echo ""

# Run Network test
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}   Part 2: Network Degrade/Reset Cycle${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

NET_RESULT=0
if bash "$SCRIPT_DIR/test_network_cycle.sh"; then
    echo -e "${GREEN}Network test passed${NC}"
else
    echo -e "${RED}Network test failed${NC}"
    NET_RESULT=1
fi

echo ""

# Summary
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}   Final Summary${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

if [ "$DB_RESULT" -eq 0 ]; then
    echo -e "  Database cycle:  ${GREEN}PASSED${NC}"
else
    echo -e "  Database cycle:  ${RED}FAILED${NC}"
fi

if [ "$NET_RESULT" -eq 0 ]; then
    echo -e "  Network cycle:   ${GREEN}PASSED${NC}"
else
    echo -e "  Network cycle:   ${RED}FAILED${NC}"
fi

echo ""

# File statistics
echo -e "${YELLOW}File statistics:${NC}"
echo "  events.jsonl lines: $(wc -l < data/live/events.jsonl 2>/dev/null || echo 0)"
echo "  actions.jsonl lines: $(wc -l < data/live/actions.jsonl 2>/dev/null || echo 0)"
echo "  actions_applied.jsonl lines: $(wc -l < data/live/actions_applied.jsonl 2>/dev/null || echo 0)"
echo "  backups count: $(ls -1 backups/snapshot_*.sql 2>/dev/null | wc -l || echo 0)"

echo ""

if [ "$DB_RESULT" -eq 0 ] && [ "$NET_RESULT" -eq 0 ]; then
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}   ALL TESTS PASSED${NC}"
    echo -e "${GREEN}============================================================${NC}"
    exit 0
else
    echo -e "${RED}============================================================${NC}"
    echo -e "${RED}   SOME TESTS FAILED${NC}"
    echo -e "${RED}============================================================${NC}"
    exit 1
fi
