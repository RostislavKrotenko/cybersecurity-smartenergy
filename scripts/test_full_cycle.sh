#!/bin/bash
# test_full_cycle.sh -- повний інфраструктурний тест (БД + мережа)
#
# Використання:
#   ./scripts/test_full_cycle.sh
#
# Передумови:
#   - docker compose --profile live_direct up --build (запущено)

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}   Повний інфраструктурний тест SmartEnergy${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

# Перевірка передумов.
echo -e "${YELLOW}Перевірка передумов...${NC}"

if ! docker ps --format '{{.Names}}' | grep -q 'smartenergy-postgres'; then
    echo -e "${RED}Помилка: контейнер smartenergy-postgres не запущений${NC}"
    echo "Запустіть: docker compose --profile live_direct up --build"
    exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q 'smartenergy-network-sim'; then
    echo -e "${RED}Помилка: контейнер smartenergy-network-sim не запущений${NC}"
    echo "Запустіть: docker compose --profile live_direct up --build"
    exit 1
fi

echo -e "${GREEN}Усі контейнери запущені${NC}"
echo ""

# Перевірка наявності директорій даних.
mkdir -p data/live

# Запуск тесту БД.
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}   Частина 1: цикл Database Backup/Corrupt/Restore${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

DB_RESULT=0
if bash "$SCRIPT_DIR/test_db_cycle.sh"; then
    echo -e "${GREEN}Тест БД пройдено${NC}"
else
    echo -e "${RED}Тест БД провалено${NC}"
    DB_RESULT=1
fi

echo ""

# Запуск тесту мережі.
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}   Частина 2: цикл Network Degrade/Reset${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

NET_RESULT=0
if bash "$SCRIPT_DIR/test_network_cycle.sh"; then
    echo -e "${GREEN}Тест мережі пройдено${NC}"
else
    echo -e "${RED}Тест мережі провалено${NC}"
    NET_RESULT=1
fi

echo ""

# Підсумок.
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}   Фінальний підсумок${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

if [ "$DB_RESULT" -eq 0 ]; then
    echo -e "  Цикл БД:      ${GREEN}ПРОЙДЕНО${NC}"
else
    echo -e "  Цикл БД:      ${RED}ПРОВАЛЕНО${NC}"
fi

if [ "$NET_RESULT" -eq 0 ]; then
    echo -e "  Цикл мережі:  ${GREEN}ПРОЙДЕНО${NC}"
else
    echo -e "  Цикл мережі:  ${RED}ПРОВАЛЕНО${NC}"
fi

echo ""

echo -e "${YELLOW}Статистика файлів:${NC}"
echo "  events.jsonl lines: $(wc -l < data/live/events.jsonl 2>/dev/null || echo 0)"
echo "  actions.jsonl lines: $(wc -l < data/live/actions.jsonl 2>/dev/null || echo 0)"
echo "  actions_applied.jsonl lines: $(wc -l < data/live/actions_applied.jsonl 2>/dev/null || echo 0)"
echo "  backups count: $(ls -1 backups/snapshot_*.sql 2>/dev/null | wc -l || echo 0)"

echo ""

if [ "$DB_RESULT" -eq 0 ] && [ "$NET_RESULT" -eq 0 ]; then
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}   УСІ ТЕСТИ ПРОЙДЕНО${NC}"
    echo -e "${GREEN}============================================================${NC}"
    exit 0
else
    echo -e "${RED}============================================================${NC}"
    echo -e "${RED}   ЧАСТИНУ ТЕСТІВ ПРОВАЛЕНО${NC}"
    echo -e "${RED}============================================================${NC}"
    exit 1
fi
