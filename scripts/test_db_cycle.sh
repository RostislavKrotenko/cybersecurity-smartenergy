#!/bin/bash
# test_db_cycle.sh -- тест циклу backup/corrupt/restore для БД
#
# Використання:
#   ./scripts/test_db_cycle.sh
#
# Передумови:
#   - docker compose --profile live_direct up --build (запущено)
#   - контейнер PostgreSQL у healthy-стані

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}=== Тест SmartEnergy DB Backup/Corrupt/Restore ===${NC}"
echo ""

# Перевірка, що контейнер postgres запущений.
if ! docker ps --format '{{.Names}}' | grep -q 'smartenergy-postgres'; then
    echo -e "${RED}Помилка: контейнер smartenergy-postgres не запущений${NC}"
    echo "Запустіть: docker compose --profile live_direct up --build"
    exit 1
fi

# Допоміжні функції.
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

echo -e "${YELLOW}Крок 1: перевірка початкового стану${NC}"
INITIAL_MARKER=$(run_psql "SELECT marker FROM integrity_check LIMIT 1;")
INITIAL_COUNT=$(run_psql "SELECT COUNT(*) FROM telemetry;")
echo "  marker integrity_check: $INITIAL_MARKER"
echo "  кількість рядків telemetry: $INITIAL_COUNT"

if [ "$INITIAL_MARKER" != "healthy" ]; then
    echo -e "${YELLOW}  Попередження: БД не в healthy-стані, пробуємо відновлення...${NC}"
fi

echo ""
echo -e "${YELLOW}Крок 2: запуск дії backup_db${NC}"
BACKUP_ID=$(emit_action "backup_db" '{"name":"test_backup"}')
echo "  створено action_id: $BACKUP_ID"
sleep 3

# Очікування backup-файла.
echo "  очікування backup..."
for i in {1..10}; do
    if ls backups/test_backup.sql 2>/dev/null; then
        echo -e "  ${GREEN}backup-файл створено${NC}"
        break
    fi
    sleep 1
done

BACKUP_COUNT=$(ls -1 backups/snapshot_*.sql 2>/dev/null | wc -l | tr -d ' ')
echo "  усього snapshot: $BACKUP_COUNT"

echo ""
echo -e "${YELLOW}Крок 3: запуск дії corrupt_db${NC}"
CORRUPT_ID=$(emit_action "corrupt_db" '{}')
echo "  створено action_id: $CORRUPT_ID"
sleep 2

CORRUPTED_MARKER=$(run_psql "SELECT marker FROM integrity_check LIMIT 1;")
echo "  marker integrity_check після пошкодження: $CORRUPTED_MARKER"

if [ "$CORRUPTED_MARKER" = "CORRUPTED" ]; then
    echo -e "  ${GREEN}Пошкодження застосовано успішно${NC}"
else
    echo -e "  ${RED}Пошкодження не виконано або не виявлено${NC}"
fi

# Перевірка події пошкодження в events.jsonl.
if grep -q "db_corruption_detected" data/live/events.jsonl 2>/dev/null; then
    echo -e "  ${GREEN}подію db_corruption_detected знайдено${NC}"
else
    echo -e "  ${YELLOW}подію db_corruption_detected не знайдено в events.jsonl${NC}"
fi

echo ""
echo -e "${YELLOW}Крок 4: запуск дії restore_db${NC}"
RESTORE_ID=$(emit_action "restore_db" '{"snapshot":"latest"}')
echo "  створено action_id: $RESTORE_ID"
echo "  очікування restore..."
sleep 5

RESTORED_MARKER=$(run_psql "SELECT marker FROM integrity_check LIMIT 1;")
RESTORED_COUNT=$(run_psql "SELECT COUNT(*) FROM telemetry;")
echo "  marker integrity_check після restore: $RESTORED_MARKER"
echo "  кількість рядків telemetry після restore: $RESTORED_COUNT"

if [ "$RESTORED_MARKER" = "healthy" ]; then
    echo -e "  ${GREEN}Restore успішний: marker healthy${NC}"
else
    echo -e "  ${RED}Restore провалено: marker досі $RESTORED_MARKER${NC}"
fi

# Перевірка restore-подій.
if grep -q "restore_completed" data/live/events.jsonl 2>/dev/null; then
    echo -e "  ${GREEN}подію restore_completed знайдено${NC}"
elif grep -q "restore_failed" data/live/events.jsonl 2>/dev/null; then
    echo -e "  ${RED}подію restore_failed знайдено${NC}"
fi

echo ""
echo -e "${YELLOW}Крок 5: перевірка ACK в actions_applied.jsonl${NC}"
ACK_COUNT=$(grep -c '"target_component":"db"' data/live/actions_applied.jsonl 2>/dev/null || echo "0")
echo "  ACK для DB знайдено: $ACK_COUNT"

if [ "$ACK_COUNT" -gt "0" ]; then
    echo "  Останні ACK:"
    tail -5 data/live/actions_applied.jsonl 2>/dev/null | grep '"target_component":"db"' | head -3
fi

echo ""
echo -e "${BLUE}=== Підсумок тесту ===${NC}"
echo "  Початковий marker: $INITIAL_MARKER"
echo "  Після пошкодження: $CORRUPTED_MARKER"
echo "  Після restore: $RESTORED_MARKER"
echo "  Початкові рядки: $INITIAL_COUNT"
echo "  Фінальні рядки: $RESTORED_COUNT"

if [ "$RESTORED_MARKER" = "healthy" ]; then
    echo -e "${GREEN}=== ТЕСТ ЦИКЛУ БД ПРОЙДЕНО ===${NC}"
    exit 0
else
    echo -e "${RED}=== ТЕСТ ЦИКЛУ БД ПРОВАЛЕНО ===${NC}"
    exit 1
fi
