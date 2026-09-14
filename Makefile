#  SmartEnergy Cyber-Resilience Analyzer — Makefile

SHELL   := /bin/bash
PYTHON  := .venv/bin/python
COMPOSE := docker compose

.DEFAULT_GOAL := help

# Директорії
DATA_DIR := data
OUT_DIR  := out
LOGS_DIR := logs

#   ЛОКАЛЬНИЙ ЗАПУСК (без Docker)

.PHONY: venv install generate analyze api demo-local demo-live clean lint help

venv:                          ## Створити virtual-env
	python3 -m venv .venv

install: venv                  ## Встановити Python-залежності та проєкт в editable-режимі
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e .

generate:                      ## Запустити емулятор → data/events.csv
	@mkdir -p $(DATA_DIR)
	$(PYTHON) -m src.emulator --seed 42 --out $(DATA_DIR)/events.csv --log-level INFO
	@echo "✓ Емулятор завершив роботу → $(DATA_DIR)/events.csv"

analyze:                       ## Запустити аналізатор → out/*
	@mkdir -p $(OUT_DIR)
	$(PYTHON) -m src.analyzer \
		--input $(DATA_DIR)/events.csv \
		--out-dir $(OUT_DIR) \
		--policies all \
		--horizon-days 1 \
		--log-level INFO
	@echo "✓ Аналізатор завершив роботу → $(OUT_DIR)/"

api:                           ## Запустити FastAPI сервер (localhost:8000)
	$(PYTHON) -m src.api --port 8000

demo-local: generate analyze api ## Повне локальне демо: generate → analyze → API

demo-live:                     ## Live-демо локально: emulator + analyzer + API з closed-loop ACK
	@echo "Запуск live-демо (Ctrl+C зупинить усі процеси)..."
	@rm -f $(DATA_DIR)/live/events.jsonl $(DATA_DIR)/live/actions.jsonl $(DATA_DIR)/live/actions_applied.jsonl
	@mkdir -p $(DATA_DIR)/live $(OUT_DIR) $(LOGS_DIR)/live
	@trap 'kill 0' INT; \
	$(PYTHON) -m src.emulator --live --live-interval-ms 500 --out $(DATA_DIR)/live/events.jsonl --raw-log-dir $(LOGS_DIR)/live --seed 42 --actions-path $(DATA_DIR)/live/actions.jsonl --applied-path $(DATA_DIR)/live/actions_applied.jsonl & \
	sleep 2 && \
	$(PYTHON) -m src.analyzer --input $(DATA_DIR)/live/events.jsonl --watch --poll-interval-ms 1000 --out-dir $(OUT_DIR) --policies all --actions-path $(DATA_DIR)/live/actions.jsonl --applied-path $(DATA_DIR)/live/actions_applied.jsonl & \
	sleep 1 && \
	SMARTENERGY_LIVE_MODE=1 $(PYTHON) -m src.api --port 8000

#   DOCKER

.PHONY: docker-build docker-live docker-api docker-down docker-clean

docker-build:                  ## Зібрати Docker-образ
	$(COMPOSE) --profile live build

docker-live:                   ## Live Docker: повний closed-loop з усіма сервісами
	@mkdir -p $(DATA_DIR)/live $(OUT_DIR) $(LOGS_DIR)/live
	$(COMPOSE) --profile live up --build

docker-api:                    ## Docker: лише окремий API сервер
	$(COMPOSE) --profile api up --build

docker-down:                   ## Зупинити всі контейнери
	$(COMPOSE) down --remove-orphans

docker-clean: docker-down      ## Зупинити контейнери та видалити images і volumes
	$(COMPOSE) down --rmi local --volumes --remove-orphans

#   FRONTEND (React)

.PHONY: frontend-install frontend-dev frontend-build

frontend-install:              ## Встановити frontend-залежності
	cd frontend && npm install

frontend-dev:                  ## Запустити frontend dev server (localhost:5173)
	cd frontend && npm run dev

frontend-build:                ## Зібрати frontend для production
	cd frontend && npm run build

#   ОБСЛУГОВУВАННЯ

clean:                         ## Видалити згенеровані артефакти
	rm -rf $(OUT_DIR)/*
	rm -f  $(DATA_DIR)/events.csv $(DATA_DIR)/_uploaded_events.csv
	@echo "✓ Очищено $(OUT_DIR)/ і $(DATA_DIR)/events.csv"

#   ТЕСТУВАННЯ ТА ЯКІСТЬ

.PHONY: test test-slow test-cov lint format

test:                          ## Запустити швидкі тести без seed repro
	$(PYTHON) -m pytest tests/ -v --tb=short

test-slow:                     ## Запустити всі тести, включно з відтворенням seed
	$(PYTHON) -m pytest tests/ -v --tb=short -m slow

test-cov:                      ## Запустити тести зі звітом покриття
	$(PYTHON) -m pytest tests/ -v --tb=short --cov=src --cov-report=term-missing

lint:                          ## Запустити Ruff linter
	$(PYTHON) -m ruff check src/ tests/
	@echo "✓ Лінтер пройдено"

format:                        ## Форматувати код через Ruff
	$(PYTHON) -m ruff format src/ tests/
	@echo "✓ Форматування виконано"

help:                          ## Показати цю довідку
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
