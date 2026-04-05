# ─────────────────────────────────────────────────────────────────────────────
#  SmartEnergy Cyber-Resilience Analyzer — Makefile
# ─────────────────────────────────────────────────────────────────────────────

SHELL   := /bin/bash
PYTHON  := .venv/bin/python
COMPOSE := docker compose

.DEFAULT_GOAL := help

# ── Directories ──────────────────────────────────────────────────────────────
DATA_DIR := data
OUT_DIR  := out
LOGS_DIR := logs

# ═════════════════════════════════════════════════════════════════════════════
#   LOCAL (no Docker)
# ═════════════════════════════════════════════════════════════════════════════

.PHONY: venv install generate analyze api demo-local demo-live clean lint help

venv:                          ## Create virtual-env
	python3 -m venv .venv

install: venv                  ## Install all Python deps + project as editable
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e .

generate:                      ## Run Emulator → data/events.csv
	@mkdir -p $(DATA_DIR)
	$(PYTHON) -m src.emulator --seed 42 --out $(DATA_DIR)/events.csv --log-level INFO
	@echo "✓ Emulator done → $(DATA_DIR)/events.csv"

analyze:                       ## Run Analyzer → out/*
	@mkdir -p $(OUT_DIR)
	$(PYTHON) -m src.analyzer \
		--input $(DATA_DIR)/events.csv \
		--out-dir $(OUT_DIR) \
		--policies all \
		--horizon-days 1 \
		--log-level INFO
	@echo "✓ Analyzer done → $(OUT_DIR)/"

api:                           ## Launch FastAPI server (localhost:8000)
	$(PYTHON) -m src.api --port 8000

demo-local: generate analyze api ## Full local demo: generate → analyze → API

demo-live:                     ## Live demo (local): emulator + analyzer + API with closed-loop ACK
	@echo "Starting live demo (Ctrl+C to stop all)..."
	@rm -f $(DATA_DIR)/live/events.jsonl $(DATA_DIR)/live/actions.jsonl $(DATA_DIR)/live/actions_applied.jsonl
	@mkdir -p $(DATA_DIR)/live $(OUT_DIR) $(LOGS_DIR)/live
	@trap 'kill 0' INT; \
	$(PYTHON) -m src.emulator --live --live-interval-ms 500 --out $(DATA_DIR)/live/events.jsonl --raw-log-dir $(LOGS_DIR)/live --seed 42 --actions-path $(DATA_DIR)/live/actions.jsonl --applied-path $(DATA_DIR)/live/actions_applied.jsonl & \
	sleep 2 && \
	$(PYTHON) -m src.analyzer --input $(DATA_DIR)/live/events.jsonl --watch --poll-interval-ms 1000 --out-dir $(OUT_DIR) --policies all --actions-path $(DATA_DIR)/live/actions.jsonl --applied-path $(DATA_DIR)/live/actions_applied.jsonl & \
	sleep 1 && \
	SMARTENERGY_LIVE_MODE=1 $(PYTHON) -m src.api --port 8000

# ═════════════════════════════════════════════════════════════════════════════
#   DOCKER
# ═════════════════════════════════════════════════════════════════════════════

.PHONY: docker-build docker-live docker-api docker-down docker-clean

docker-build:                  ## Build Docker image
	$(COMPOSE) --profile live build

docker-live:                   ## Live Docker: full closed-loop with all services
	@mkdir -p $(DATA_DIR)/live $(OUT_DIR) $(LOGS_DIR)/live
	$(COMPOSE) --profile live up --build

docker-api:                    ## Docker: standalone API server only
	$(COMPOSE) --profile api up --build

docker-down:                   ## Stop all containers
	$(COMPOSE) down --remove-orphans

docker-clean: docker-down      ## Stop + remove images & volumes
	$(COMPOSE) down --rmi local --volumes --remove-orphans

# ═════════════════════════════════════════════════════════════════════════════
#   FRONTEND (React)
# ═════════════════════════════════════════════════════════════════════════════

.PHONY: frontend-install frontend-dev frontend-build

frontend-install:              ## Install frontend dependencies
	cd frontend && npm install

frontend-dev:                  ## Run frontend dev server (localhost:5173)
	cd frontend && npm run dev

frontend-build:                ## Build frontend for production
	cd frontend && npm run build

# ═════════════════════════════════════════════════════════════════════════════
#   MAINTENANCE
# ═════════════════════════════════════════════════════════════════════════════

clean:                         ## Remove generated artefacts
	rm -rf $(OUT_DIR)/*
	rm -f  $(DATA_DIR)/events.csv $(DATA_DIR)/_uploaded_events.csv
	@echo "✓ Cleaned $(OUT_DIR)/ and $(DATA_DIR)/events.csv"

# ═════════════════════════════════════════════════════════════════════════════
#   TESTING & QUALITY
# ═════════════════════════════════════════════════════════════════════════════

.PHONY: test test-slow test-cov lint format

test:                          ## Run fast tests (no seed repro)
	$(PYTHON) -m pytest tests/ -v --tb=short

test-slow:                     ## Run ALL tests incl. seed reproducibility
	$(PYTHON) -m pytest tests/ -v --tb=short -m slow

test-cov:                      ## Run tests with coverage report
	$(PYTHON) -m pytest tests/ -v --tb=short --cov=src --cov-report=term-missing

lint:                          ## Run ruff linter
	$(PYTHON) -m ruff check src/ tests/
	@echo "✓ Lint passed"

format:                        ## Format code with ruff
	$(PYTHON) -m ruff format src/ tests/
	@echo "✓ Formatted"

help:                          ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
