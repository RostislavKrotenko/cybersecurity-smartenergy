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

.PHONY: venv install generate normalize analyze ui demo-local clean lint help

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

normalize:                     ## Run Normalizer → data/events.csv + out/quarantine.csv
	@mkdir -p $(DATA_DIR) $(OUT_DIR)
	$(PYTHON) -m src.normalizer \
		--inputs "$(LOGS_DIR)/*.log" \
		--out $(DATA_DIR)/events.csv \
		--quarantine $(OUT_DIR)/quarantine.csv \
		--log-level INFO
	@echo "✓ Normalizer done"

analyze:                       ## Run Analyzer → out/*
	@mkdir -p $(OUT_DIR)
	$(PYTHON) -m src.analyzer \
		--input $(DATA_DIR)/events.csv \
		--out-dir $(OUT_DIR) \
		--policies all \
		--horizon-days 1 \
		--log-level INFO
	@echo "✓ Analyzer done → $(OUT_DIR)/"

ui:                            ## Launch Streamlit dashboard (localhost:8501)
	$(PYTHON) -m streamlit run src/dashboard/app.py \
		--server.headless true --server.port 8501

demo-local: generate analyze ui ## Full local demo: generate → analyze → UI

demo-live:                     ## Live demo: emulator + analyzer + UI (real-time streaming)
	@echo "Starting live demo (Ctrl+C to stop all)..."
	@rm -f $(DATA_DIR)/live/events.jsonl
	@mkdir -p $(DATA_DIR)/live $(OUT_DIR) $(LOGS_DIR)/live
	@trap 'kill 0' INT; \
	$(PYTHON) -m src.emulator --live --live-interval-ms 500 --out $(DATA_DIR)/live/events.jsonl --raw-log-dir $(LOGS_DIR)/live --seed 42 & \
	sleep 2 && \
	$(PYTHON) -m src.analyzer --input $(DATA_DIR)/live/events.jsonl --watch --poll-interval-ms 1000 --out-dir $(OUT_DIR) --policies all & \
	sleep 1 && \
	$(PYTHON) -m streamlit run src/dashboard/app.py --server.headless true --server.port 8501

# ═════════════════════════════════════════════════════════════════════════════
#   DOCKER
# ═════════════════════════════════════════════════════════════════════════════

.PHONY: docker-build docker-generate docker-normalize docker-analyze docker-ui \
        docker-live demo docker-down docker-clean

docker-build:                  ## Build Docker image
	$(COMPOSE) --profile demo --profile normalize build

docker-generate: docker-build  ## Docker: run emulator
	@mkdir -p $(DATA_DIR)
	$(COMPOSE) run --rm emulator
	@echo "✓ Docker emulator done"

docker-normalize: docker-build ## Docker: run normalizer
	@mkdir -p $(DATA_DIR) $(OUT_DIR)
	$(COMPOSE) run --rm normalizer
	@echo "✓ Docker normalizer done"

docker-analyze: docker-build   ## Docker: run analyzer
	@mkdir -p $(OUT_DIR)
	$(COMPOSE) run --rm analyzer
	@echo "✓ Docker analyzer done"

docker-ui: docker-build        ## Docker: start Streamlit
	$(COMPOSE) up ui

demo: docker-build             ## Full Docker demo: generate → analyze → UI
	@echo "── Step 1/3: Generating synthetic data ──"
	@mkdir -p $(DATA_DIR) $(OUT_DIR)
	$(COMPOSE) run --rm emulator
	@echo "── Step 2/3: Running analyzer ──"
	$(COMPOSE) run --rm analyzer
	@echo "── Step 3/3: Starting UI on http://localhost:8501 ──"
	$(COMPOSE) up ui

docker-live:                   ## Live Docker: emulator + analyzer + UI (one command)
	@mkdir -p $(DATA_DIR)/live $(OUT_DIR) $(LOGS_DIR)/live
	$(COMPOSE) --profile live up --build

docker-down:                   ## Stop all containers
	$(COMPOSE) down --remove-orphans

docker-clean: docker-down      ## Stop + remove images & volumes
	$(COMPOSE) down --rmi local --volumes --remove-orphans

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
