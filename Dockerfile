# ─────────────────────────────────────────────────────────────────────────────
#  SmartEnergy Cyber-Resilience Analyzer — single-stage Docker image
#  Base: python:3.11-slim  (Debian bookworm, ~150 MB compressed)
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim AS base

# Prevents Python from writing .pyc files & enables unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /work

# ── 1. Install OS-level deps (none required, but keep layer for future) ──
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# ── 2. Install Python deps (cached unless requirements.txt changes) ──────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── 3. Copy application source, configs & package definition ────────────
COPY pyproject.toml .
COPY src/ src/
COPY config/ config/

# ── 4. Install project as editable package (makes 'src' importable) ─────
RUN pip install --no-cache-dir -e .

# ── 5. Create directories for volume mounts ──────────────────────────────
RUN mkdir -p data out logs

# ── 6. Default command — show help ───────────────────────────────────────
CMD ["python", "-c", "print('SmartEnergy image ready. Use docker compose to run services.')"]

# ── Health-check for the UI service ──────────────────────────────────────
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

EXPOSE 8501
