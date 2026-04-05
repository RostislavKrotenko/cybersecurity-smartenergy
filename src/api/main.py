"""Головний FastAPI застосунок SmartEnergy Cyber-Resilience Analyzer.

Запуск:
    uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

Або через модуль:
    python -m src.api
"""

from __future__ import annotations

from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.models import HealthResponse
from src.api.routes import actions, incidents, metrics, state

app = FastAPI(
    title="SmartEnergy Cyber-Resilience API",
    description="""
REST API для SmartEnergy Cyber-Resilience Analyzer.

Надає ендпоінти для:
- **Incidents** - інциденти безпеки, виявлені аналізатором
- **Actions** - дії реагування (block_actor, isolate_component тощо)
- **State** - поточний стан компонентів інфраструктури
- **Metrics** - метрики стійкості (availability, MTTD, MTTR)

API призначений для React-фронтенду та інших клієнтів.
    """,
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(incidents.router, prefix="/api")
app.include_router(actions.router, prefix="/api")
app.include_router(state.router, prefix="/api")
app.include_router(metrics.router, prefix="/api")


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    """Повертає коротку інформацію про API та шлях до документації."""
    return {"message": "SmartEnergy API", "docs": "/api/docs"}


@app.get("/health", response_model=HealthResponse, tags=["health"])
@app.get("/api/health", response_model=HealthResponse, tags=["health"])
def health_check() -> HealthResponse:
    """Повертає стан сервісу для моніторингу доступності."""
    return HealthResponse(
        status="ok",
        version="1.0.0",
        timestamp=datetime.utcnow().isoformat() + "Z",
    )


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    """Спрощений health-check у форматі `healthz`."""
    return {"status": "ok"}
