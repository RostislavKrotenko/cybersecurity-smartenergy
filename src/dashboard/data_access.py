"""Шар завантаження та фільтрації даних."""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

log = logging.getLogger(__name__)

# ── paths (relative to repo root) ───────────────────────────────────────────

ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_PATH = ROOT / "out" / "results.csv"
INCIDENTS_PATH = ROOT / "out" / "incidents.csv"
EVENTS_PATH = ROOT / "data" / "events.csv"

# ── retry / stability settings ──────────────────────────────────────────────

_MAX_READ_RETRIES = 3
_READ_RETRY_DELAY_SEC = 0.15  # 150 ms between retries


# ── file info helpers ───────────────────────────────────────────────────────


def file_mtime(path: Path) -> float:
    """Повертає mtime як UNIX timestamp, або 0.0 якщо файл відсутній."""
    try:
        return os.path.getmtime(path) if path.exists() else 0.0
    except OSError:
        return 0.0


def file_mtime_str(path: Path) -> str:
    """Повертає людськочитаний mtime файлу, або 'N/A'."""
    ts = file_mtime(path)
    if ts == 0.0:
        return "N/A"
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def file_size(path: Path) -> int:
    """Повертає розмір файлу в байтах, або 0."""
    try:
        return path.stat().st_size if path.exists() else 0
    except OSError:
        return 0


def file_row_count(path: Path) -> int:
    """Повертає кількість рядків даних (без заголовка), або 0."""
    if not path.exists() or file_size(path) == 0:
        return 0
    try:
        with open(path, encoding="utf-8") as fh:
            return max(0, sum(1 for _ in fh) - 1)
    except Exception:
        return 0


# ── internal CSV reader with retry ──────────────────────────────────────────


def _read_csv_safe(path: Path, **kwargs) -> pd.DataFrame | None:
    """Зчитує CSV з повторними спробами для стійкості."""
    for attempt in range(1, _MAX_READ_RETRIES + 1):
        if not path.exists():
            return None
        sz = file_size(path)
        if sz == 0:
            # File may have just been created / replaced; wait and retry
            if attempt < _MAX_READ_RETRIES:
                time.sleep(_READ_RETRY_DELAY_SEC)
                continue
            return None
        try:
            return pd.read_csv(path, **kwargs)
        except Exception as exc:
            log.debug(
                "CSV read attempt %d/%d for %s failed: %s",
                attempt,
                _MAX_READ_RETRIES,
                path,
                exc,
            )
            if attempt < _MAX_READ_RETRIES:
                time.sleep(_READ_RETRY_DELAY_SEC)
    return None


# ── loaders ─────────────────────────────────────────────────────────────────


def _is_live() -> bool:
    return bool(st.session_state.get("auto_refresh", False))


def load_results() -> pd.DataFrame | None:
    """Завантажує out/results.csv. Повертає None якщо відсутній."""
    return _read_csv_safe(RESULTS_PATH)


def load_incidents() -> pd.DataFrame | None:
    """Завантажує out/incidents.csv. Повертає None якщо відсутній."""
    df = _read_csv_safe(INCIDENTS_PATH)
    if df is None:
        return None
    for col in ("start_ts", "detect_ts", "recover_ts"):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    return df


def load_events(nrows: int = 200) -> pd.DataFrame | None:
    """Завантажує data/events.csv (перші nrows рядків)."""
    return _read_csv_safe(EVENTS_PATH, nrows=nrows)


def clear_caches() -> None:
    """Не використовується, збережено для сумісності інтерфейсу."""
    pass


# ── filtering ───────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def filter_results(
    df: pd.DataFrame,
    policies: list[str],
) -> pd.DataFrame:
    """Фільтрує results за політиками."""
    if not policies:
        return df
    return df[df["policy"].isin(policies)].copy()


def filter_incidents(
    df: pd.DataFrame,
    *,
    policies: list[str] | None = None,
    severities: list[str] | None = None,
    threat_types: list[str] | None = None,
    components: list[str] | None = None,
    horizon_days: float | None = None,
) -> pd.DataFrame:
    """Застосовує фільтри sidebar до incidents."""
    mask = pd.Series(True, index=df.index)

    if policies:
        mask &= df["policy"].isin(policies)
    if severities:
        mask &= df["severity"].isin(severities)
    if threat_types:
        mask &= df["threat_type"].isin(threat_types)
    if components:
        mask &= df["component"].isin(components)

    if horizon_days and horizon_days > 0 and "start_ts" in df.columns:
        latest = df["start_ts"].max()
        if pd.notna(latest):
            cutoff = latest - pd.Timedelta(days=horizon_days)
            mask &= df["start_ts"] >= cutoff

    return df.loc[mask].copy()
