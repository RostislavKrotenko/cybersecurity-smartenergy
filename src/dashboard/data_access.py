"""Data loading and filtering layer.

All read operations go through cached loaders so that the dashboard
never re-reads CSVs on every re-render.  A single ``apply_filters``
helper is used everywhere to keep filtering logic consistent.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

# ── paths (relative to repo root) ───────────────────────────────────────────

ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_PATH = ROOT / "out" / "results.csv"
INCIDENTS_PATH = ROOT / "out" / "incidents.csv"
EVENTS_PATH = ROOT / "data" / "events.csv"


# ── cached loaders ──────────────────────────────────────────────────────────


@st.cache_data(show_spinner=False, ttl=10)
def load_results() -> pd.DataFrame | None:
    """Load ``out/results.csv``.  Returns *None* when the file is absent."""
    if not RESULTS_PATH.exists():
        return None
    return pd.read_csv(RESULTS_PATH)


@st.cache_data(show_spinner=False, ttl=10)
def load_incidents() -> pd.DataFrame | None:
    """Load ``out/incidents.csv``.  Returns *None* when the file is absent."""
    if not INCIDENTS_PATH.exists():
        return None
    df = pd.read_csv(INCIDENTS_PATH)
    for col in ("start_ts", "detect_ts", "recover_ts"):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    return df


@st.cache_data(show_spinner=False, ttl=30)
def load_events(nrows: int = 200) -> pd.DataFrame | None:
    """Load ``data/events.csv`` (first *nrows* rows)."""
    if not EVENTS_PATH.exists():
        return None
    return pd.read_csv(EVENTS_PATH, nrows=nrows)


def clear_caches() -> None:
    """Bust every cached loader so the next render gets fresh data."""
    load_results.clear()
    load_incidents.clear()
    load_events.clear()


# ── filtering ───────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def filter_results(
    df: pd.DataFrame,
    policies: list[str],
) -> pd.DataFrame:
    """Return results rows matching *policies*."""
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
    """Apply every sidebar filter to the incidents dataframe."""
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
