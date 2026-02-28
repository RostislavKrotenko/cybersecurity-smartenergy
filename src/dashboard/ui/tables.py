"""Incident table rendering.

Provides ``render_incident_table`` which shows a filterable, sortable
``st.dataframe`` with severity colour coding.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.dashboard.data_access import SEVERITY_ORDER

# columns to display (in order)
_DISPLAY_COLS = [
    "start_ts",
    "threat_type",
    "severity",
    "component",
    "policy",
    "mttd_sec",
    "mttr_sec",
    "impact_score",
    "description",
]

_COL_LABELS = {
    "start_ts": "Time",
    "threat_type": "Type",
    "severity": "Severity",
    "component": "Component",
    "policy": "Policy",
    "mttd_sec": "MTTD (s)",
    "mttr_sec": "MTTR (s)",
    "impact_score": "Impact",
    "description": "Description",
}


def render_incident_table(df: pd.DataFrame) -> None:
    """Render the incidents dataframe as a styled table."""
    if df.empty:
        st.info("No incidents match the current filters.")
        return

    # pick available columns
    cols = [c for c in _DISPLAY_COLS if c in df.columns]
    view = df[cols].copy()

    # sort by severity then time
    if "severity" in view.columns:
        view["_sev_ord"] = view["severity"].map(SEVERITY_ORDER).fillna(99)
        view = view.sort_values(["_sev_ord", "start_ts"], ascending=[True, False])
        view = view.drop(columns=["_sev_ord"])

    # format timestamps
    if "start_ts" in view.columns:
        view["start_ts"] = view["start_ts"].dt.strftime("%b %d, %Y  %H:%M")

    # readable column names
    view = view.rename(columns=_COL_LABELS)

    st.caption(f"Showing {len(view)} incidents")

    st.dataframe(
        view,
        hide_index=True,
        width="stretch",
        height=min(len(view) * 36 + 42, 520),
    )
