"""Відображення таблиці інцидентів."""

from __future__ import annotations

import pandas as pd
import streamlit as st
from streamlit import column_config as colcfg

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

# Column configuration for st.dataframe -- keeps the table self-contained
# for sorting (click header) and filtering (built-in search bar).
_COL_CONFIG = {
    "Time": colcfg.DatetimeColumn("Time", format="MMM DD, YYYY  HH:mm"),
    "MTTD (s)": colcfg.NumberColumn("MTTD (s)", format="%.1f"),
    "MTTR (s)": colcfg.NumberColumn("MTTR (s)", format="%.1f"),
    "Impact": colcfg.NumberColumn("Impact", format="%.2f"),
}


def render_incident_table(df: pd.DataFrame) -> None:
    """Render an interactive incident table.

    Users can sort by clicking any column header and use the built-in
    search bar (top-right corner of the dataframe widget) to filter
    rows -- no separate sidebar filters needed.
    """
    if df.empty:
        st.info("No incidents to display.")
        return

    # pick available columns
    cols = [c for c in _DISPLAY_COLS if c in df.columns]
    view = df[cols].copy()

    # default sort: severity (critical first), then newest first
    if "severity" in view.columns:
        view["_sev_ord"] = view["severity"].map(SEVERITY_ORDER).fillna(99)
        view = view.sort_values(["_sev_ord", "start_ts"], ascending=[True, False])
        view = view.drop(columns=["_sev_ord"])

    # readable column names
    view = view.rename(columns=_COL_LABELS)

    st.caption(f"Total incidents: {len(view)}")

    st.dataframe(
        view,
        hide_index=True,
        use_container_width=True,
        height=min(len(view) * 36 + 42, 600),
        column_config=_COL_CONFIG,
        key="tbl_incidents",
    )
