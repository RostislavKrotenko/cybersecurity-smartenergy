"""Page layout — sidebar controls and main-area scaffolding.

``render_sidebar`` populates the left panel and returns an object
with the current filter values.  ``render_header`` draws the top
title bar.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

try:
    from streamlit_autorefresh import st_autorefresh  # type: ignore[import-untyped]
    _HAS_AUTOREFRESH = True
except ImportError:
    _HAS_AUTOREFRESH = False


@dataclass
class SidebarState:
    """Values collected from sidebar controls."""
    policies: list[str]
    severities: list[str]
    threat_types: list[str]
    components: list[str]
    horizon_days: float


# ── header ──────────────────────────────────────────────────────────────────


def render_header() -> None:
    st.markdown(
        '<h1 class="page-title">SmartEnergy Security Dashboard</h1>'
        '<p class="page-subtitle">'
        "Real-time analysis and metrics for SmartEnergy security events."
        "</p>",
        unsafe_allow_html=True,
    )


# ── sidebar ─────────────────────────────────────────────────────────────────


def render_sidebar(
    incidents_df: pd.DataFrame | None,
) -> SidebarState:
    """Draw sidebar controls and return current selections."""

    with st.sidebar:
        st.markdown('<p class="sidebar-brand">SmartEnergy</p>', unsafe_allow_html=True)
        st.caption("Cyber-Resilience Analyzer")
        st.divider()

        # -- policies --
        st.markdown("##### Policies")
        policies = st.multiselect(
            "Policies",
            options=["baseline", "minimal", "standard"],
            default=["baseline", "minimal", "standard"],
            label_visibility="collapsed",
        )

        st.divider()

        # -- incident filters --
        st.markdown("##### Filter Incidents")

        # severity
        sev_options = (
            sorted(incidents_df["severity"].dropna().unique(), key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s, 9))
            if incidents_df is not None and "severity" in incidents_df.columns
            else []
        )
        severities = st.multiselect("Severity", options=sev_options, default=sev_options, label_visibility="visible")

        # threat type
        type_options = (
            sorted(incidents_df["threat_type"].dropna().unique())
            if incidents_df is not None and "threat_type" in incidents_df.columns
            else []
        )
        threat_types = st.multiselect("Threat type", options=type_options, default=type_options, label_visibility="visible")

        # component
        comp_options = (
            sorted(incidents_df["component"].dropna().unique())
            if incidents_df is not None and "component" in incidents_df.columns
            else []
        )
        components = st.multiselect("Component", options=comp_options, default=comp_options, label_visibility="visible")

        # horizon
        horizon_days = st.number_input(
            "Horizon (days)",
            min_value=0.0,
            max_value=365.0,
            value=0.0,
            step=0.5,
            help="Filter incidents within the last N days. 0 = show all.",
        )

        st.divider()

        # -- auto-refresh --
        st.markdown("##### Auto-refresh")
        auto_refresh = st.toggle("Enable auto-refresh", value=False)
        refresh_interval = st.slider(
            "Refresh interval (sec)",
            min_value=2,
            max_value=60,
            value=5,
            step=1,
            disabled=not auto_refresh,
        )

        if auto_refresh:
            if _HAS_AUTOREFRESH:
                from src.dashboard.data_access import clear_caches
                clear_caches()
                st_autorefresh(interval=refresh_interval * 1000, key="live_refresh")
            else:
                st.warning("Install streamlit-autorefresh:\npip install streamlit-autorefresh")

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        st.markdown(
            f'<p class="refresh-timestamp">Last refresh: {now_str}</p>',
            unsafe_allow_html=True,
        )

    return SidebarState(
        policies=policies,
        severities=severities,
        threat_types=threat_types,
        components=components,
        horizon_days=horizon_days,
    )
