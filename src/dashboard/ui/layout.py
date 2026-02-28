"""Макет сторінки: sidebar та заголовок."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st

_TZ_OPTIONS: list[str] = [
    "UTC",
    "Europe/Kyiv",
    "Europe/Berlin",
    "Europe/London",
    "US/Eastern",
    "US/Pacific",
    "Asia/Tokyo",
]


@dataclass
class SidebarState:
    """Значення з елементів керування sidebar."""

    policies: list[str]
    severities: list[str]
    threat_types: list[str]
    components: list[str]
    horizon_days: float
    display_tz: str


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
    """Відображає елементи керування sidebar та повертає поточні вибори."""

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
            key="f_policies",
        )

        st.divider()

        # -- incident filters --
        st.markdown("##### Filter Incidents")

        # severity
        sev_options = (
            sorted(
                incidents_df["severity"].dropna().unique(),
                key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s, 9),
            )
            if incidents_df is not None and "severity" in incidents_df.columns
            else []
        )
        severities = st.multiselect(
            "Severity",
            options=sev_options,
            default=sev_options,
            label_visibility="visible",
            key="f_severities",
        )
        # Store initial option set so the fragment can detect "all selected"
        st.session_state["_sev_opts"] = list(sev_options)

        # threat type
        type_options = (
            sorted(incidents_df["threat_type"].dropna().unique())
            if incidents_df is not None and "threat_type" in incidents_df.columns
            else []
        )
        threat_types = st.multiselect(
            "Threat type",
            options=type_options,
            default=type_options,
            label_visibility="visible",
            key="f_threats",
        )
        st.session_state["_threat_opts"] = list(type_options)

        # component
        comp_options = (
            sorted(incidents_df["component"].dropna().unique())
            if incidents_df is not None and "component" in incidents_df.columns
            else []
        )
        components = st.multiselect(
            "Component",
            options=comp_options,
            default=comp_options,
            label_visibility="visible",
            key="f_components",
        )
        st.session_state["_comp_opts"] = list(comp_options)

        # horizon
        horizon_days = st.number_input(
            "Horizon (days)",
            min_value=0.0,
            max_value=365.0,
            value=0.0,
            step=0.5,
            help="Filter incidents within the last N days. 0 = show all.",
            key="f_horizon",
        )

        st.divider()

        # -- display timezone --
        st.markdown("##### Display timezone")
        display_tz = st.selectbox(
            "Timezone",
            options=_TZ_OPTIONS,
            index=_TZ_OPTIONS.index("Europe/Kyiv"),
            key="display_tz",
            label_visibility="collapsed",
        )

        st.divider()

        # -- auto-refresh --
        st.markdown("##### Auto-refresh")
        auto_refresh = st.toggle(
            "Enable auto-refresh",
            key="auto_refresh",
        )
        refresh_interval = st.slider(
            "Refresh interval (sec)",
            min_value=2,
            max_value=60,
            value=5,
            step=1,
            disabled=not auto_refresh,
            key="refresh_interval",
        )

        if auto_refresh:
            st.caption("Fragment-based auto-refresh is active.")

        tz_obj = ZoneInfo(display_tz)
        now_str = datetime.now(tz_obj).strftime("%Y-%m-%d %H:%M:%S")
        st.markdown(
            f'<p class="refresh-timestamp">Last refresh: {now_str} ({display_tz})</p>',
            unsafe_allow_html=True,
        )

    return SidebarState(
        policies=policies,
        severities=severities,
        threat_types=threat_types,
        components=components,
        horizon_days=horizon_days,
        display_tz=display_tz,
    )
