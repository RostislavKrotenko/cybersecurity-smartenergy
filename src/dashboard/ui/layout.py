"""Макет сторінки: sidebar та заголовок."""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

import streamlit as st

from src.dashboard.data_access import (
    INCIDENTS_PATH,
    RESULTS_PATH,
    file_mtime_str,
    file_row_count,
    file_size,
)

# Fixed display timezone -- no user-selectable widget.
DISPLAY_TZ = "Europe/Kyiv"


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


def _reset_defaults() -> None:
    """Callback: reset auto-refresh settings to defaults."""
    st.session_state["auto_refresh"] = False
    st.session_state["refresh_interval"] = 5


def render_sidebar() -> None:
    """Minimal sidebar: auto-refresh controls, file diagnostics, reset."""

    with st.sidebar:
        st.markdown('<p class="sidebar-brand">SmartEnergy</p>', unsafe_allow_html=True)
        st.caption("Cyber-Resilience Analyzer")
        st.divider()

        # -- auto-refresh --
        st.markdown("##### Auto-refresh")
        auto_refresh = st.toggle(
            "Enable auto-refresh",
            key="auto_refresh",
        )
        st.slider(
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

        tz_obj = ZoneInfo(DISPLAY_TZ)
        now_str = datetime.now(tz_obj).strftime("%Y-%m-%d %H:%M:%S")
        st.markdown(
            f'<p class="refresh-timestamp">Last refresh: {now_str} ({DISPLAY_TZ})</p>',
            unsafe_allow_html=True,
        )

        st.divider()

        # -- file diagnostics (read-only) --
        st.markdown("##### Data files")

        _inc_mtime = file_mtime_str(INCIDENTS_PATH)
        _inc_size = file_size(INCIDENTS_PATH)
        _inc_rows = file_row_count(INCIDENTS_PATH)

        _res_mtime = file_mtime_str(RESULTS_PATH)
        _res_size = file_size(RESULTS_PATH)
        _res_rows = file_row_count(RESULTS_PATH)

        st.markdown(
            f"""
**incidents.csv**
- mtime: {_inc_mtime}
- size: {_inc_size} bytes
- rows: {_inc_rows}

**results.csv**
- mtime: {_res_mtime}
- size: {_res_size} bytes
- rows: {_res_rows}
""",
        )

        st.divider()

        # -- reset --
        st.button("Reset to defaults", on_click=_reset_defaults)
