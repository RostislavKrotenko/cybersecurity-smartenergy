"""Page layout -- sidebar controls and main-area scaffolding.

``render_sidebar`` populates the left panel with auto-refresh controls
and live diagnostics.  ``render_header`` draws the top title bar.
"""

from __future__ import annotations

from datetime import datetime, timezone

import streamlit as st

from src.dashboard.data_access import (
    ACTIONS_PATH,
    INCIDENTS_PATH,
    RESULTS_PATH,
    STATE_PATH,
    file_mtime_str,
    file_row_count,
    file_size,
)

try:
    from streamlit_autorefresh import st_autorefresh  # type: ignore[import-untyped]

    _HAS_AUTOREFRESH = True
except ModuleNotFoundError:
    _HAS_AUTOREFRESH = False


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


def render_sidebar() -> None:
    """Draw sidebar: auto-refresh controls, diagnostics, reset."""

    with st.sidebar:
        st.markdown('<p class="sidebar-brand">SmartEnergy</p>', unsafe_allow_html=True)
        st.caption("Cyber-Resilience Analyzer")
        st.divider()

        # -- auto-refresh --
        st.markdown("##### Auto-refresh")
        auto_refresh = st.toggle(
            "Enable auto-refresh",
            value=False,
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
            if _HAS_AUTOREFRESH:
                st_autorefresh(
                    interval=refresh_interval * 1000,
                    key="live_refresh",
                )
            else:
                st.warning("Install streamlit-autorefresh:\npip install streamlit-autorefresh")

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        st.markdown(
            f'<p class="refresh-timestamp">Last refresh: {now_str} (UTC)</p>',
            unsafe_allow_html=True,
        )

        st.divider()

        # -- live diagnostics (read-only) --
        st.markdown("##### Live Diagnostics")

        _diag_files = [
            ("incidents.csv", INCIDENTS_PATH),
            ("results.csv", RESULTS_PATH),
            ("actions.csv", ACTIONS_PATH),
            ("state.csv", STATE_PATH),
        ]

        for label, path in _diag_files:
            mtime = file_mtime_str(path)
            size = file_size(path)
            rows = file_row_count(path)
            if mtime == "N/A":
                st.markdown(
                    f"**{label}** -- not found",
                    help=f"{path}",
                )
            else:
                st.markdown(
                    f"**{label}**  \n"
                    f"mtime: {mtime}  \n"
                    f"size: {size} bytes | rows: {rows}",
                )

        st.divider()

        # -- reset to defaults --
        if st.button("Reset to defaults", use_container_width=True):
            from src.dashboard.ui.state import DEFAULTS

            for key, value in DEFAULTS.items():
                st.session_state[key] = value
            st.rerun()
