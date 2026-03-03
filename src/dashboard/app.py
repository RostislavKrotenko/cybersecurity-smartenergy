"""Головний файл дашборду SmartEnergy на Streamlit."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

# ── page config (MUST be the first Streamlit call) ───────────────────────────

st.set_page_config(
    page_title="SmartEnergy Security Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── inject theme CSS ────────────────────────────────────────────────────────

_CSS_PATH = Path(__file__).resolve().parent / "styles" / "theme.css"
if _CSS_PATH.exists():
    st.markdown(f"<style>{_CSS_PATH.read_text()}</style>", unsafe_allow_html=True)

# ── local imports (after page config) ───────────────────────────────────────

from src.dashboard.data_access import (  # noqa: E402
    INCIDENTS_PATH,
    RESULTS_PATH,
    file_mtime_str,
    file_row_count,
    file_size,
    load_incidents,
    load_results,
)
from src.dashboard.ui.cards import policy_kpi_card  # noqa: E402
from src.dashboard.ui.charts import (  # noqa: E402
    CHART_CONFIG,
    availability_bar,
    downtime_bar,
    incidents_per_minute,
)
from src.dashboard.ui.layout import render_header, render_sidebar  # noqa: E402
from src.dashboard.ui.state import init_state  # noqa: E402
from src.dashboard.ui.tables import render_incident_table  # noqa: E402

# ── initialise session state ────────────────────────────────────────────────

init_state()

# ── sidebar (needs incidents for dynamic filter options) ────────────────────

_sidebar_incidents = load_incidents()
_sidebar_state = render_sidebar(_sidebar_incidents)

# store display_tz in session state so the fragment can access it
st.session_state["_display_tz"] = _sidebar_state.display_tz

# ── header ──────────────────────────────────────────────────────────────────

render_header()


# ═════════════════════════════════════════════════════════════════════════════
#   LIVE DATA SECTION -- wrapped in @st.fragment for flicker-free refresh
#
#   When auto-refresh is enabled the fragment re-executes every N seconds
#   WITHOUT triggering a full page rerun, so KPI cards, charts and the
#   incident table update in-place with no visible flash.
# ═════════════════════════════════════════════════════════════════════════════

_auto = st.session_state.get("auto_refresh", False)
_interval = st.session_state.get("refresh_interval", 5)


@st.fragment(run_every=timedelta(seconds=_interval) if _auto else None)
def _live_data_section() -> None:
    # ── refresh tick (counts fragment + full reruns) ─────────────────
    if "refresh_tick" not in st.session_state:
        st.session_state["refresh_tick"] = 0
    st.session_state["refresh_tick"] += 1

    # ── load fresh data ─────────────────────────────────────────────
    df_results = load_results()
    df_incidents = load_incidents()

    # ── guard: no data ──────────────────────────────────────────────
    if df_results is None:
        st.markdown(
            '<div class="no-data-box">'
            "<strong>No results yet. Run analysis first.</strong>"
            "The output files <code>out/results.csv</code> and "
            "<code>out/incidents.csv</code> were not found.<br><br>"
            "Run the analyzer:<br>"
            "<code>python -m src.analyzer --input data/events.csv --horizon-days 1</code>"
            "</div>",
            unsafe_allow_html=True,
        )
        return

    # ── KPI CARDS ───────────────────────────────────────────────────
    _policy_order = ["baseline", "minimal", "standard"]
    ordered = df_results.set_index("policy").reindex(
        [p for p in _policy_order if p in df_results["policy"].values]
    )

    if not ordered.empty:
        cols = st.columns(len(ordered))
        for col, (policy, row) in zip(cols, ordered.iterrows()):
            with col:
                st.markdown(
                    policy_kpi_card(
                        policy=str(policy),
                        availability=row["availability_pct"],
                        downtime_hr=row["total_downtime_hr"],
                        mttd_min=row["mean_mttd_min"],
                        mttr_min=row["mean_mttr_min"],
                    ),
                    unsafe_allow_html=True,
                )

    # ── CHARTS: availability + downtime ─────────────────────────────
    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        st.plotly_chart(
            availability_bar(df_results),
            width="stretch",
            config=CHART_CONFIG,
            key="chart_avail",
        )
    with c2:
        st.plotly_chart(
            downtime_bar(df_results),
            width="stretch",
            config=CHART_CONFIG,
            key="chart_downtime",
        )

    # ── CHART: incidents per minute ─────────────────────────────────
    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

    _tz = st.session_state.get("_display_tz", "Europe/Kyiv")

    if df_incidents is not None and not df_incidents.empty:
        fig = incidents_per_minute(df_incidents, tz=_tz)
        if fig is not None:
            st.plotly_chart(
                fig,
                width="stretch",
                config=CHART_CONFIG,
                key="chart_ipm",
            )
            st.caption(f"Incident rows: {len(df_incidents)} | Time axis: {_tz}")
        else:
            st.markdown(
                '<div class="no-data-box">'
                "<strong>Incidents per Minute</strong><br>Not enough data yet."
                "</div>",
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div class="no-data-box">'
            "<strong>Incidents per Minute</strong><br>Not enough data yet."
            "</div>",
            unsafe_allow_html=True,
        )

    # ── INCIDENT TABLE ──────────────────────────────────────────────
    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
    st.markdown('<p class="section-label">Incident Table</p>', unsafe_allow_html=True)

    if df_incidents is not None:
        render_incident_table(df_incidents)
    else:
        st.info("No incidents data available.")

    # ── DIAGNOSTICS ─────────────────────────────────────────────────
    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

    with st.expander("Diagnostics (live debug info)", expanded=False):
        _now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        _tick = st.session_state.get("refresh_tick", "?")

        _inc_mtime = file_mtime_str(INCIDENTS_PATH)
        _inc_size = file_size(INCIDENTS_PATH)
        _inc_rows = file_row_count(INCIDENTS_PATH)

        _res_mtime = file_mtime_str(RESULTS_PATH)
        _res_size = file_size(RESULTS_PATH)
        _res_rows = file_row_count(RESULTS_PATH)

        _last_inc_ts = "N/A"
        if (
            df_incidents is not None
            and not df_incidents.empty
            and "start_ts" in df_incidents.columns
        ):
            _max_ts = df_incidents["start_ts"].max()
            if pd.notna(_max_ts):
                _last_inc_ts = str(_max_ts)

        st.markdown(
            f"""
| Metric | Value |
|---|---|
| **Refresh tick** | {_tick} |
| **Last refresh (UI)** | {_now} |
| **incidents.csv mtime** | {_inc_mtime} |
| **incidents.csv size** | {_inc_size} bytes |
| **incidents.csv rows** | {_inc_rows} |
| **Last incident timestamp** | {_last_inc_ts} |
| **results.csv mtime** | {_res_mtime} |
| **results.csv size** | {_res_size} bytes |
| **results.csv rows** | {_res_rows} |
""",
        )


# ── invoke the fragment ─────────────────────────────────────────────────────

_live_data_section()
