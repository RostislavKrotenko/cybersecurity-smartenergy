"""Main dashboard file for SmartEnergy (Streamlit)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

# -- page config (MUST be the first Streamlit call) ---------------------------

st.set_page_config(
    page_title="SmartEnergy Security Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -- inject theme CSS ---------------------------------------------------------

_CSS_PATH = Path(__file__).resolve().parent / "styles" / "theme.css"
if _CSS_PATH.exists():
    st.markdown(f"<style>{_CSS_PATH.read_text()}</style>", unsafe_allow_html=True)

# -- local imports (after page config) ----------------------------------------

from src.dashboard.data_access import (  # noqa: E402
    ACTIONS_PATH,
    INCIDENTS_PATH,
    RESULTS_PATH,
    STATE_PATH,
    file_mtime_str,
    file_row_count,
    file_size,
    load_actions,
    load_incidents,
    load_results,
    load_state,
)
from src.dashboard.ui.cards import (  # noqa: E402
    action_summary_card,
    component_status_card,
    db_status_card,
    network_status_card,
    policy_kpi_card,
)
from src.dashboard.ui.charts import (  # noqa: E402
    CHART_CONFIG,
    actions_per_minute,
    availability_bar,
    downtime_bar,
    incidents_per_minute,
)
from src.dashboard.ui.layout import render_header, render_sidebar  # noqa: E402
from src.dashboard.ui.state import init_state  # noqa: E402
from src.dashboard.ui.tables import render_incident_table  # noqa: E402

# -- initialise session state -------------------------------------------------

init_state()

# -- sidebar ------------------------------------------------------------------

render_sidebar()

# -- header -------------------------------------------------------------------

render_header()


# =============================================================================
#   LIVE DATA SECTION -- wrapped in @st.fragment for flicker-free refresh
# =============================================================================

_auto = st.session_state.get("auto_refresh", False)
_interval = st.session_state.get("refresh_interval", 5)


def _action_counts(df: pd.DataFrame | None) -> dict[str, int]:
    """Compute emitted/applied/failed counts from actions DataFrame."""
    counts = {"emitted": 0, "applied": 0, "failed": 0, "total": 0}
    if df is None or "status" not in df.columns:
        return counts
    counts["total"] = len(df)
    counts["emitted"] = int((df["status"] == "emitted").sum())
    counts["applied"] = int((df["status"] == "applied").sum())
    counts["failed"] = int((df["status"] == "failed").sum())
    return counts


def _parse_details(details: str) -> dict[str, str]:
    """Parse 'key1=val1 key2=val2' or 'key1=val1,key2=val2' into dict."""
    result = {}
    if not details or details in ("nan", "NaN", "None", "none"):
        return result
    # Support both space and comma separators
    parts = details.replace(",", " ").split()
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
    return result


@st.fragment(run_every=timedelta(seconds=_interval) if _auto else None)
def _live_data_section() -> None:
    # -- refresh tick (counts fragment + full reruns) -------------------------
    if "refresh_tick" not in st.session_state:
        st.session_state["refresh_tick"] = 0
    st.session_state["refresh_tick"] += 1

    # -- load fresh data ------------------------------------------------------
    df_results = load_results()
    df_incidents = load_incidents()

    # -- guard: no data -------------------------------------------------------
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

    # -- KPI CARDS ------------------------------------------------------------
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

    # -- COMPONENT STATUS + ACTION SUMMARY ------------------------------------
    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
    st.markdown('<p class="section-label">Infrastructure Status (Live)</p>', unsafe_allow_html=True)

    df_state = load_state()
    df_act_all = load_actions()
    act_counts = _action_counts(df_act_all)

    if df_state is not None and not df_state.empty and "component" in df_state.columns:
        # Row 1: Gateway, API, Auth status cards
        _basic_components = ["gateway", "api", "auth"]
        basic_cols = st.columns(len(_basic_components))
        for col, comp_name in zip(basic_cols, _basic_components):
            row = df_state[df_state["component"] == comp_name]
            if not row.empty:
                r = row.iloc[0]
                _comp_status = str(r.get("status", "healthy"))
                _raw_details = r.get("details", "")
                _comp_details = "" if pd.isna(_raw_details) else str(_raw_details)
                _raw_ttl = r.get("ttl_sec", 0)
                _comp_ttl = 0.0 if pd.isna(_raw_ttl) else float(_raw_ttl)
            else:
                _comp_status = "healthy"
                _comp_details = ""
                _comp_ttl = 0.0
            with col:
                st.markdown(
                    component_status_card(comp_name, _comp_status, _comp_details, _comp_ttl),
                    unsafe_allow_html=True,
                )

        # Row 2: DB, Network, Actions (dedicated cards)
        st.markdown('<div style="margin-top:12px"></div>', unsafe_allow_html=True)
        infra_cols = st.columns(3)

        # DB status card
        with infra_cols[0]:
            db_row = df_state[df_state["component"] == "db"]
            if not db_row.empty:
                r = db_row.iloc[0]
                _db_status = str(r.get("status", "healthy"))
                _raw_details = r.get("details", "")
                _db_details = "" if pd.isna(_raw_details) else str(_raw_details)
                _raw_ttl = r.get("ttl_sec", 0)
                _db_ttl = 0.0 if pd.isna(_raw_ttl) else float(_raw_ttl)
                # Parse details for last_backup info
                parsed = _parse_details(_db_details)
                last_backup = parsed.get("latest", parsed.get("backup", ""))
            else:
                _db_status = "healthy"
                _db_details = ""
                _db_ttl = 0.0
                last_backup = ""
            st.markdown(
                db_status_card(_db_status, _db_details, _db_ttl, last_backup=last_backup),
                unsafe_allow_html=True,
            )

        # Network status card
        with infra_cols[1]:
            net_row = df_state[df_state["component"] == "network"]
            if not net_row.empty:
                r = net_row.iloc[0]
                _net_status = str(r.get("status", "healthy"))
                _raw_details = r.get("details", "")
                _net_details = "" if pd.isna(_raw_details) else str(_raw_details)
                _raw_ttl = r.get("ttl_sec", 0)
                _net_ttl = 0.0 if pd.isna(_raw_ttl) else float(_raw_ttl)
                # Parse details for latency/drop_rate
                parsed = _parse_details(_net_details)
                latency_ms = None
                drop_rate = None
                if "latency" in parsed:
                    try:
                        latency_ms = int(parsed["latency"].replace("ms", ""))
                    except ValueError:
                        pass
                if "drop" in parsed:
                    try:
                        drop_rate = float(parsed["drop"])
                    except ValueError:
                        pass
            else:
                _net_status = "healthy"
                _net_details = ""
                _net_ttl = 0.0
                latency_ms = None
                drop_rate = None
            st.markdown(
                network_status_card(
                    _net_status, _net_details, _net_ttl,
                    latency_ms=latency_ms, drop_rate=drop_rate
                ),
                unsafe_allow_html=True,
            )

        # Action summary card
        with infra_cols[2]:
            st.markdown(
                action_summary_card(
                    act_counts["total"],
                    act_counts["applied"],
                    act_counts["failed"],
                    act_counts["emitted"],
                ),
                unsafe_allow_html=True,
            )

        # Diagnostics row
        _state_mtime_inner = file_mtime_str(STATE_PATH)
        _state_rows_inner = file_row_count(STATE_PATH)
        _last_state_ts = "N/A"
        if "timestamp_utc" in df_state.columns and not df_state.empty:
            _last_ts = df_state["timestamp_utc"].iloc[0]
            if pd.notna(_last_ts):
                _last_state_ts = str(_last_ts)

        _diag_cols = st.columns(4)
        with _diag_cols[0]:
            st.caption(f"state.csv mtime: {_state_mtime_inner}")
        with _diag_cols[1]:
            st.caption(f"state.csv rows: {_state_rows_inner}")
        with _diag_cols[2]:
            st.caption(f"last_state_ts: {_last_state_ts}")
        with _diag_cols[3]:
            st.caption(
                f"actions: {act_counts['applied']} applied / "
                f"{act_counts['failed']} failed / "
                f"{act_counts['emitted']} pending"
            )
    else:
        st.markdown(
            '<div class="no-data-box">'
            "<strong>Infrastructure Status</strong><br>"
            "State not available yet. Waiting for live data..."
            "</div>",
            unsafe_allow_html=True,
        )

    # -- CHARTS: availability + downtime --------------------------------------
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

    # -- CHART: incidents per minute ------------------------------------------
    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

    if df_incidents is not None and not df_incidents.empty:
        fig = incidents_per_minute(df_incidents, tz="UTC")
        if fig is not None:
            st.plotly_chart(
                fig,
                width="stretch",
                config=CHART_CONFIG,
                key="chart_ipm",
            )
            st.caption(f"Incident rows: {len(df_incidents)} | Time axis: UTC")
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

    # -- INCIDENT TABLE -------------------------------------------------------
    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
    st.markdown('<p class="section-label">Incident Table</p>', unsafe_allow_html=True)

    if df_incidents is not None:
        render_incident_table(df_incidents)
    else:
        st.info("No incidents data available.")

    # -- ACTIONS TIMELINE -----------------------------------------------------
    st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
    st.markdown('<p class="section-label">Actions Timeline (Closed-Loop)</p>', unsafe_allow_html=True)

    df_actions = load_actions()
    if df_actions is not None and not df_actions.empty:
        # Chart: actions per minute
        fig_apm = actions_per_minute(df_actions, tz="UTC")
        if fig_apm is not None:
            st.plotly_chart(
                fig_apm,
                width="stretch",
                config=CHART_CONFIG,
                key="chart_apm",
            )

        # Table: last 100 actions
        _action_cols = [
            c for c in ["ts_utc", "action", "target_component", "target_id",
                        "reason", "correlation_id", "status"]
            if c in df_actions.columns
        ]
        _df_display = (
            df_actions[_action_cols].sort_values("ts_utc", ascending=False).head(100)
            if "ts_utc" in df_actions.columns
            else df_actions[_action_cols].head(100)
        )
        st.dataframe(
            _df_display,
            use_container_width=True,
            height=300,
        )

        _act_counts_disp = _action_counts(df_actions)
        st.caption(
            f"Actions: {_act_counts_disp['total']} total | "
            f"{_act_counts_disp['applied']} applied | "
            f"{_act_counts_disp['failed']} failed | "
            f"{_act_counts_disp['emitted']} pending"
        )
    else:
        st.markdown(
            '<div class="no-data-box">'
            "<strong>Actions Timeline</strong><br>"
            "No actions emitted yet. Waiting for closed-loop response..."
            "</div>",
            unsafe_allow_html=True,
        )

    # -- DIAGNOSTICS ----------------------------------------------------------
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

        _act_mtime = file_mtime_str(ACTIONS_PATH)
        _act_size = file_size(ACTIONS_PATH)
        _act_rows = file_row_count(ACTIONS_PATH)

        _state_mtime = file_mtime_str(STATE_PATH)
        _state_size = file_size(STATE_PATH)
        _state_rows = file_row_count(STATE_PATH)

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
| **actions.csv mtime** | {_act_mtime} |
| **actions.csv size** | {_act_size} bytes |
| **actions.csv rows** | {_act_rows} |
| **state.csv mtime** | {_state_mtime} |
| **state.csv size** | {_state_size} bytes |
| **state.csv rows** | {_state_rows} |
""",
        )


# -- invoke the fragment ------------------------------------------------------

_live_data_section()
