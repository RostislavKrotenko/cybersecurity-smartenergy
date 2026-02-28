"""SmartEnergy Security Dashboard — Streamlit entrypoint.

Launch
------
    streamlit run src/dashboard/app.py
"""

from __future__ import annotations

from pathlib import Path

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
    filter_incidents,
    filter_results,
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

# ── load raw data ───────────────────────────────────────────────────────────

df_results_raw = load_results()
df_incidents_raw = load_incidents()

# ── sidebar (needs incidents for dynamic filter options) ────────────────────

sidebar = render_sidebar(df_incidents_raw)

# ── header ──────────────────────────────────────────────────────────────────

render_header()

# ── guard: no data yet ──────────────────────────────────────────────────────

if df_results_raw is None:
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
    st.stop()

# ── apply filters ───────────────────────────────────────────────────────────

df_results = filter_results(df_results_raw, sidebar.policies)

df_incidents = (
    filter_incidents(
        df_incidents_raw,
        policies=sidebar.policies,
        severities=sidebar.severities,
        threat_types=sidebar.threat_types,
        components=sidebar.components,
        horizon_days=sidebar.horizon_days,
    )
    if df_incidents_raw is not None
    else None
)

# ═════════════════════════════════════════════════════════════════════════════
#   KPI CARDS — one per policy, in a single row
# ═════════════════════════════════════════════════════════════════════════════

_POLICY_ORDER = ["baseline", "minimal", "standard"]
ordered = df_results.set_index("policy").reindex(
    [p for p in _POLICY_ORDER if p in df_results["policy"].values]
)

if not ordered.empty:
    cols = st.columns(len(ordered))
    for col, (policy, row) in zip(cols, ordered.iterrows()):
        with col:
            st.markdown(
                policy_kpi_card(
                    policy=policy,
                    availability=row["availability_pct"],
                    downtime_hr=row["total_downtime_hr"],
                    mttd_min=row["mean_mttd_min"],
                    mttr_min=row["mean_mttr_min"],
                ),
                unsafe_allow_html=True,
            )

# ═════════════════════════════════════════════════════════════════════════════
#   CHARTS — availability + downtime side-by-side
# ═════════════════════════════════════════════════════════════════════════════

st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

c1, c2 = st.columns(2)
with c1:
    st.plotly_chart(
        availability_bar(df_results),
        width="stretch",
        config=CHART_CONFIG,
    )
with c2:
    st.plotly_chart(
        downtime_bar(df_results),
        width="stretch",
        config=CHART_CONFIG,
    )

# ═════════════════════════════════════════════════════════════════════════════
#   CHART — incidents per minute
# ═════════════════════════════════════════════════════════════════════════════

st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)

_ipm_fig = incidents_per_minute(df_incidents) if df_incidents is not None else None
if _ipm_fig is not None:
    st.plotly_chart(_ipm_fig, use_container_width=True, config=CHART_CONFIG)
else:
    st.markdown(
        '<div class="no-data-box">'
        "<strong>Incidents per Minute</strong><br>Not enough data yet."
        "</div>",
        unsafe_allow_html=True,
    )

# ═════════════════════════════════════════════════════════════════════════════
#   INCIDENT TABLE
# ═════════════════════════════════════════════════════════════════════════════

st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
st.markdown('<p class="section-label">Incident Table</p>', unsafe_allow_html=True)

if df_incidents is not None:
    render_incident_table(df_incidents)
else:
    st.info("No incidents data available.")
