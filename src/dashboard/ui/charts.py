"""Plotly chart builders — unified dark theme, consistent policy palette.

Every function returns a ``plotly.graph_objects.Figure`` ready for
``st.plotly_chart(fig, width="stretch", config=CHART_CONFIG)``.
"""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go

from src.dashboard.ui.cards import POLICY_COLORS

# ── chart config (hide toolbar by default) ──────────────────────────────────

CHART_CONFIG: dict = {"displayModeBar": False}

POLICY_ORDER: list[str] = ["baseline", "minimal", "standard"]

# ── shared layout ───────────────────────────────────────────────────────────

_FONT = dict(family="-apple-system, Segoe UI, Roboto, sans-serif", size=13, color="#c9d1d9")

_LAYOUT: dict = dict(
    template="plotly_dark",
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    margin=dict(l=48, r=16, t=44, b=36),
    font=_FONT,
    title=dict(font=dict(size=14, color="#e6edf3"), x=0, xanchor="left", y=0.98, yanchor="top"),
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(size=11)),
    bargap=0.35,
    height=340,
)

_GRID_COLOR = "rgba(128,128,128,0.10)"


def _base(**overrides: object) -> dict:
    merged = {**_LAYOUT}
    for k, v in overrides.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k] = {**merged[k], **v}
        else:
            merged[k] = v
    return merged


def _color(policy: str) -> str:
    return POLICY_COLORS.get(policy, "#888")


def _sort_policies(df: pd.DataFrame) -> pd.DataFrame:
    return df.sort_values(
        "policy",
        key=lambda s: s.map({p: i for i, p in enumerate(POLICY_ORDER)}),
    )


# ── availability bar ────────────────────────────────────────────────────────


def availability_bar(df: pd.DataFrame) -> go.Figure:
    df = _sort_policies(df)
    fig = go.Figure()
    for _, row in df.iterrows():
        p = row["policy"]
        fig.add_trace(go.Bar(
            x=[p.capitalize()],
            y=[row["availability_pct"]],
            marker_color=_color(p),
            marker_line_width=0,
            showlegend=False,
            hovertemplate="%{x}: %{y:.2f}%<extra></extra>",
            text=[f"{row['availability_pct']:.2f}%"],
            textposition="outside",
            textfont=dict(size=12, color="#e6edf3"),
        ))
    y_min = max(0, df["availability_pct"].min() - 5)
    fig.update_layout(**_base(
        title=dict(text="Availability by Security Policy"),
        yaxis=dict(range=[y_min, 102], title="", gridcolor=_GRID_COLOR, zeroline=False),
        xaxis=dict(title=""),
    ))
    return fig


# ── downtime bar ────────────────────────────────────────────────────────────


def downtime_bar(df: pd.DataFrame) -> go.Figure:
    df = _sort_policies(df)
    fig = go.Figure()
    for _, row in df.iterrows():
        p = row["policy"]
        fig.add_trace(go.Bar(
            x=[p.capitalize()],
            y=[row["total_downtime_hr"]],
            marker_color=_color(p),
            marker_line_width=0,
            showlegend=False,
            hovertemplate="%{x}: %{y:.2f} h<extra></extra>",
            text=[f"{row['total_downtime_hr']:.2f}"],
            textposition="outside",
            textfont=dict(size=12, color="#e6edf3"),
        ))
    fig.update_layout(**_base(
        title=dict(text="Downtime Comparison"),
        yaxis=dict(title="", gridcolor=_GRID_COLOR, zeroline=False),
        xaxis=dict(title=""),
    ))
    return fig
