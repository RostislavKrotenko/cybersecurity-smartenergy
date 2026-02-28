"""Білдери HTML KPI карток."""

from __future__ import annotations

# ── canonical policy colours & display names ────────────────────────────────

POLICY_COLORS: dict[str, str] = {
    "baseline": "#f59e0b",
    "minimal": "#ef4444",
    "standard": "#22c55e",
}

POLICY_DISPLAY: dict[str, str] = {
    "baseline": "Baseline Policy",
    "minimal": "Minimal Security",
    "standard": "Standard Security",
}

POLICY_ACCENT_CLASS: dict[str, str] = {
    "baseline": "card-accent-baseline",
    "minimal": "card-accent-minimal",
    "standard": "card-accent-standard",
}


def policy_kpi_card(
    policy: str,
    availability: float,
    downtime_hr: float,
    mttd_min: float,
    mttr_min: float,
) -> str:
    """Побудова однієї KPI картки політики."""
    accent_cls = POLICY_ACCENT_CLASS.get(policy, "")
    title = POLICY_DISPLAY.get(policy, policy.capitalize())
    return (
        f'<div class="policy-card {accent_cls}">'
        f'  <div class="policy-card-header">{title}</div>'
        f'  <div class="policy-card-body">'
        f'    <div class="policy-metric-main">{availability:.2f}%</div>'
        f'    <div class="policy-metric-label">Availability</div>'
        f'    <div class="policy-metric-row">'
        f'      <span class="policy-metric-item">Downtime: {downtime_hr:.2f} h</span>'
        f"    </div>"
        f'    <div class="policy-metric-row">'
        f'      <span class="policy-metric-item">Mean MTTD: {mttd_min:.0f} min</span>'
        f'      <span class="policy-metric-item">Mean MTTR: {mttr_min:.0f} min</span>'
        f"    </div>"
        f"  </div>"
        f"</div>"
    )
