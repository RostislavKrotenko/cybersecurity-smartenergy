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


# ── component status colours ─────────────────────────────────────────────

_STATUS_COLORS: dict[str, str] = {
    "healthy": "#22c55e",
    "rate_limited": "#f59e0b",
    "isolated": "#ef4444",
    "blocking": "#f97316",
    "restoring": "#8b5cf6",
    "corrupted": "#dc2626",
    "degraded": "#eab308",
    "restored": "#22c55e",
}

_COMPONENT_LABELS: dict[str, str] = {
    "gateway": "Gateway",
    "api": "API",
    "auth": "Auth",
    "db": "Database",
    "network": "Network",
}


def component_status_card(
    component: str,
    status: str,
    details: str,
    ttl_sec: float,
) -> str:
    """Build an HTML card for one infrastructure component's live status."""
    label = _COMPONENT_LABELS.get(component, component.upper())
    # Normalise status: strip whitespace, lowercase, fallback to healthy
    status = (status or "").strip().lower() or "healthy"
    color = _STATUS_COLORS.get(status, "#6b7280")
    status_display = status.upper().replace("_", " ")

    # Clean details: pandas NaN reads as "nan", empty strings are useless
    if not details or details in ("nan", "NaN", "None", "none"):
        details = ""

    ttl_html = ""
    if ttl_sec > 0:
        m, s = divmod(int(ttl_sec), 60)
        if m > 0:
            ttl_html = (
                f'<div class="policy-metric-row">'
                f'  <span class="policy-metric-item" style="color:#f59e0b">'
                f"    TTL: {m}m {s}s"
                f"  </span>"
                f"</div>"
            )
        else:
            ttl_html = (
                f'<div class="policy-metric-row">'
                f'  <span class="policy-metric-item" style="color:#f59e0b">'
                f"    TTL: {s}s"
                f"  </span>"
                f"</div>"
            )

    details_html = ""
    if details:
        details_html = (
            f'<div class="policy-metric-row">'
            f'  <span class="policy-metric-item">{details}</span>'
            f"</div>"
        )

    return (
        f'<div class="policy-card" style="border-top:3px solid {color}">'
        f'  <div class="policy-card-header">{label}</div>'
        f'  <div class="policy-card-body">'
        f'    <div class="policy-metric-main" style="color:{color};font-size:1.3em">'
        f"      {status_display}"
        f"    </div>"
        f"    {details_html}"
        f"    {ttl_html}"
        f"  </div>"
        f"</div>"
    )
