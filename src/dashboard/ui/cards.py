"""Builders for HTML KPI cards."""

from __future__ import annotations

# -- canonical policy colours & display names ---------------------------------

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
    """Build one KPI card for a security policy."""
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


# -- component status colours ------------------------------------------------

_STATUS_COLORS: dict[str, str] = {
    "healthy": "#22c55e",
    "rate_limited": "#f59e0b",
    "isolated": "#ef4444",
    "blocking": "#f97316",
    "restoring": "#8b5cf6",
    "corrupted": "#dc2626",
    "degraded": "#eab308",
    "restored": "#22c55e",
    "disconnected": "#dc2626",
    "reset": "#22c55e",
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


# -- dedicated DB status card -------------------------------------------------

_DB_STATUS_COLORS: dict[str, str] = {
    "healthy": "#22c55e",
    "corrupted": "#dc2626",
    "restoring": "#8b5cf6",
    "restored": "#22c55e",
}

_DB_STATUS_ICONS: dict[str, str] = {
    "healthy": "[OK]",
    "corrupted": "[!!]",
    "restoring": "[..]",
    "restored": "[OK]",
}


def db_status_card(
    status: str,
    details: str,
    ttl_sec: float,
    last_backup: str = "",
    row_count: int | None = None,
) -> str:
    """Build a detailed Database status card."""
    status = (status or "").strip().lower() or "healthy"
    color = _DB_STATUS_COLORS.get(status, "#6b7280")
    icon = _DB_STATUS_ICONS.get(status, "")
    status_display = f"{icon} {status.upper()}"

    # Clean details
    if not details or details in ("nan", "NaN", "None", "none"):
        details = ""

    # Build details section
    detail_lines = []
    if details:
        detail_lines.append(details)
    if last_backup:
        detail_lines.append(f"Last backup: {last_backup}")
    if row_count is not None:
        detail_lines.append(f"Rows: {row_count:,}")

    details_html = ""
    if detail_lines:
        details_html = "".join(
            f'<div class="policy-metric-row">'
            f'  <span class="policy-metric-item" style="font-size:0.85em">{line}</span>'
            f"</div>"
            for line in detail_lines
        )

    # TTL display (for restoring state)
    ttl_html = ""
    if ttl_sec > 0 and status == "restoring":
        m, s = divmod(int(ttl_sec), 60)
        ttl_str = f"{m}m {s}s" if m > 0 else f"{s}s"
        ttl_html = (
            f'<div class="policy-metric-row">'
            f'  <span class="policy-metric-item" style="color:#f59e0b">'
            f"    Restoring... {ttl_str}"
            f"  </span>"
            f"</div>"
        )

    return (
        f'<div class="policy-card" style="border-top:3px solid {color}">'
        f'  <div class="policy-card-header">Database (Postgres)</div>'
        f'  <div class="policy-card-body">'
        f'    <div class="policy-metric-main" style="color:{color};font-size:1.3em">'
        f"      {status_display}"
        f"    </div>"
        f"    {details_html}"
        f"    {ttl_html}"
        f"  </div>"
        f"</div>"
    )


# -- dedicated Network status card --------------------------------------------

_NET_STATUS_COLORS: dict[str, str] = {
    "healthy": "#22c55e",
    "degraded": "#eab308",
    "disconnected": "#dc2626",
    "reset": "#22c55e",
}

_NET_STATUS_ICONS: dict[str, str] = {
    "healthy": "[OK]",
    "degraded": "[!!]",
    "disconnected": "[X]",
    "reset": "[OK]",
}


def network_status_card(
    status: str,
    details: str,
    ttl_sec: float,
    latency_ms: int | None = None,
    drop_rate: float | None = None,
) -> str:
    """Build a detailed Network status card."""
    status = (status or "").strip().lower() or "healthy"
    color = _NET_STATUS_COLORS.get(status, "#6b7280")
    icon = _NET_STATUS_ICONS.get(status, "")
    status_display = f"{icon} {status.upper()}"

    # Clean details
    if not details or details in ("nan", "NaN", "None", "none"):
        details = ""

    # Build details section
    detail_lines = []
    if details:
        detail_lines.append(details)
    if latency_ms is not None and latency_ms > 0:
        detail_lines.append(f"Latency: {latency_ms}ms")
    if drop_rate is not None and drop_rate > 0:
        detail_lines.append(f"Drop rate: {drop_rate:.1%}")

    details_html = ""
    if detail_lines:
        details_html = "".join(
            f'<div class="policy-metric-row">'
            f'  <span class="policy-metric-item" style="font-size:0.85em">{line}</span>'
            f"</div>"
            for line in detail_lines
        )

    # TTL display (for degraded state)
    ttl_html = ""
    if ttl_sec > 0 and status == "degraded":
        m, s = divmod(int(ttl_sec), 60)
        ttl_str = f"{m}m {s}s" if m > 0 else f"{s}s"
        ttl_html = (
            f'<div class="policy-metric-row">'
            f'  <span class="policy-metric-item" style="color:#f59e0b">'
            f"    TTL: {ttl_str}"
            f"  </span>"
            f"</div>"
        )

    return (
        f'<div class="policy-card" style="border-top:3px solid {color}">'
        f'  <div class="policy-card-header">Network (Sim)</div>'
        f'  <div class="policy-card-body">'
        f'    <div class="policy-metric-main" style="color:{color};font-size:1.3em">'
        f"      {status_display}"
        f"    </div>"
        f"    {details_html}"
        f"    {ttl_html}"
        f"  </div>"
        f"</div>"
    )


# -- executor action summary card ---------------------------------------------

def action_summary_card(
    total: int,
    applied: int,
    failed: int,
    emitted: int,
) -> str:
    """Build HTML card for executor action status summary."""
    if total == 0:
        bar_html = '<div style="height:6px;background:#374151;border-radius:3px"></div>'
    else:
        pct_applied = (applied / total * 100) if total > 0 else 0
        pct_failed = (failed / total * 100) if total > 0 else 0
        pct_emitted = 100 - pct_applied - pct_failed
        bar_html = (
            '<div style="display:flex;height:6px;border-radius:3px;overflow:hidden;margin-top:4px">'
            f'<div style="width:{pct_applied:.0f}%;background:#22c55e"></div>'
            f'<div style="width:{pct_failed:.0f}%;background:#ef4444"></div>'
            f'<div style="width:{pct_emitted:.0f}%;background:#6b7280"></div>'
            "</div>"
        )

    return (
        '<div class="policy-card" style="border-top:3px solid #3b82f6">'
        '  <div class="policy-card-header">Executor Actions</div>'
        '  <div class="policy-card-body">'
        f'    <div class="policy-metric-main" style="color:#3b82f6;font-size:1.3em">'
        f"      {total} TOTAL"
        f"    </div>"
        f'    <div class="policy-metric-row">'
        f'      <span class="policy-metric-item" style="color:#22c55e">Applied: {applied}</span>'
        f'      <span class="policy-metric-item" style="color:#ef4444">Failed: {failed}</span>'
        f'      <span class="policy-metric-item" style="color:#6b7280">Pending: {emitted}</span>'
        f"    </div>"
        f"    {bar_html}"
        f"  </div>"
        f"</div>"
    )
