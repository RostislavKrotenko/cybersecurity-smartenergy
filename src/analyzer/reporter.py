"""Звітування: запис CSV, TXT, HTML, PNG."""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from src.analyzer.metrics import PolicyMetrics
from src.contracts.incident import Incident

log = logging.getLogger(__name__)


def _atomic_write(path: str, content: str) -> None:
    """Атомарно записує content у файл path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=str(target.parent),
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        # Clean up temp file on any failure
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ═══════════════════════════════════════════════════════════════════════════
#  CSV writers
# ═══════════════════════════════════════════════════════════════════════════


def write_results_csv(
    metrics_list: list[PolicyMetrics],
    path: str,
) -> None:
    lines = [PolicyMetrics.csv_header()]
    for m in metrics_list:
        lines.append(m.to_csv_row())
    _atomic_write(path, "\n".join(lines) + "\n")
    log.info("Wrote results → %s (%d policies)", path, len(metrics_list))


def write_incidents_csv(
    incidents: list[Incident],
    path: str,
) -> None:
    lines = [Incident.csv_header()]
    for inc in incidents:
        lines.append(inc.to_csv_row())
    _atomic_write(path, "\n".join(lines) + "\n")
    log.info("Wrote incidents → %s (%d rows)", path, len(incidents))


# ═══════════════════════════════════════════════════════════════════════════
#  TXT report
# ═══════════════════════════════════════════════════════════════════════════


def write_report_txt(
    metrics_list: list[PolicyMetrics],
    all_incidents: list[Incident],
    control_ranking: list[dict[str, Any]],
    path: str,
) -> None:
    """Генерує текстовий звіт."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []

    lines.append("=" * 60)
    lines.append("  SmartEnergy Cyber-Resilience Report")
    lines.append("=" * 60)
    lines.append("")

    for m in metrics_list:
        lines.append(f"--- Policy: {m.policy} ---")
        lines.append(f"  Availability:     {m.availability_pct:.2f}%")
        lines.append(f"  Downtime:         {m.total_downtime_hr:.4f} hr")
        lines.append(f"  Mean MTTD:        {m.mean_mttd_min:.2f} min")
        lines.append(f"  Mean MTTR:        {m.mean_mttr_min:.2f} min")
        lines.append(f"  Incidents total:  {m.incidents_total}")
        sev_str = ", ".join(f"{k}={v}" for k, v in sorted(m.incidents_by_severity.items()))
        lines.append(f"  By severity:      {sev_str}")
        thr_str = ", ".join(f"{k}={v}" for k, v in sorted(m.incidents_by_threat.items()))
        lines.append(f"  By threat type:   {thr_str}")
        lines.append("")

    # Comparison
    lines.append("--- Comparison ---")
    if metrics_list:
        best_avail = max(metrics_list, key=lambda m: m.availability_pct)
        worst_avail = min(metrics_list, key=lambda m: m.availability_pct)
        lines.append(
            f"  Best availability:  {best_avail.policy} ({best_avail.availability_pct:.2f}%)"
        )
        lines.append(
            f"  Worst availability: {worst_avail.policy} ({worst_avail.availability_pct:.2f}%)"
        )

        if any(m.mean_mttr_min > 0 for m in metrics_list):
            candidates = [m for m in metrics_list if m.mean_mttr_min > 0]
            best_mttr = min(candidates, key=lambda m: m.mean_mttr_min)
            worst_mttr = max(metrics_list, key=lambda m: m.mean_mttr_min)
            lines.append(
                f"  Best MTTR:          {best_mttr.policy} ({best_mttr.mean_mttr_min:.2f} min)"
            )
            lines.append(
                f"  Worst MTTR:         {worst_mttr.policy} ({worst_mttr.mean_mttr_min:.2f} min)"
            )
    lines.append("")

    # Top-3 effective controls
    lines.append("--- Top 3 Most Effective Control Sets ---")
    for i, cr in enumerate(control_ranking[:3], 1):
        lines.append(
            f"  {i}. {cr['policy']} "
            f"(effectiveness={cr['effectiveness']:.3f}, "
            f"MTTD×{cr['avg_mttd_mult']:.2f}, MTTR×{cr['avg_mttr_mult']:.2f})"
        )
        lines.append(f"     Controls: {', '.join(cr['enabled_controls'])}")
    lines.append("")
    lines.append("=" * 60)

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log.info("Wrote report → %s", path)


# ═══════════════════════════════════════════════════════════════════════════
#  HTML report (optional)
# ═══════════════════════════════════════════════════════════════════════════


def write_report_html(
    metrics_list: list[PolicyMetrics],
    all_incidents: list[Incident],
    control_ranking: list[dict[str, Any]],
    path: str,
) -> None:
    """Generate a self-contained HTML report."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)

    rows_html = ""
    for m in metrics_list:
        rows_html += (
            f"<tr><td>{m.policy}</td><td>{m.availability_pct:.2f}%</td>"
            f"<td>{m.total_downtime_hr:.4f}h</td>"
            f"<td>{m.mean_mttd_min:.2f}</td><td>{m.mean_mttr_min:.2f}</td>"
            f"<td>{m.incidents_total}</td></tr>\n"
        )

    inc_rows = ""
    for inc in all_incidents[:50]:  # limit to 50 for HTML
        inc_rows += (
            f"<tr><td>{inc.incident_id}</td><td>{inc.policy}</td>"
            f"<td>{inc.threat_type}</td><td>{inc.severity}</td>"
            f"<td>{inc.component}</td><td>{inc.mttd_sec:.1f}</td>"
            f"<td>{inc.mttr_sec:.1f}</td><td>{inc.impact_score:.3f}</td></tr>\n"
        )

    ctrl_rows = ""
    for i, cr in enumerate(control_ranking[:3], 1):
        ctrl_rows += (
            f"<tr><td>{i}</td><td>{cr['policy']}</td>"
            f"<td>{cr['effectiveness']:.3f}</td>"
            f"<td>{cr['avg_mttd_mult']:.2f}</td>"
            f"<td>{cr['avg_mttr_mult']:.2f}</td>"
            f"<td>{', '.join(cr['enabled_controls'])}</td></tr>\n"
        )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>SmartEnergy Cyber-Resilience Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 2em; background: #f8f9fa; }}
  h1 {{ color: #2c3e50; }} h2 {{ color: #34495e; margin-top: 2em; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
  th {{ background: #2c3e50; color: white; }}
  tr:nth-child(even) {{ background: #f2f2f2; }}
  .metric {{ display: inline-block; background: #fff; border: 1px solid #ddd;
             border-radius: 8px; padding: 1em 2em; margin: 0.5em; text-align: center; }}
  .metric .value {{ font-size: 2em; font-weight: bold; color: #2980b9; }}
  .metric .label {{ color: #7f8c8d; }}
</style></head><body>
<h1>SmartEnergy Cyber-Resilience Report</h1>
<h2>Policy Comparison</h2>
<table><thead><tr>
  <th>Policy</th><th>Availability</th><th>Downtime</th>
  <th>MTTD (min)</th><th>MTTR (min)</th><th>Incidents</th>
</tr></thead><tbody>{rows_html}</tbody></table>
<h2>Top 3 Most Effective Control Sets</h2>
<table><thead><tr>
  <th>#</th><th>Policy</th><th>Effectiveness</th>
  <th>MTTD mult</th><th>MTTR mult</th><th>Controls</th>
</tr></thead><tbody>{ctrl_rows}</tbody></table>
<h2>Incidents (top 50)</h2>
<table><thead><tr>
  <th>ID</th><th>Policy</th><th>Threat</th><th>Severity</th>
  <th>Component</th><th>MTTD(s)</th><th>MTTR(s)</th><th>Impact</th>
</tr></thead><tbody>{inc_rows}</tbody></table>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    log.info("Wrote HTML report → %s", path)


# ═══════════════════════════════════════════════════════════════════════════
#  Plots (matplotlib)
# ═══════════════════════════════════════════════════════════════════════════


def write_plots(
    metrics_list: list[PolicyMetrics],
    out_dir: str,
) -> None:
    """Generate PNG charts into out_dir/plots/."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        log.warning("matplotlib not installed — skipping plots")
        return

    plots_dir = Path(out_dir) / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    policies = [m.policy for m in metrics_list]
    colors = ["#e74c3c", "#f39c12", "#27ae60"][: len(policies)]

    # ── 1. Availability bar chart ────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    avail = [m.availability_pct for m in metrics_list]
    bars = ax.bar(policies, avail, color=colors, edgecolor="black", linewidth=0.5)
    for bar, v in zip(bars, avail):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.1,
            f"{v:.2f}%",
            ha="center",
            va="bottom",
            fontweight="bold",
        )
    ax.set_ylabel("Availability (%)")
    ax.set_title("System Availability by Policy")
    ax.set_ylim(min(avail) - 2 if min(avail) > 2 else 0, 101)
    fig.tight_layout()
    fig.savefig(str(plots_dir / "availability.png"), dpi=150)
    plt.close(fig)
    log.info("Wrote plots/availability.png")

    # ── 2. Downtime bar chart ────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    dt = [m.total_downtime_hr for m in metrics_list]
    bars = ax.bar(policies, dt, color=colors, edgecolor="black", linewidth=0.5)
    for bar, v in zip(bars, dt):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.001,
            f"{v:.4f}h",
            ha="center",
            va="bottom",
            fontweight="bold",
        )
    ax.set_ylabel("Total Downtime (hours)")
    ax.set_title("Total Downtime by Policy")
    fig.tight_layout()
    fig.savefig(str(plots_dir / "downtime.png"), dpi=150)
    plt.close(fig)
    log.info("Wrote plots/downtime.png")

    # ── 3. MTTD & MTTR grouped bar chart ────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    x = range(len(policies))
    w = 0.35
    mttd = [m.mean_mttd_min for m in metrics_list]
    mttr = [m.mean_mttr_min for m in metrics_list]
    bars1 = ax.bar(
        [i - w / 2 for i in x],
        mttd,
        w,
        label="MTTD (min)",
        color="#3498db",
        edgecolor="black",
        linewidth=0.5,
    )
    bars2 = ax.bar(
        [i + w / 2 for i in x],
        mttr,
        w,
        label="MTTR (min)",
        color="#e67e22",
        edgecolor="black",
        linewidth=0.5,
    )
    for bar, v in zip(bars1, mttd):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.05,
            f"{v:.1f}",
            ha="center",
            va="bottom",
            fontsize=9,
        )
    for bar, v in zip(bars2, mttr):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.05,
            f"{v:.1f}",
            ha="center",
            va="bottom",
            fontsize=9,
        )
    ax.set_xticks(list(x))
    ax.set_xticklabels(policies)
    ax.set_ylabel("Minutes")
    ax.set_title("Mean MTTD & MTTR by Policy")
    ax.legend()
    fig.tight_layout()
    fig.savefig(str(plots_dir / "mttd_mttr.png"), dpi=150)
    plt.close(fig)
    log.info("Wrote plots/mttd_mttr.png")
