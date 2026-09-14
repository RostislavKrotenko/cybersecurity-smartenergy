"""Звітування: запис CSV, TXT, HTML, PNG."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from src.analyzer.metrics import PolicyMetrics
from src.contracts.incident import Incident
from src.shared.file_utils import atomic_write as _atomic_write

log = logging.getLogger(__name__)


def write_results_csv(
    metrics_list: list[PolicyMetrics],
    path: str,
) -> None:
    lines = [PolicyMetrics.csv_header()]
    for m in metrics_list:
        lines.append(m.to_csv_row())
    _atomic_write(path, "\n".join(lines) + "\n")
    log.info("Записано results → %s (%d політик)", path, len(metrics_list))


def write_incidents_csv(
    incidents: list[Incident],
    path: str,
) -> None:
    lines = [Incident.csv_header()]
    for inc in incidents:
        lines.append(inc.to_csv_row())
    _atomic_write(path, "\n".join(lines) + "\n")
    log.info("Записано incidents → %s (%d рядків)", path, len(incidents))


def write_report_txt(
    metrics_list: list[PolicyMetrics],
    all_incidents: list[Incident],
    control_ranking: list[dict[str, Any]],
    path: str,
    *,
    actions_count: int = 0,
) -> None:
    """Генерує текстовий звіт."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []

    lines.append("=" * 60)
    lines.append("  Звіт SmartEnergy про кіберстійкість")
    lines.append("=" * 60)
    lines.append("")

    for m in metrics_list:
        lines.append(f"--- Політика: {m.policy} ---")
        lines.append(f"  Доступність:      {m.availability_pct:.2f}%")
        lines.append(f"  Простій:          {m.total_downtime_hr:.4f} год")
        lines.append(f"  Середній MTTD:    {m.mean_mttd_min:.2f} хв")
        lines.append(f"  Середній MTTR:    {m.mean_mttr_min:.2f} хв")
        lines.append(f"  Інцидентів разом: {m.incidents_total}")
        sev_str = ", ".join(f"{k}={v}" for k, v in sorted(m.incidents_by_severity.items()))
        lines.append(f"  За критичністю:   {sev_str}")
        thr_str = ", ".join(f"{k}={v}" for k, v in sorted(m.incidents_by_threat.items()))
        lines.append(f"  За типом загрози: {thr_str}")
        lines.append("")

    lines.append("--- Порівняння ---")
    if metrics_list:
        best_avail = max(metrics_list, key=lambda m: m.availability_pct)
        worst_avail = min(metrics_list, key=lambda m: m.availability_pct)
        lines.append(
            f"  Найкраща доступність: {best_avail.policy} ({best_avail.availability_pct:.2f}%)"
        )
        lines.append(
            f"  Найгірша доступність: {worst_avail.policy} ({worst_avail.availability_pct:.2f}%)"
        )

        if any(m.mean_mttr_min > 0 for m in metrics_list):
            candidates = [m for m in metrics_list if m.mean_mttr_min > 0]
            best_mttr = min(candidates, key=lambda m: m.mean_mttr_min)
            worst_mttr = max(metrics_list, key=lambda m: m.mean_mttr_min)
            lines.append(
                f"  Найкращий MTTR:       {best_mttr.policy} ({best_mttr.mean_mttr_min:.2f} хв)"
            )
            lines.append(
                f"  Найгірший MTTR:       {worst_mttr.policy} ({worst_mttr.mean_mttr_min:.2f} хв)"
            )
    lines.append("")

    lines.append("--- Топ-3 найефективніших набори контролів ---")
    for i, cr in enumerate(control_ranking[:3], 1):
        lines.append(
            f"  {i}. {cr['policy']} "
            f"(effectiveness={cr['effectiveness']:.3f}, "
            f"MTTD×{cr['avg_mttd_mult']:.2f}, MTTR×{cr['avg_mttr_mult']:.2f})"
        )
        lines.append(f"     Контролі: {', '.join(cr['enabled_controls'])}")
    lines.append("")

    if actions_count > 0:
        lines.append("--- Closed-loop реагування ---")
        lines.append(f"  Випущено дій:     {actions_count}")
        lines.append("")

    lines.append("=" * 60)

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log.info("Записано звіт → %s", path)


def write_report_html(
    metrics_list: list[PolicyMetrics],
    all_incidents: list[Incident],
    control_ranking: list[dict[str, Any]],
    path: str,
) -> None:
    """Генерує самодостатній HTML-звіт."""
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
    for inc in all_incidents[:50]:
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
<title>Звіт SmartEnergy про кіберстійкість</title>
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
<h1>Звіт SmartEnergy про кіберстійкість</h1>
<h2>Порівняння політик</h2>
<table><thead><tr>
  <th>Політика</th><th>Доступність</th><th>Простій</th>
  <th>MTTD (хв)</th><th>MTTR (хв)</th><th>Інциденти</th>
</tr></thead><tbody>{rows_html}</tbody></table>
<h2>Топ-3 найефективніших набори контролів</h2>
<table><thead><tr>
  <th>#</th><th>Політика</th><th>Ефективність</th>
  <th>Множник MTTD</th><th>Множник MTTR</th><th>Контролі</th>
</tr></thead><tbody>{ctrl_rows}</tbody></table>
<h2>Інциденти (топ 50)</h2>
<table><thead><tr>
  <th>ID</th><th>Політика</th><th>Загроза</th><th>Критичність</th>
  <th>Компонент</th><th>MTTD(с)</th><th>MTTR(с)</th><th>Вплив</th>
</tr></thead><tbody>{inc_rows}</tbody></table>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    log.info("Записано HTML-звіт → %s", path)


def write_plots(
    metrics_list: list[PolicyMetrics],
    out_dir: str,
) -> None:
    """Генерує PNG-графіки в out_dir/plots/."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        log.warning("matplotlib не встановлено — графіки пропущено")
        return

    plots_dir = Path(out_dir) / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    policies = [m.policy for m in metrics_list]
    colors = ["#e74c3c", "#f39c12", "#27ae60"][: len(policies)]

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
    ax.set_ylabel("Доступність (%)")
    ax.set_title("Доступність системи за політиками")
    ax.set_ylim(min(avail) - 2 if min(avail) > 2 else 0, 101)
    fig.tight_layout()
    fig.savefig(str(plots_dir / "availability.png"), dpi=150)
    plt.close(fig)
    log.info("Записано plots/availability.png")

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
    ax.set_ylabel("Загальний простій (години)")
    ax.set_title("Загальний простій за політиками")
    fig.tight_layout()
    fig.savefig(str(plots_dir / "downtime.png"), dpi=150)
    plt.close(fig)
    log.info("Записано plots/downtime.png")

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
    ax.set_ylabel("Хвилини")
    ax.set_title("Середні MTTD і MTTR за політиками")
    ax.legend()
    fig.tight_layout()
    fig.savefig(str(plots_dir / "mttd_mttr.png"), dpi=150)
    plt.close(fig)
    log.info("Записано plots/mttd_mttr.png")
