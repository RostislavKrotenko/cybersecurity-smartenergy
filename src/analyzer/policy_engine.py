"""Policy Engine — load policy configs and apply multipliers.

Reads ``config/policies.yaml`` and provides per-threat_type multiplier
dicts that the Detector and Correlator use to adjust thresholds, windows,
MTTD, MTTR, and impact scoring.
"""

from __future__ import annotations

import logging
from typing import Any

from src.shared.config_loader import load_yaml

log = logging.getLogger(__name__)


def load_policies(config_dir: str) -> dict[str, Any]:
    """Load policies.yaml and return the full dict.

    Returns
    ───────
    { "policies": { "minimal": {...}, "baseline": {...}, "standard": {...} } }
    """
    path = f"{config_dir}/policies.yaml"
    cfg = load_yaml(path)
    names = list(cfg.get("policies", {}).keys())
    log.info("Loaded %d policies from %s: %s", len(names), path, ", ".join(names))
    return cfg


def get_modifiers(
    policies_cfg: dict[str, Any],
    policy_name: str,
) -> dict[str, dict[str, float]]:
    """Extract per-threat_type multipliers for a given policy.

    Returns
    ───────
    {
      "credential_attack": {"prob_multiplier": 1.0, "mttd_multiplier": 1.0, ...},
      "availability_attack": {...},
      ...
    }
    """
    policy = policies_cfg.get("policies", {}).get(policy_name)
    if policy is None:
        log.warning("Policy '%s' not found — using default multipliers (1.0)", policy_name)
        return {}
    return policy.get("modifiers", {})


def get_policy_meta(
    policies_cfg: dict[str, Any],
    policy_name: str,
) -> dict[str, Any]:
    """Return the full policy dict (name, description, controls, modifiers)."""
    return policies_cfg.get("policies", {}).get(policy_name, {})


def list_policy_names(policies_cfg: dict[str, Any]) -> list[str]:
    """Return names of all available policies."""
    return list(policies_cfg.get("policies", {}).keys())


def rank_controls(
    policies_cfg: dict[str, Any],
    policy_names: list[str],
) -> list[dict[str, Any]]:
    """Compare policies and return a ranked list of controls.

    For each control, compute a simple "effectiveness" estimate based on
    how much it reduces average mttd+mttr across threat_types.

    Returns a list sorted by effectiveness descending.
    """
    results: list[dict[str, Any]] = []

    for pname in policy_names:
        policy = policies_cfg.get("policies", {}).get(pname, {})
        controls = policy.get("controls", {})
        modifiers = policy.get("modifiers", {})

        # Average mttd+mttr reduction across all threat types
        mttd_vals = [m.get("mttd_multiplier", 1.0) for m in modifiers.values()]
        mttr_vals = [m.get("mttr_multiplier", 1.0) for m in modifiers.values()]
        avg_mttd = sum(mttd_vals) / len(mttd_vals) if mttd_vals else 1.0
        avg_mttr = sum(mttr_vals) / len(mttr_vals) if mttr_vals else 1.0

        enabled_controls = [
            c for c, v in controls.items() if isinstance(v, dict) and v.get("enabled")
        ]

        results.append(
            {
                "policy": pname,
                "enabled_controls": enabled_controls,
                "avg_mttd_mult": round(avg_mttd, 3),
                "avg_mttr_mult": round(avg_mttr, 3),
                "effectiveness": round(1.0 - (avg_mttd + avg_mttr) / 2, 3),
            }
        )

    results.sort(key=lambda r: r["effectiveness"], reverse=True)
    return results
