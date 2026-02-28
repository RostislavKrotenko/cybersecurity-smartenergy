"""Tests for src.analyzer.policy_engine — policy loading and modifier extraction."""

from __future__ import annotations

import pytest

from src.analyzer.policy_engine import (
    get_modifiers,
    get_policy_meta,
    list_policy_names,
    rank_controls,
)


@pytest.fixture
def policies_cfg():
    """Minimal policies config mirroring real structure."""
    return {
        "policies": {
            "minimal": {
                "name": "Minimal Security",
                "controls": {
                    "mfa": {"enabled": False},
                    "rbac": {"enabled": False},
                    "monitoring": {"enabled": True},
                },
                "modifiers": {
                    "credential_attack": {
                        "mttd_multiplier": 1.5,
                        "mttr_multiplier": 1.5,
                        "threshold_multiplier": 1.0,
                        "impact_multiplier": 1.2,
                    },
                    "availability_attack": {
                        "mttd_multiplier": 1.3,
                        "mttr_multiplier": 1.4,
                        "threshold_multiplier": 1.0,
                        "impact_multiplier": 1.1,
                    },
                },
            },
            "baseline": {
                "name": "Baseline Security",
                "controls": {
                    "mfa": {"enabled": True},
                    "rbac": {"enabled": True},
                    "monitoring": {"enabled": True},
                },
                "modifiers": {
                    "credential_attack": {
                        "mttd_multiplier": 1.0,
                        "mttr_multiplier": 1.0,
                        "threshold_multiplier": 1.0,
                        "impact_multiplier": 1.0,
                    },
                    "availability_attack": {
                        "mttd_multiplier": 1.0,
                        "mttr_multiplier": 1.0,
                        "threshold_multiplier": 1.0,
                        "impact_multiplier": 1.0,
                    },
                },
            },
            "standard": {
                "name": "Standard Security",
                "controls": {
                    "mfa": {"enabled": True},
                    "rbac": {"enabled": True},
                    "monitoring": {"enabled": True},
                    "rate_limiting": {"enabled": True},
                },
                "modifiers": {
                    "credential_attack": {
                        "mttd_multiplier": 0.5,
                        "mttr_multiplier": 0.5,
                        "threshold_multiplier": 0.8,
                        "impact_multiplier": 0.6,
                    },
                    "availability_attack": {
                        "mttd_multiplier": 0.6,
                        "mttr_multiplier": 0.6,
                        "threshold_multiplier": 0.7,
                        "impact_multiplier": 0.5,
                    },
                },
            },
        }
    }


class TestGetModifiers:
    def test_returns_modifiers_for_known_policy(self, policies_cfg):
        mods = get_modifiers(policies_cfg, "baseline")
        assert "credential_attack" in mods
        assert mods["credential_attack"]["mttd_multiplier"] == 1.0

    def test_unknown_policy_returns_empty(self, policies_cfg):
        mods = get_modifiers(policies_cfg, "nonexistent")
        assert mods == {}

    def test_minimal_has_higher_multipliers(self, policies_cfg):
        mods = get_modifiers(policies_cfg, "minimal")
        assert mods["credential_attack"]["mttd_multiplier"] > 1.0

    def test_standard_has_lower_multipliers(self, policies_cfg):
        mods = get_modifiers(policies_cfg, "standard")
        assert mods["credential_attack"]["mttd_multiplier"] < 1.0


class TestGetPolicyMeta:
    def test_returns_full_dict(self, policies_cfg):
        meta = get_policy_meta(policies_cfg, "baseline")
        assert meta["name"] == "Baseline Security"
        assert "controls" in meta
        assert "modifiers" in meta

    def test_unknown_policy_empty(self, policies_cfg):
        meta = get_policy_meta(policies_cfg, "nonexistent")
        assert meta == {}


class TestListPolicyNames:
    def test_lists_all(self, policies_cfg):
        names = list_policy_names(policies_cfg)
        assert set(names) == {"minimal", "baseline", "standard"}

    def test_empty_config(self):
        assert list_policy_names({}) == []


class TestRankControls:
    def test_standard_ranked_higher_than_minimal(self, policies_cfg):
        ranking = rank_controls(policies_cfg, ["minimal", "baseline", "standard"])
        policies_ordered = [r["policy"] for r in ranking]
        # Standard should rank higher (more effective) than minimal
        assert policies_ordered.index("standard") < policies_ordered.index("minimal")

    def test_effectiveness_values(self, policies_cfg):
        ranking = rank_controls(policies_cfg, ["baseline"])
        # baseline: avg_mttd=1.0, avg_mttr=1.0 → effectiveness = 1 - (1+1)/2 = 0.0
        assert ranking[0]["effectiveness"] == 0.0

    def test_enabled_controls_counted(self, policies_cfg):
        ranking = rank_controls(policies_cfg, ["standard"])
        assert len(ranking[0]["enabled_controls"]) >= 3
