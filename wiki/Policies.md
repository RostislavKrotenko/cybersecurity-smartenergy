# Policies

Security policies are defined in `config/policies.yaml`. Each policy represents a different level of protection and is evaluated independently by the analyzer to compare resilience outcomes.

## Available policies

| Policy | Description |
|--------|-------------|
| `minimal` | Logging and basic monitoring only. No MFA, rate limiting, segmentation, or backup. Worst-case scenario. |
| `baseline` | Moderate protection: MFA enabled (soft thresholds), partial rate limiting, basic RBAC, infrequent backups, two-zone segmentation. |
| `standard` | Full protection: strict MFA, strict RBAC, automatic rate limiting with IP blocking, near-real-time monitoring, frequent backups with fast rollback, three-zone segmentation with micro-segmentation. |

## Modelling note

All security controls listed in the policies -- including MFA, RBAC, rate limiting, network segmentation, and backup -- are **modelled through numerical parameters** (multipliers and coefficients). The prototype does not integrate with a real IAM provider, MFA service, or firewall appliance. Instead, each control's presence or absence adjusts the following multipliers per threat type:

| Multiplier | Effect |
|------------|--------|
| `mttd_multiplier` | Scales the base Mean-Time-To-Detect. Lower value = faster detection. |
| `mttr_multiplier` | Scales the base Mean-Time-To-Recover. Lower value = faster recovery. |
| `prob_multiplier` | Scales the probability of a successful attack. Lower value = harder to exploit. |
| `impact_multiplier` | Scales the blast radius / damage score. Lower value = less damage on success. |
| `threshold_multiplier` | Scales detection rule thresholds. Lower value = more sensitive rules. |
| `window_multiplier` | Scales detection rule time windows. Higher value = broader event aggregation. |

For example, in the `minimal` policy the `credential_attack.mttd_multiplier` is `2.5`, meaning brute-force detection takes 2.5x longer than baseline. In the `standard` policy the same multiplier is `0.3`, reflecting near-real-time detection enabled by strict MFA and alerting.

## Policy structure

Each policy entry in `policies.yaml` contains three sections:

### controls

A dictionary of named controls with `enabled` flag and optional parameters. These describe **what** is active in the policy. The analyzer does not enforce controls directly; they serve as documentation and input for the multiplier values.

Example (standard):

```yaml
mfa:
  enabled: true
  max_attempts: 3
  lockout_sec: 600
```

### modifiers

A dictionary keyed by `threat_type` (`credential_attack`, `availability_attack`, `integrity_attack`, `outage`). Each entry contains the six multipliers listed above.

### How the analyzer uses modifiers

The `PolicyEngine` (`src/analyzer/policy_engine.py`) loads the active policy and passes its modifiers to the correlator and detector:

1. Detection rules have their `threshold` and `window` scaled by the policy's multipliers.
2. The correlator computes incident timing: `MTTD = base_mttd * mttd_multiplier` and `MTTR = base_mttr * mttr_multiplier`.
3. The impact score is scaled: `impact = base_impact * avg_confidence * impact_multiplier`.

See [[Metrics]] for how these values feed into availability and downtime calculations.

## Ranking

`policy_engine.rank_controls()` ranks policies by an effectiveness score:

```
effectiveness = 1 - (avg_mttd_multiplier + avg_mttr_multiplier) / 2
```

Higher effectiveness means the policy reduces detection and recovery times more aggressively. The report (`docs/examples/report.txt`) includes a "Top 3 Most Effective Control Sets" section based on this ranking.
