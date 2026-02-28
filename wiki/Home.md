# SmartEnergy Cyber-Resilience Analyzer

System for modelling cyber-attacks on smart energy grid components and evaluating security policy effectiveness.

## Architecture

The platform consists of four modules:

| Module | Purpose |
|--------|---------|
| **Emulator** | Generates synthetic security events (brute-force, DDoS, telemetry spoofing, outages) |
| **Normalizer** | Converts raw logs into a unified normalised format |
| **Analyzer** | Threat detection, alert correlation into incidents, resilience metrics (Availability, MTTD, MTTR) |
| **Dashboard** | Streamlit UI with real-time charts and tables |

### Data flow

```
Emulator -> Normalizer -> Analyzer (Detector -> Correlator -> Metrics) -> Reporter / Dashboard
```

Events are generated in UTC, normalised, and analysed per policy. The dashboard converts timestamps to the user-selected display timezone for rendering only.

### Security controls -- modelling note

All security controls referenced in this project (MFA, RBAC, rate limiting, network segmentation, etc.) are **modelled through detection parameters and impact coefficients** defined in `policies.yaml`. The prototype does not integrate with a real IAM provider, MFA service, or firewall. Each control's effect is expressed as a set of multipliers (`mttd_multiplier`, `mttr_multiplier`, `prob_multiplier`, `impact_multiplier`, `threshold_multiplier`, `window_multiplier`) that alter detection sensitivity and incident timing. See [[Policies]] for details.

## Pages

- [[Metrics]] -- resilience metrics definitions and formulas
- [[Event-Contract]] -- normalised event schema and timestamp conventions
- [[Policies]] -- security policy model and control multipliers
- [[Running]] -- how to start the system locally and in Docker
