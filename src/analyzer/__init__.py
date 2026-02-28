"""SmartEnergy Analyzer — light SIEM-like pipeline.

Modules
───────
  detector      — rule-based: Event → Alert
  correlator    — Alert → Incident (grouping by correlation/time/component)
  policy_engine — apply policy multipliers to MTTD/MTTR/thresholds
  metrics       — compute Availability, Downtime, MTTD, MTTR, counts
  reporter      — write CSV, TXT, PNG outputs
  pipeline      — orchestrate the full flow
  cli           — argparse entry-point
"""
