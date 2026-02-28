# Example Artifacts

This directory contains **curated excerpts** of the pipeline outputs
for reference and documentation purposes. Full files are generated
by running the pipeline (`make demo-local`).

## Files

| File                  | Description                                     |
|-----------------------|-------------------------------------------------|
| `events_sample.csv`   | First 20 events from `data/events.csv`          |
| `results.csv`         | Complete policy comparison (3 rows)             |
| `incidents_sample.csv`| First 15 incidents from `out/incidents.csv`     |
| `report.txt`          | Complete human-readable analysis report         |

## Reproducing

```bash
make clean && make generate && make analyze
# Outputs appear in data/ and out/
# Copies below are static snapshots for reference
```
