# Running

## Prerequisites

- Python 3.11+
- Docker and Docker Compose (for containerised mode)

## Local setup

```bash
git clone https://github.com/RostislavKrotenko/cybersecurity-smartenergy.git
cd cybersecurity-smartenergy
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Batch mode (Make)

```bash
make demo-local
```

Or step by step:

```bash
make generate    # Emulate events -> data/events.csv
make analyze     # Analyze -> out/results.csv, out/incidents.csv
make ui          # Dashboard -> http://localhost:8501
```

## Live mode (without Docker)

```bash
make demo-live
```

The emulator continuously generates events, the analyzer processes them in real time, and the dashboard auto-refreshes.

## Docker Compose (recommended)

```bash
# Live mode
docker compose --profile live up --build

# Batch mode
make demo
```

Dashboard: http://localhost:8501

## Testing

```bash
make test        # Run tests
make test-cov    # Tests with coverage
make lint        # Code quality (ruff)
```

## Timestamps and display timezone

All data files (`data/events.csv`, `data/live/events.jsonl`, `data/live/normalized.jsonl`, `out/incidents.csv`, `out/results.csv`) store timestamps in **UTC**.

The dashboard sidebar contains a **Display timezone** selector (default: `Europe/Kyiv`). When a timezone other than UTC is selected, the UI converts timestamps for chart axes and table columns before rendering. This conversion happens exclusively in the Streamlit frontend (`src/dashboard/ui/charts.py` and `src/dashboard/data_access.py`); no backend module performs timezone conversion.

If you observe timestamps that look shifted, verify the sidebar timezone selector. The raw data is always UTC.

## Demo High-Rate profile

The `demo_high_rate` profile generates approximately 3--6 incidents per minute. This is the default profile when running via Docker Compose.

### Emulator CLI parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--profile demo_high_rate` | `default` | Activates the high-rate event stream |
| `--live-interval-ms` | `250` | Interval between ticks (ms) |
| `--attack-every-sec` | `10` | Seconds between burst injections |
| `--background-events-per-tick` | `20` | Background events per tick |
| `--max-file-mb` | `50` | File rotation threshold (MB) |

### Manual launch (without Docker)

The recommended live chain runs three processes: **emulator -> normalizer -> analyzer**.  
The normalizer tails raw logs produced by the emulator and writes normalised JSONL; the analyzer watches that normalised output.

```bash
# Terminal 1 -- emulator
python -m src.emulator \
  --live \
  --profile demo_high_rate \
  --live-interval-ms 250 \
  --attack-every-sec 10 \
  --background-events-per-tick 20 \
  --max-file-mb 50 \
  --out data/live/events.jsonl \
  --raw-log-dir logs/live \
  --csv-out data/live/events.csv

# Terminal 2 -- normalizer (follow mode, tails raw logs)
python -m src.normalizer \
  --inputs "logs/live/*.log" \
  --mapping config/mapping.yaml \
  --out data/live/normalized.jsonl \
  --quarantine out/quarantine_live.csv \
  --follow \
  --poll-interval-ms 500

# Terminal 3 -- analyzer (watch mode, reads normalised JSONL)
python -m src.analyzer \
  --input data/live/normalized.jsonl \
  --watch \
  --poll-interval-ms 1000 \
  --out-dir out \
  --policies all

# Terminal 4 -- dashboard (auto-refresh 3 sec)
SMARTENERGY_LIVE_MODE=1 streamlit run src/dashboard/app.py
```
