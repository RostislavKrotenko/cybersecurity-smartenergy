# SmartEnergy Cyber-Resilience Analyzer

## Project Overview

Reproducible experimental pipeline for evaluating the impact of cybersecurity
policy levels on smart-grid infrastructure resilience. The system generates
synthetic SCADA/IoT events, runs detection and correlation analysis under
multiple security policies, and presents comparative metrics (availability,
MTTD, MTTR) through an interactive dashboard. Built as a master's thesis
prototype.

## Requirements

- **Docker** (Engine 24.0+, Compose v2.20+) -- recommended path.
- **Python 3.11+** and `make` -- for local execution without Docker.

## Quick Start

### Docker (recommended)

```bash
make demo
```

This builds the image, generates synthetic events, runs the analyzer, and
starts the dashboard at `http://localhost:8501`. Press `Ctrl+C` to stop.

To stop and clean up containers afterwards:

```bash
make docker-down
```

### Live Mode (continuous streaming)

```bash
docker compose --profile live up --build
```

This launches the full live pipeline:

| Service           | Role                                                        |
|-------------------|-------------------------------------------------------------|
| `emulator-live`   | Generates events every 500 ms in JSONL + CSV + raw logs     |
| `normalizer-live` | Tails raw logs (`logs/live/*.log`) and normalises them       |
| `analyzer-live`   | Watches `events.jsonl`, recalculates metrics every second   |
| `ui-live`         | Streamlit dashboard at `http://localhost:8501` (auto-refresh)|

The emulator uses the `demo_high_rate` profile with `--attack-rate 3`, which
injects attacks every 3-45 seconds (≥ 1-3 incidents per minute).

**Verification checklist** (open the dashboard and enable *Auto-refresh*):

1. **Last refresh** timestamp updates every few seconds.
2. **Results rows** / **Incident rows** counters grow over time.
3. **results.csv mtime** and **incidents.csv mtime** advance.
4. Availability / Downtime bar charts reflect new data.
5. *Incidents per Minute* chart shows points after 1-2 minutes.
6. Incident table gains new rows.

To stop:

```bash
docker compose --profile live down
```

### Local

```bash
make install        # create .venv and install dependencies
make demo-local     # generate events, analyze, launch dashboard
```

The dashboard will be available at `http://localhost:8501`.

### Tests

```bash
make test
```

---

## Documentation

Повна документація проєкту доступна у [GitHub Wiki](https://github.com/RostislavKrotenko/cybersecurity-smartenergy/wiki):
архітектура, Event Contract, політики безпеки, сценарії атак, правила детекції,
нормалізатор, метрики, запуск та розробка.

## License

MIT License. See [LICENSE](LICENSE) for details.
