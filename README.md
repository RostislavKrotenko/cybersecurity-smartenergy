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
