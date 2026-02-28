# Contributing

Thank you for your interest in contributing to the SmartEnergy
Cyber-Resilience Analyzer.

## Getting Started

1. Fork the repository and clone your fork.
2. Create a virtual environment and install dependencies:
   ```bash
   make install
   ```
3. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

- Run the test suite before submitting changes:
  ```bash
  make test
  ```
- Run the linter:
  ```bash
  make lint
  ```
- Format code:
  ```bash
  make format
  ```

## Code Style

- Python 3.11+, type hints encouraged.
- Line length: 100 characters (enforced by `ruff`).
- Follow existing patterns in `src/` for new modules.

## Pull Requests

1. Keep PRs focused -- one feature or fix per PR.
2. Include or update tests for any new functionality.
3. Update documentation (README, docstrings) if behaviour changes.
4. Ensure all tests pass and the linter reports no errors.

## Adding a New Attack Scenario

1. Create a new file in `src/emulator/scenarios/`.
2. Subclass `BaseScenario` (see existing scenarios for examples).
3. Register it in `src/emulator/scenarios/__init__.py`.
4. Add corresponding detection rules in `config/rules.yaml`.
5. Add tests in `tests/`.

## Reporting Issues

Use GitHub Issues. Please include:

- Steps to reproduce.
- Expected vs. actual behaviour.
- Python version, OS, and Docker version (if applicable).

## License

By contributing, you agree that your contributions will be licensed under
the MIT License (see LICENSE file).
