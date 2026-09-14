"""Командна точка входу для запуску захисного шлюзу."""

from __future__ import annotations

import argparse


def main() -> None:
    """Читає CLI-параметри та запускає Uvicorn."""

    parser = argparse.ArgumentParser(
        description="Активний захисний шлюз SmartEnergy"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Адреса, на якій gateway приймає з’єднання",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Внутрішній порт gateway",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["critical", "error", "warning", "info", "debug"],
        help="Рівень журналювання",
    )

    args = parser.parse_args()

    import uvicorn

    uvicorn.run(
        "src.gateway.app:app",
        host=args.host,
        port=args.port,
        workers=1,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()