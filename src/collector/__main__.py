"""Точка запуску Collector через python -m src.collector."""

from __future__ import annotations

import logging
import signal
import threading

from src.collector.config import CollectorSettings
from src.collector.service import create_collector


def main() -> None:
    """Запускає Collector і коректно обробляє завершення."""

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s %(levelname)s "
            "%(name)s: %(message)s"
        ),
    )

    stop_event = threading.Event()

    def request_stop(
        signum: int,
        frame: object,
    ) -> None:
        """Позначає запит на коректне завершення."""

        stop_event.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    settings = CollectorSettings.from_env()
    collector = create_collector(settings)

    try:
        collector.run(stop_event)
    finally:
        collector.close()


if __name__ == "__main__":
    main()