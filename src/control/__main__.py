"""Точка запуску control worker через python -m src.control."""

from __future__ import annotations

import asyncio
import logging
import signal

from src.control.worker import (
    WorkerSettings,
    create_worker,
)


async def async_main() -> None:
    """Запускає worker і обробляє сигнали завершення."""

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s %(levelname)s "
            "%(name)s: %(message)s"
        ),
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    for signal_name in (
        signal.SIGINT,
        signal.SIGTERM,
    ):
        loop.add_signal_handler(
            signal_name,
            stop_event.set,
        )

    settings = WorkerSettings.from_env()
    worker = create_worker(settings)

    try:
        await worker.run(stop_event)
    finally:
        await worker.close()


def main() -> None:
    """Запускає асинхронний цикл control worker."""

    asyncio.run(async_main())


if __name__ == "__main__":
    main()