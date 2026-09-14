"""Точка входу для запуску API як Python-модуля.

Приклади:
    python -m src.api
    python -m src.api --port 8000 --reload
"""

import argparse
import sys


def main() -> None:
    """Парсить аргументи CLI та запускає Uvicorn-сервер."""
    parser = argparse.ArgumentParser(description="API кіберстійкості SmartEnergy")
    parser.add_argument("--host", default="0.0.0.0", help="Адреса, на якій слухає сервер")
    parser.add_argument("--port", type=int, default=8000, help="Порт сервера")
    parser.add_argument("--reload", action="store_true", help="Увімкнути автоматичне перезавантаження")
    parser.add_argument("--workers", type=int, default=1, help="Кількість worker-процесів")

    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print("Помилка: uvicorn не встановлено. Виконайте: pip install uvicorn", file=sys.stderr)
        sys.exit(1)

    uvicorn.run(
        "src.api.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers if not args.reload else 1,
    )


if __name__ == "__main__":
    main()
