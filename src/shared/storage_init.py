"""Одноразова ініціалізація runtime-сховища SECMS.

Docker image не містить інцидентів або звітів, але іменовані Docker volumes
переживають оновлення image. Цей модуль очищує лише SECMS volumes, коли
змінюється явна версія формату даних. Звичайний restart із тією самою версією
не видаляє checkpoints, історію або результати.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

DATA_ROOT = Path("/work/data/integration")
OUTPUT_ROOT = Path("/work/out")
GENERATION_ENV = "CYBERSECURITY_STORAGE_GENERATION"
DEFAULT_GENERATION = "2026-09-20-clean-runtime-v1"
MARKER_NAME = ".secms-storage-generation"


def _read_generation(root: Path) -> str:
    """Читає поточну версію сховища або повертає порожній рядок."""

    marker = root / MARKER_NAME
    try:
        return marker.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return ""


def _clear_root(root: Path) -> None:
    """Видаляє лише дочірні елементи перевіреного SECMS-каталогу."""

    root.mkdir(parents=True, exist_ok=True)
    for child in root.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def initialize_storage(
    data_root: Path,
    output_root: Path,
    generation: str,
) -> bool:
    """Очищує обидва сховища один раз для нової версії даних.

    Повертає ``True``, якщо очищення виконано, і ``False``, якщо обидва
    сховища вже мають потрібну версію.
    """

    normalized_generation = generation.strip()
    if not normalized_generation:
        raise ValueError("Версія SECMS-сховища не може бути порожньою")

    roots = (data_root, output_root)
    if all(_read_generation(root) == normalized_generation for root in roots):
        return False

    for root in roots:
        _clear_root(root)
    for root in roots:
        (root / MARKER_NAME).write_text(
            normalized_generation + "\n",
            encoding="utf-8",
        )
    return True


def main() -> int:
    """Ініціалізує стандартні Docker volumes і друкує результат."""

    generation = os.getenv(GENERATION_ENV, DEFAULT_GENERATION)
    changed = initialize_storage(DATA_ROOT, OUTPUT_ROOT, generation)
    if changed:
        print(
            "SECMS storage: старі runtime-дані очищено; "
            f"generation={generation}"
        )
    else:
        print(
            "SECMS storage: повторне очищення не потрібне; "
            f"generation={generation}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
