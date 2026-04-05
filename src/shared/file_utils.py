"""Утиліти для атомарного запису файлів."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def atomic_write(path: str, content: str) -> None:
    """Атомарно записує content у файл path.

    Використовує tempfile + os.replace для гарантії цілісності.

    Args:
        path: Шлях до файлу.
        content: Вміст для запису.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=str(target.parent),
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
