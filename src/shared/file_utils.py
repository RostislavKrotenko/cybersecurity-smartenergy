"""Утиліти для атомарного запису файлів і збереження offset."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)


def atomic_write(path: str, content: str) -> None:
    """Атомарно записує вміст у вказаний файл.

    Використовує тимчасовий файл та os.replace, щоб інші процеси
    ніколи не побачили частково записаний результат.

    Аргументи:
        path: Шлях до цільового файла.
        content: Текст, який потрібно записати.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    file_descriptor, temporary_path = tempfile.mkstemp(
        dir=str(target.parent),
        prefix=f".{target.name}.",
        suffix=".tmp",
    )

    try:
        with os.fdopen(
            file_descriptor,
            "w",
            encoding="utf-8",
        ) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporary_path, target)

    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary_path)
        raise


def load_offset_checkpoint(
    checkpoint_path: str | Path | None,
    source_path: str | Path,
) -> tuple[int, int | None]:
    """Завантажує збережений offset та inode джерела.

    Якщо checkpoint відсутній, пошкоджений або належить іншому
    файлу, читання безпечно починається з початку.

    Аргументи:
        checkpoint_path: Шлях до checkpoint або None.
        source_path: Файл, позиція читання якого відновлюється.

    Повертає:
        Кортеж із byte-offset та inode файла.
    """
    if checkpoint_path is None:
        return 0, None

    checkpoint = Path(checkpoint_path)
    source = Path(source_path)
    normalized_source = str(source.resolve(strict=False))

    if not checkpoint.exists():
        return 0, None

    try:
        payload = json.loads(
            checkpoint.read_text(encoding="utf-8")
        )

        if not isinstance(payload, dict):
            raise ValueError("Checkpoint повинен містити JSON-об'єкт")

        stored_source = str(payload.get("source", ""))

        if stored_source and stored_source != normalized_source:
            log.warning(
                "Checkpoint %s належить іншому джерелу",
                checkpoint,
            )
            return 0, None

        offset = max(0, int(payload.get("offset", 0)))

        raw_inode = payload.get("inode")
        inode = (
            int(raw_inode)
            if raw_inode is not None
            else None
        )

        if not source.exists():
            return offset, inode

        source_stat = source.stat()
        current_inode = source_stat.st_ino

        if inode is not None and inode != current_inode:
            log.info(
                "Файл %s було замінено — offset скинуто",
                source,
            )
            return 0, current_inode

        if source_stat.st_size < offset:
            log.info(
                "Файл %s було скорочено — offset скинуто",
                source,
            )
            return 0, current_inode

        return offset, current_inode

    except (
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        log.warning(
            "Не вдалося завантажити checkpoint %s: %s",
            checkpoint,
            error,
        )
        return 0, None


def save_offset_checkpoint(
    checkpoint_path: str | Path | None,
    source_path: str | Path,
    offset: int,
    inode: int | None,
) -> None:
    """Атомарно зберігає поточну позицію читання файла.

    Помилка запису checkpoint журналюється, але не зупиняє
    основний процес обробки подій.

    Аргументи:
        checkpoint_path: Шлях до checkpoint або None.
        source_path: Файл, для якого зберігається позиція.
        offset: Поточний byte-offset.
        inode: Ідентифікатор поточної версії файла.
    """
    if checkpoint_path is None:
        return

    checkpoint = Path(checkpoint_path)
    source = Path(source_path)

    payload = {
        "version": 1,
        "source": str(source.resolve(strict=False)),
        "offset": max(0, int(offset)),
        "inode": inode,
    }

    try:
        atomic_write(
            str(checkpoint),
            json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n",
        )

    except OSError:
        log.exception(
            "Не вдалося зберегти checkpoint %s",
            checkpoint,
        )