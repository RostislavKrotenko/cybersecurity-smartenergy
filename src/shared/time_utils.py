"""Утиліти для роботи з ISO-8601 timestamp."""

from __future__ import annotations

from datetime import datetime


def parse_iso_ts(iso: str) -> datetime:
    """Парсить ISO-8601 timestamp у datetime (UTC).

    Args:
        iso: Рядок у форматі ISO-8601 (``2024-01-01T10:00:00Z``).

    Returns:
        datetime об'єкт з timezone-aware UTC.
    """
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def format_iso_ts(dt: datetime) -> str:
    """Форматує datetime в ISO-8601 UTC рядок.

    Args:
        dt: datetime об'єкт.

    Returns:
        Рядок ``YYYY-MM-DDTHH:MM:SSZ``.
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
