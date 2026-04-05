"""Спільні константи рівнів серйозності."""

from __future__ import annotations

SEV_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def normalize_severity(value: str | None, default: str = "low") -> str:
    """Нормалізує severity до підтримуваного значення.

    Args:
        value: Вхідне значення severity (може бути None або довільний рядок).
        default: Значення за замовчуванням для некоректних вхідних даних.

    Returns:
        Одне з: low, medium, high, critical.
    """
    candidate = (value or "").strip().lower()
    if candidate in SEV_ORDER:
        return candidate

    normalized_default = (default or "low").strip().lower()
    if normalized_default in SEV_ORDER:
        return normalized_default
    return "low"


def max_severity(a: str | None, b: str | None, default: str = "low") -> str:
    """Повертає більш критичне з двох severity значень."""
    sa = normalize_severity(a, default)
    sb = normalize_severity(b, default)
    return sa if SEV_ORDER[sa] >= SEV_ORDER[sb] else sb
