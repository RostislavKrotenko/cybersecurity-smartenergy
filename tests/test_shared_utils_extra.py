"""Додаткові тести shared-утиліт: seed/time/severity."""

from __future__ import annotations

import random

import pytest

from src.shared.seed import init_seed
from src.shared.severity import SEV_ORDER, max_severity, normalize_severity
from src.shared.time_utils import format_iso_ts, parse_iso_ts


def test_init_seed_is_deterministic():
    rng1 = init_seed(123)
    rng2 = init_seed(123)

    seq1 = [rng1.randint(0, 1000) for _ in range(5)]
    seq2 = [rng2.randint(0, 1000) for _ in range(5)]
    assert seq1 == seq2

    # Глобальний random теж детермінований після init_seed.
    init_seed(777)
    a = [random.randint(0, 100) for _ in range(3)]
    init_seed(777)
    b = [random.randint(0, 100) for _ in range(3)]
    assert a == b


def test_time_utils_parse_and_format_roundtrip_utc():
    src = "2026-03-05T10:11:12Z"
    dt = parse_iso_ts(src)
    out = format_iso_ts(dt)
    assert out == src


def test_time_utils_parse_accepts_offset():
    dt = parse_iso_ts("2026-03-05T12:11:12+02:00")
    assert dt.tzinfo is not None


def test_time_utils_parse_invalid_raises():
    with pytest.raises(ValueError):
        parse_iso_ts("not-a-timestamp")


def test_severity_mapping_and_default_behavior():
    assert SEV_ORDER["critical"] > SEV_ORDER["high"] > SEV_ORDER["medium"] > SEV_ORDER["low"]

    assert normalize_severity("HIGH") == "high"
    assert normalize_severity("unknown") == "low"
    assert normalize_severity(None, default="medium") == "medium"
    assert normalize_severity("", default="bad-default") == "low"

    assert max_severity("high", "low") == "high"
    assert max_severity("invalid", "medium") == "medium"
