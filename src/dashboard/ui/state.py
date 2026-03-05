"""Iнiцiалiзацiя стану сесiї."""

from __future__ import annotations

import os

import streamlit as st

# Auto-detect live mode via env var set in docker-compose for ui-live.
_LIVE_MODE = os.environ.get("SMARTENERGY_LIVE_MODE", "") == "1"

DEFAULTS: dict[str, object] = {
    "auto_refresh": _LIVE_MODE,
    "refresh_interval": 5,
}


def init_state() -> None:
    """Заповнює st.session_state значеннями за замовчуванням."""
    for key, value in DEFAULTS.items():
        if key not in st.session_state:
            st.session_state[key] = value
