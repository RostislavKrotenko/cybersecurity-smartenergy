"""Session-state defaults and initialisation.

Call ``init_state()`` once at the top of ``app.py`` to ensure every
key used by sidebar controls has a sensible default before any widget
renders.
"""

from __future__ import annotations

import streamlit as st

_DEFAULTS: dict[str, object] = {
    "policies": ["baseline", "minimal", "standard"],
    "severity_filter": [],
    "threat_type_filter": [],
    "component_filter": [],
    "horizon_days": 1.0,
    "auto_refresh": False,
    "refresh_interval": 5,
}


def init_state() -> None:
    """Populate ``st.session_state`` with defaults for missing keys."""
    for key, value in _DEFAULTS.items():
        if key not in st.session_state:
            st.session_state[key] = value
