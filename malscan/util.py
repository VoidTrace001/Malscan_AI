"""Small helpers shared across layers.

Deliberately dependency-free. The UI helpers live in ``malscan.ui.theme``, but
that module imports Streamlit, so anything the model layer or the CLI also
needs has to sit somewhere neutral -- otherwise a headless scan drags the whole
web framework in behind it.
"""
from __future__ import annotations


def human_bytes(n: float) -> str:
    """Format a byte count the way a person would say it."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"
