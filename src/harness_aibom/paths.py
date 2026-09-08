"""Small shared path helper."""

from __future__ import annotations

from pathlib import Path


def relative_to_or_none(path: Path, base: Path) -> str | None:
    """`path` relative to `base`, or None if `path` isn't actually under
    `base` -- e.g. OpenClaw's env_dir, which defaults to /opt/openclaw,
    entirely outside ~/.openclaw. `Component.set()` treats None as "don't
    set this property", so callers can use this unconditionally without a
    try/except at each call site.
    """
    try:
        return str(path.relative_to(base))
    except ValueError:
        return None
