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


def is_symlink_outside_home(file_path: Path, home: Path) -> bool:
    """True only if `file_path` is a symlink whose *resolved* target
    lands outside `home` -- the same check hooks.py's own
    `pathOutsideHome` property has made since v0.1.9 (a hook script that
    looks like it lives inside the harness but is actually a symlink
    pointing somewhere else entirely), generalized here for any
    file-based collector that walks a directory tree without already
    resolving every path it finds (prompt_surface.py, memory_store.py).

    Only resolves anything when `file_path` actually IS a symlink -- a
    plain file (the overwhelming majority during a recursive walk) never
    pays the extra stat/readlink cost, and this function never has to
    reconcile a caller's possibly-unresolved `home` against a resolved
    file path for that common case (macOS's `/tmp` -> `/private/tmp` is
    a real example of the mismatch a naive "always resolve" version
    would hit). `.resolve()` is applied to both sides only once a
    symlink is actually in play, so the comparison is always apples to
    apples regardless of whether the caller's own `home` was pre-resolved.
    """
    if not file_path.is_symlink():
        return False
    return relative_to_or_none(file_path.resolve(), home.resolve()) is None
