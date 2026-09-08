"""Shared secrets-surface discovery: locate files that look like credential
material anywhere under a harness's own directory, and record *presence
and permissions only* -- never contents. See SPEC.md section 3 on why
secrets_surface is fingerprint-exempt: hashing or reading `.env` contents
would turn the AIBOM itself into a secrets leak.

Recurses into the whole tree, not just the top level -- a `.env` dropped
inside a skill's directory is exactly where a poisoned skill would keep a
payload's configuration, and a top-level-only scan would never see it.
"""

from __future__ import annotations

import fnmatch
import os
import stat
from pathlib import Path

from ..model import Component

SECRET_NAME_PATTERNS = (".env", "*.env", "*credentials*", "*token*", "*.pem", "*.key", "*.sqlite")


def find_secrets_surface(directory: Path, exclude_dirnames: frozenset[str] = frozenset()) -> list[Component]:
    """`exclude_dirnames` skips descending into subdirectories with that
    exact name -- for a spot a collector already scans separately with
    richer, harness-specific metadata (e.g. OpenClaw's per-agent SQLite
    store), so it isn't reported twice under two different components.
    """
    if not directory.is_dir():
        return []

    found: list[Component] = []
    # os.walk(onerror=...) skips a subdirectory it can't list instead of
    # raising -- same reasoning as collectors/skills.py.
    for root, dirs, files in os.walk(directory, onerror=lambda exc: None):
        dirs[:] = [d for d in dirs if d not in exclude_dirnames]
        for filename in sorted(files):
            if not any(fnmatch.fnmatch(filename, pattern) for pattern in SECRET_NAME_PATTERNS):
                continue
            file_path = Path(root) / filename
            try:
                mode = stat.S_IMODE(file_path.stat().st_mode)
            except OSError:
                continue
            comp = Component(component_class="secrets_surface", name=filename)
            comp.set("path", str(file_path))
            comp.set("mode", oct(mode))
            comp.set("worldReadable", bool(mode & stat.S_IROTH))
            found.append(comp)
    return found
