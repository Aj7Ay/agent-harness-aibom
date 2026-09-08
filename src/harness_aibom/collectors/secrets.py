"""Shared secrets-surface discovery: locate files that look like credential
material near a harness's config, and record *presence and permissions
only* -- never contents. See SPEC.md section 3 on why secrets_surface is
fingerprint-exempt: hashing or reading `.env` contents would turn the AIBOM
itself into a secrets leak.
"""

from __future__ import annotations

import stat
from pathlib import Path

from ..model import Component

SECRET_NAME_PATTERNS = (".env", "*.env", "*credentials*", "*token*", "*.pem", "*.key", "*.sqlite")


def find_secrets_surface(directory: Path) -> list[Component]:
    found: list[Component] = []
    if not directory.is_dir():
        return found

    seen: set[Path] = set()
    for pattern in SECRET_NAME_PATTERNS:
        for path in sorted(directory.glob(pattern)):
            if not path.is_file() or path in seen:
                continue
            seen.add(path)
            mode = stat.S_IMODE(path.stat().st_mode)
            comp = Component(component_class="secrets_surface", name=path.name)
            comp.set("path", str(path))
            comp.set("mode", oct(mode))
            comp.set("worldReadable", bool(mode & stat.S_IROTH))
            found.append(comp)
    return found
