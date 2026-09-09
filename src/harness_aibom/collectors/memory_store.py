"""Memory-store discovery: well-known, cross-project AI-memory artifacts
found anywhere under a harness's own directory -- a persisted vector
store, a conversation/session log.

Confirmed generic conventions of specific, real, widely-used tools, not
harness-specific guessing -- the same justification deps.py and
prompt_surface.py both use: `chroma.sqlite3` is Chroma's own real,
documented default persistence filename; `*.faiss`/`*.index` are FAISS's
own real index-file extensions. None of these are confirmed specifically
for Hermes or OpenClaw from this project's source material -- like
prompt_surface.py, this is "if a file with one of these known shapes
exists in the harness's own tree, record it", not a claim that this
specific harness is confirmed to use it.

Metadata only, same secrets-never-leak discipline as secrets_surface
(SPEC.md section 3) and for the same reason: a memory store can carry
conversation history, which can itself contain anything a user or the
agent ever discussed, including credentials -- so this module never
opens a matched file to read or fingerprint its content, only records
that it exists and its permissions. Recursion mirrors
secrets.find_secrets_surface() -- a memory artifact dropped inside a
skill directory is exactly where a poisoned skill would keep persisted
state, and a top-level-only scan would miss it.
"""

from __future__ import annotations

import fnmatch
import os
import stat
from pathlib import Path

from ..model import Component
from ..paths import is_symlink_outside_home, relative_to_or_none

#: Filename/extension patterns for specific, real, well-known AI-memory
#: artifacts. Deliberately NOT "*.sqlite" or "*.json" generally -- both
#: are far too broad (secrets.py's own SECRET_NAME_PATTERNS already
#: covers *.sqlite for the credential-store angle; a bare *.json would
#: match nearly anything). `chroma.sqlite3` is Chroma's literal default
#: filename, not a wildcard guess.
MEMORY_STORE_NAME_PATTERNS = ("chroma.sqlite3", "*.faiss", "*.index")


def find_memory_store(directory: Path, home: Path) -> list[Component]:
    """`home` is the harness's own scan root, used only to compute
    `relPath` (see paths.py) -- same contract as
    `secrets.find_secrets_surface()`.
    """
    if not directory.is_dir():
        return []

    found: list[Component] = []
    for root, _dirs, files in os.walk(directory, onerror=lambda exc: None):
        for filename in sorted(files):
            if not any(fnmatch.fnmatch(filename, pattern) for pattern in MEMORY_STORE_NAME_PATTERNS):
                continue
            file_path = Path(root) / filename
            try:
                mode = stat.S_IMODE(file_path.stat().st_mode)
            except OSError:
                continue
            comp = Component(component_class="memory_store", name=str(file_path.relative_to(directory)))
            comp.set("path", str(file_path))
            comp.set("relPath", relative_to_or_none(file_path, home))
            comp.set("mode", oct(mode))
            comp.set("worldReadable", bool(mode & stat.S_IROTH))
            # symlink/pathOutsideHome (v0.6.1) -- same check as hooks.py
            # (v0.1.9) and prompt_surface.py (this same release); a
            # memory store swapped in via a symlink escaping --home is
            # the same shape of gap.
            comp.set("symlink", file_path.is_symlink())
            if is_symlink_outside_home(file_path, home):
                comp.set("pathOutsideHome", True)
            found.append(comp)
    return found
