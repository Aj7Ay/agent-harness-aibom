"""Content-fingerprinting helpers.

Deliberately narrow: only file/text hashing lives here. `secrets_surface`
components are hash-exempt by design -- see SPEC.md section 3 -- so this
module is never called against `.env`-style files, only against
configuration files and skill directories.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

_CHUNK_SIZE = 65536


def sha256_file(path: Path) -> str | None:
    """SHA-256 of a file's bytes, or None if it can't be read (missing,
    permission denied, etc.) -- callers treat that as "fingerprint unknown",
    not a fatal error."""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def sha256_directory(path: Path) -> str | None:
    """SHA-256 over every file under `path` -- a real skill directory isn't
    just `SKILL.md`, it's `SKILL.md` plus whatever `scripts/`, `references/`,
    and `templates/` sit next to it, and those scripts are exactly what a
    poisoned skill would carry a payload in. Files are hashed in sorted
    relative-path order (so the result doesn't depend on filesystem
    directory order), with both the relative path and the content folded
    into the digest so a rename and a content change both move the hash.

    Confirmed necessary against a realistic lab condition: scanning
    root-owned skills as a non-root user. `Path.rglob()` propagates a
    `PermissionError` from any single unreadable subdirectory and aborts
    the whole walk, which would crash the scan -- `os.walk(onerror=...)`
    instead just skips what it can't list. A file that can't be *opened*
    (found, but unreadable) still has its path folded into the digest, so
    its presence is captured even though its content can't be; a change to
    that file's content won't move the hash, an inherent limit of
    unprivileged scanning, not a bug.

    None only if `path` itself isn't a directory.
    """
    if not path.is_dir():
        return None

    paths: list[Path] = []
    for root, _dirs, files in os.walk(path, onerror=lambda exc: None):
        paths.extend(Path(root) / name for name in files)

    digest = hashlib.sha256()
    for file_path in sorted(paths, key=lambda p: p.relative_to(path).as_posix()):
        digest.update(file_path.relative_to(path).as_posix().encode("utf-8"))
        digest.update(b"\x00")
        try:
            with open(file_path, "rb") as handle:
                for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
                    digest.update(chunk)
        except OSError:
            digest.update(b"<unreadable>")
        digest.update(b"\x00")
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
