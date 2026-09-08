"""Content-fingerprinting helpers.

Deliberately narrow: only file/text hashing lives here. `secrets_surface`
components are hash-exempt by design -- see SPEC.md section 3 -- so this
module is never called against `.env`-style files, only against
configuration files and skill manifests.
"""

from __future__ import annotations

import hashlib
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


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
