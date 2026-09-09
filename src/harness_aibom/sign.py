"""Sign and verify a harness-aibom document with `cosign` (sigstore) --
key-based, fully offline, no OIDC/network dependency required.

Thin subprocess wrapper only: this module never re-implements signature
verification itself (a hand-rolled verifier would be a real cryptographic
mistake to get subtly wrong) -- it shells out to the real `cosign` binary
and reports its own exit code and output honestly, never reinterpreting
"verification failed" into something friendlier that could blur a real
failure.

Confirmed against a real, locally installed `cosign v3.1.3`: `sign-blob`/
`verify-blob` both require `--bundle <path>` on this version -- the older
`--output-signature`/`--signature` flags are deprecated, and combining
them with this version's default bundle-format behavior raises "must
specify --bundle with --new-bundle-format" outright, confirmed by
actually running it. Only this exact command shape (`--key`, `--bundle`,
`--yes` for signing; `--key`, `--bundle`, `--insecure-ignore-tlog=true`
for verifying) was verified locally, against one real cosign version --
an older install may use a different flag shape, and this module doesn't
try to detect or paper over that; see SPEC.md for what's confirmed vs.
not.

`--insecure-ignore-tlog=true` on verify (and no transparency-log upload
on sign) is deliberate, not a shortcut: this is *key-based* signing, not
keyless/OIDC, so there's no public identity for Rekor's transparency log
to attest to in the first place -- the trust here is "you already trust
this specific public key", the same model a GPG-signed release artifact
uses, not "this signature is publicly, independently logged".
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class CosignNotFound(RuntimeError):
    """Raised when `cosign` isn't on PATH -- callers turn this into a
    clean CLI error message, never a raw traceback."""


def _cosign_path() -> str:
    path = shutil.which("cosign")
    if not path:
        raise CosignNotFound(
            "cosign not found on PATH -- install it from "
            "https://docs.sigstore.dev/cosign/system_config/installation/"
        )
    return path


def sign_blob(file_path: Path, key_path: Path, bundle_path: Path) -> subprocess.CompletedProcess:
    """Sign `file_path` with the private key at `key_path`, writing a
    sigstore bundle to `bundle_path`. Raises `CosignNotFound` if cosign
    isn't installed; otherwise returns cosign's own `CompletedProcess`
    (`returncode`, `stdout`, `stderr`) verbatim for the caller to relay.
    `COSIGN_PASSWORD` (if the key is password-protected) is read from the
    calling process's own environment by cosign itself, exactly like
    running cosign directly on the command line -- this module never
    reads, stores, or passes a password itself.
    """
    cosign = _cosign_path()
    return subprocess.run(
        [cosign, "sign-blob", "--key", str(key_path), "--bundle", str(bundle_path), "--yes", str(file_path)],
        capture_output=True,
        text=True,
    )


def verify_blob(file_path: Path, key_path: Path, bundle_path: Path) -> subprocess.CompletedProcess:
    """Verify `file_path` against `bundle_path` using the public key at
    `key_path`. Returns cosign's own `CompletedProcess` -- `returncode ==
    0` means cosign itself confirmed the signature; anything else (a
    tampered file, a wrong key, a missing bundle) is cosign's own
    non-zero exit and error text, relayed as-is, never reinterpreted.
    """
    cosign = _cosign_path()
    return subprocess.run(
        [
            cosign, "verify-blob", "--key", str(key_path), "--bundle", str(bundle_path),
            "--insecure-ignore-tlog=true", str(file_path),
        ],
        capture_output=True,
        text=True,
    )
