"""Sign and verify a harness-aibom document with `cosign` (sigstore) --
key-based, and (as of v0.8.3) genuinely offline for both `sign` and
`verify`, no OIDC/network dependency required.

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

**v0.8.3: `sign-blob` was NOT actually offline before this fix, despite
the v0.8.2 docstring above claiming it was.** A reviewer found that on a
machine with no pre-existing `~/.sigstore` TUF cache, `cosign sign-blob`
still consults Sigstore's TUF-hosted signing config by default -- even in
pure key-based mode, with no OIDC/Fulcio/Rekor involved -- which means a
real network fetch to `tuf-repo-cdn.sigstore.dev`. Reproduced here (this
sandbox's own network happened to reach that host fine, so the repro
instead blocked it with an unroutable `HTTPS_PROXY`, which is
deterministic either way): with an isolated `$HOME` and no signing-config
override, `sign-blob` failed with
`Error: error getting signing config from TUF: ... tuf refresh failed:
Get "https://tuf-repo-cdn.sigstore.dev/15.root.json": ...` -- the same
failure class the reviewer saw as a 403 through a real firewall. `verify-
blob` has no equivalent flag at all (confirmed via `cosign verify-blob
--help`) and was already confirmed to succeed under the exact same
blocked-network conditions with `--insecure-ignore-tlog=true` -- so the
v0.8.2 "fully offline" claim was correct for verification, just not for
signing.

The fix, verified end-to-end under the same blocked-network conditions:
pass `--signing-config <path>` to `sign-blob`, pointing at a *local* file
so cosign never needs to ask TUF for one. `signing_config_offline.json`
(vendored alongside this module, shipped as package data) is the public
`https://raw.githubusercontent.com/sigstore/root-signing/refs/heads/main/
targets/signing_config.v0.2.json` with only `rekorTlogUrls` and `tsaUrls`
removed -- the two remote services pure key-based signing never needs
(`caUrls`/`oidcUrls` are harmless no-ops for key-based signing and are
left in unmodified). `sign_blob()` below passes this vendored file by
default, so `harness-aibom sign` works out of the box, offline, on any
machine with `cosign` installed and a `--key` -- no setup, no TUF cache
required. A caller (or the `sign` CLI's own `--signing-config` flag) can
still override it with a different signing-config file.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

#: The public Sigstore signing config, fetched once and stripped of
#: `rekorTlogUrls`/`tsaUrls` (see this module's own docstring above) --
#: shipped as package data (see pyproject.toml's
#: `[tool.setuptools.package-data]`) so `sign_blob()` has a real, local
#: file to point `--signing-config` at without the caller supplying one.
DEFAULT_SIGNING_CONFIG = Path(__file__).parent / "signing_config_offline.json"


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


def sign_blob(
    file_path: Path,
    key_path: Path,
    bundle_path: Path,
    signing_config: Path | None = None,
) -> subprocess.CompletedProcess:
    """Sign `file_path` with the private key at `key_path`, writing a
    sigstore bundle to `bundle_path`. Raises `CosignNotFound` if cosign
    isn't installed; otherwise returns cosign's own `CompletedProcess`
    (`returncode`, `stdout`, `stderr`) verbatim for the caller to relay.
    `COSIGN_PASSWORD` (if the key is password-protected) is read from the
    calling process's own environment by cosign itself, exactly like
    running cosign directly on the command line -- this module never
    reads, stores, or passes a password itself.

    `signing_config` (v0.8.3) is passed through to cosign's own
    `--signing-config` flag -- defaults to `DEFAULT_SIGNING_CONFIG`, the
    vendored, offline-safe config this module ships (see the module
    docstring for why this is required for a genuinely offline sign, not
    optional polish). Pass a different path to use your own.
    """
    cosign = _cosign_path()
    config_path = Path(signing_config) if signing_config is not None else DEFAULT_SIGNING_CONFIG
    return subprocess.run(
        [
            cosign, "sign-blob", "--key", str(key_path), "--bundle", str(bundle_path),
            "--signing-config", str(config_path), "--yes", str(file_path),
        ],
        capture_output=True,
        text=True,
    )


def verify_blob(file_path: Path, key_path: Path, bundle_path: Path) -> subprocess.CompletedProcess:
    """Verify `file_path` against `bundle_path` using the public key at
    `key_path`. Returns cosign's own `CompletedProcess` -- `returncode ==
    0` means cosign itself confirmed the signature; anything else (a
    tampered file, a wrong key, a missing bundle) is cosign's own
    non-zero exit and error text, relayed as-is, never reinterpreted.

    No `signing_config` parameter here, unlike `sign_blob()` above: `cosign
    verify-blob --help` has no `--signing-config` flag at all (confirmed
    directly, v0.8.3) -- there is nothing to pass one through to. This was
    already genuinely offline before v0.8.3 and needed no fix: confirmed
    by running it with `$HOME` pointed at a fresh directory (no TUF cache)
    and outbound network to `tuf-repo-cdn.sigstore.dev` blocked -- verify
    still succeeds on a good signature, and still correctly rejects a
    tampered file, a wrong key, and a missing bundle.
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
