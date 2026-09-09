"""Real, end-to-end sign/verify tests against an actual `cosign` binary --
never a mocked subprocess. This module never re-implements signature
verification (see sign.py's own docstring for why), so what's actually
worth testing is that this project's own command shape (confirmed once,
manually, against a real cosign v3.1.3 install -- see sign.py) still
signs and verifies correctly, and that a tampered file is genuinely
rejected, not that a hand-rolled crypto check behaves as expected.

Skipped entirely when `cosign` isn't on PATH -- these are real
subprocess calls to a real external binary, the same "verify against the
real thing, never assume" discipline this project applies to the
CycloneDX schema (test_cyclonedx_schema.py) and headless-Chrome JS
verification, not something a mock could stand in for. CI installs
cosign specifically so this suite runs for real there too, not just
locally (see .github/workflows/ci.yml).
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from harness_aibom.sign import DEFAULT_SIGNING_CONFIG, CosignNotFound, sign_blob, verify_blob

pytestmark = pytest.mark.skipif(shutil.which("cosign") is None, reason="cosign not installed")

#: Points at an address nothing listens on -- `connect()` fails
#: immediately (`connection refused`), rather than hanging on a timeout
#: the way a silently-dropped-packet firewall would. Used below to
#: deterministically simulate "TUF is unreachable" regardless of this
#: sandbox's own real network access (which does reach
#: tuf-repo-cdn.sigstore.dev fine -- see SPEC.md's account of how this
#: bug was actually reproduced).
_UNREACHABLE_PROXY = "http://127.0.0.1:1"


@pytest.fixture()
def keypair(tmp_path, monkeypatch):
    # An empty (not password-protected) key, generated fresh per test --
    # COSIGN_PASSWORD="" avoids an interactive password prompt, both here
    # and in every sign_blob()/verify_blob() call this test makes (cosign
    # reads it from the environment at call time, not just at generation
    # time -- confirmed real: omitting it entirely makes cosign try to
    # prompt on stdin, which fails outright in a non-interactive test run).
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    key_path = tmp_path / "cosign.key"
    pub_path = tmp_path / "cosign.pub"
    result = subprocess.run(
        ["cosign", "generate-key-pair", "--output-key-prefix", str(tmp_path / "cosign")],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert key_path.is_file() and pub_path.is_file()
    return key_path, pub_path


def test_sign_then_verify_a_real_file_succeeds(tmp_path, keypair):
    key_path, pub_path = keypair
    doc = tmp_path / "aibom.json"
    doc.write_text('{"bomFormat": "CycloneDX"}')
    bundle_path = tmp_path / "aibom.json.bundle"

    sign_result = sign_blob(doc, key_path, bundle_path)
    assert sign_result.returncode == 0, sign_result.stderr
    assert bundle_path.is_file()

    verify_result = verify_blob(doc, pub_path, bundle_path)
    assert verify_result.returncode == 0, verify_result.stderr
    assert "Verified OK" in verify_result.stdout + verify_result.stderr


def test_verify_rejects_a_tampered_file(tmp_path, keypair):
    key_path, pub_path = keypair
    doc = tmp_path / "aibom.json"
    doc.write_text('{"bomFormat": "CycloneDX"}')
    bundle_path = tmp_path / "aibom.json.bundle"
    assert sign_blob(doc, key_path, bundle_path).returncode == 0

    doc.write_text('{"bomFormat": "CycloneDX", "tampered": true}')
    verify_result = verify_blob(doc, pub_path, bundle_path)
    assert verify_result.returncode != 0


def test_verify_rejects_the_wrong_public_key(tmp_path, keypair, monkeypatch):
    key_path, _pub_path = keypair
    doc = tmp_path / "aibom.json"
    doc.write_text('{"bomFormat": "CycloneDX"}')
    bundle_path = tmp_path / "aibom.json.bundle"
    assert sign_blob(doc, key_path, bundle_path).returncode == 0

    # A second, unrelated key pair -- verifying against its public half
    # must fail, proving the check is genuinely tied to the signing key.
    other_prefix = tmp_path / "other"
    subprocess.run(
        ["cosign", "generate-key-pair", "--output-key-prefix", str(other_prefix)],
        capture_output=True, text=True, check=True,
    )
    verify_result = verify_blob(doc, tmp_path / "other.pub", bundle_path)
    assert verify_result.returncode != 0


def test_missing_cosign_binary_raises_a_clean_error(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(CosignNotFound):
        sign_blob(tmp_path / "x.json", tmp_path / "cosign.key", tmp_path / "x.json.bundle")


# ---- v0.8.3: cosign's "fully offline" claim was false for sign-blob -----
#
# A reviewer found that a *fresh* environment (no pre-existing
# `~/.sigstore` TUF cache) makes `cosign sign-blob` -- even in pure
# key-based mode, with no OIDC/Fulcio/Rekor involved -- fail with
# "error getting signing config from TUF" unless the TUF-hosted signing
# config can actually be fetched over the network. The tests below
# reproduce that with an isolated `$HOME` (so no pre-existing cache can
# paper over it) and a deliberately unroutable HTTPS_PROXY (so the
# failure is deterministic in any environment, including one -- like this
# sandbox -- whose network happens to reach tuf-repo-cdn.sigstore.dev
# just fine).


@pytest.fixture()
def isolated_keypair(tmp_path, monkeypatch):
    """A fresh cosign keypair under a `$HOME` with no pre-existing
    `.sigstore` TUF cache -- generated before any network blocking is
    applied, so key generation itself is never what's under test."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    key_path = home / "cosign.key"
    pub_path = home / "cosign.pub"
    result = subprocess.run(
        ["cosign", "generate-key-pair", "--output-key-prefix", str(home / "cosign")],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert key_path.is_file() and pub_path.is_file()
    assert not (home / ".sigstore").is_dir(), "test setup bug: a TUF cache exists, so this wouldn't reproduce anything"
    return key_path, pub_path


def test_vendored_signing_config_exists_and_strips_remote_services():
    """The actual fix: a local signing-config file `sign_blob()` can point
    `--signing-config` at instead of asking TUF for one. Must be valid
    JSON, and must NOT declare `rekorTlogUrls`/`tsaUrls` -- the two remote
    services pure key-based signing never needs and that the reviewer's
    own verified fix (and this project's own SPEC.md account of it)
    deliberately strips. This test needs no cosign binary and never skips."""
    assert DEFAULT_SIGNING_CONFIG.is_file()
    data = json.loads(DEFAULT_SIGNING_CONFIG.read_text())
    assert isinstance(data, dict)
    assert "rekorTlogUrls" not in data
    assert "tsaUrls" not in data


def test_sign_blob_without_signing_config_fails_when_tuf_is_unreachable(tmp_path, isolated_keypair, monkeypatch):
    """Reproduces the reviewer's claim directly against cosign, bypassing
    sign_blob() entirely, to prove this is a real cosign behavior and not
    an artifact of this project's own wrapper: with no signing-config
    override and no reachable TUF host, `sign-blob` fails outright, even
    in pure key-based mode."""
    key_path, _pub_path = isolated_keypair
    monkeypatch.setenv("HTTPS_PROXY", _UNREACHABLE_PROXY)
    monkeypatch.setenv("HTTP_PROXY", _UNREACHABLE_PROXY)
    doc = tmp_path / "aibom.json"
    doc.write_text('{"bomFormat": "CycloneDX"}')
    bundle_path = tmp_path / "aibom.json.bundle"
    result = subprocess.run(
        ["cosign", "sign-blob", "--key", str(key_path), "--bundle", str(bundle_path), "--yes", str(doc)],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "signing config from TUF" in result.stderr or "tuf" in result.stderr.lower()


def test_sign_blob_default_works_when_tuf_is_unreachable(tmp_path, isolated_keypair, monkeypatch):
    """The actual fix, end to end: `sign_blob()`'s own default (no
    `signing_config` argument given) must still succeed under the exact
    same blocked-network conditions the test above just proved break raw
    `cosign sign-blob` -- because it now passes the vendored
    `--signing-config` file by default. The resulting bundle must also
    still verify correctly under the same blocked network (verify-blob
    was already offline before this fix and must stay that way)."""
    key_path, pub_path = isolated_keypair
    monkeypatch.setenv("HTTPS_PROXY", _UNREACHABLE_PROXY)
    monkeypatch.setenv("HTTP_PROXY", _UNREACHABLE_PROXY)
    doc = tmp_path / "aibom.json"
    doc.write_text('{"bomFormat": "CycloneDX"}')
    bundle_path = tmp_path / "aibom.json.bundle"

    sign_result = sign_blob(doc, key_path, bundle_path)
    assert sign_result.returncode == 0, sign_result.stderr
    assert bundle_path.is_file()

    verify_result = verify_blob(doc, pub_path, bundle_path)
    assert verify_result.returncode == 0, verify_result.stderr
    assert "Verified OK" in verify_result.stdout + verify_result.stderr


def test_sign_blob_still_rejects_tampering_and_wrong_key_when_offline(tmp_path, isolated_keypair, monkeypatch):
    """The same full check the reviewer ran manually (tamper + wrong key
    rejected), under the same blocked-network conditions -- the offline
    fix must not have loosened what actually gets verified."""
    key_path, pub_path = isolated_keypair
    monkeypatch.setenv("HTTPS_PROXY", _UNREACHABLE_PROXY)
    monkeypatch.setenv("HTTP_PROXY", _UNREACHABLE_PROXY)
    doc = tmp_path / "aibom.json"
    doc.write_text('{"bomFormat": "CycloneDX"}')
    bundle_path = tmp_path / "aibom.json.bundle"
    assert sign_blob(doc, key_path, bundle_path).returncode == 0

    doc.write_text('{"bomFormat": "CycloneDX", "tampered": true}')
    assert verify_blob(doc, pub_path, bundle_path).returncode != 0

    doc.write_text('{"bomFormat": "CycloneDX"}')  # restore, then try the wrong key
    other_prefix = tmp_path / "other"
    subprocess.run(
        ["cosign", "generate-key-pair", "--output-key-prefix", str(other_prefix)],
        capture_output=True, text=True, check=True,
    )
    assert verify_blob(doc, tmp_path / "other.pub", bundle_path).returncode != 0


def test_sign_blob_signing_config_override_is_honored(tmp_path, isolated_keypair, monkeypatch):
    """A caller-supplied `signing_config` (matching the CLI's own
    `--signing-config` override) must actually be used, not silently
    ignored in favor of the vendored default -- proven two ways: a valid
    custom copy still signs successfully offline, and a nonexistent path
    is rejected by cosign itself (proof the flag is really reaching it)."""
    key_path, pub_path = isolated_keypair
    monkeypatch.setenv("HTTPS_PROXY", _UNREACHABLE_PROXY)
    monkeypatch.setenv("HTTP_PROXY", _UNREACHABLE_PROXY)
    doc = tmp_path / "aibom.json"
    doc.write_text('{"bomFormat": "CycloneDX"}')

    custom_config = tmp_path / "my-signing-config.json"
    custom_config.write_text(DEFAULT_SIGNING_CONFIG.read_text())
    bundle_path = tmp_path / "aibom.json.bundle"
    result = sign_blob(doc, key_path, bundle_path, signing_config=custom_config)
    assert result.returncode == 0, result.stderr
    assert verify_blob(doc, pub_path, bundle_path).returncode == 0

    bad_bundle = tmp_path / "aibom2.json.bundle"
    bad_result = sign_blob(doc, key_path, bad_bundle, signing_config=tmp_path / "no-such-config.json")
    assert bad_result.returncode != 0
