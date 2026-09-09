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

import shutil
import subprocess

import pytest

from harness_aibom.sign import CosignNotFound, sign_blob, verify_blob

pytestmark = pytest.mark.skipif(shutil.which("cosign") is None, reason="cosign not installed")


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
