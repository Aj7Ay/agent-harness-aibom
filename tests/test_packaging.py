"""Verifies the actual *built* wheel/sdist, not just pyproject.toml's own
declared intent -- a config change that isn't checked against a real
build is not verified, the same discipline this project applies to
cosign (test_sign.py) and the CycloneDX/SARIF schemas
(test_cyclonedx_schema.py/test_sarif.py).

Confirmed real gap this guards against (v0.8.3): setuptools does NOT
include a non-.py file inside a package by default -- adding
`signing_config_offline.json` (sign.py's vendored, offline-safe cosign
signing config) without also declaring it in
`[tool.setuptools.package-data]` produced a wheel/sdist that silently
omitted the file entirely, which would have made `sign_blob()`'s own
default `--signing-config` path a 404 for anyone installing from PyPI --
exactly the kind of gap `MANIFEST.in`'s own comment about the tests/
sdist bug (found by an earlier reviewer) describes.

Runs a real `uv build` (sdist + wheel -- the exact command this project's
own release process uses, per README.md/SPEC.md) into a temp directory
and inspects the actual archive contents -- never assumes the
pyproject.toml declaration alone is enough. Skipped if `uv` isn't on
PATH.
"""

from __future__ import annotations

import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed")


@pytest.fixture(scope="module")
def built_dists(tmp_path_factory):
    out_dir = tmp_path_factory.mktemp("dist")
    result = subprocess.run(
        ["uv", "build", "--out-dir", str(out_dir)],
        cwd=str(REPO_ROOT),
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    sdist = next(out_dir.glob("*.tar.gz"))
    wheel = next(out_dir.glob("*.whl"))
    return sdist, wheel


def test_sdist_excludes_tests_directory(built_dists):
    sdist, _wheel = built_dists
    with tarfile.open(sdist) as tf:
        names = tf.getnames()
    test_files = [n for n in names if "/tests/" in n or n.rstrip("/").endswith("/tests")]
    assert test_files == []


def test_signing_config_is_present_in_the_sdist(built_dists):
    sdist, _wheel = built_dists
    with tarfile.open(sdist) as tf:
        names = tf.getnames()
    matches = [n for n in names if n.endswith("signing_config_offline.json")]
    assert len(matches) == 1, f"expected exactly one signing_config_offline.json in the sdist, found {matches}"


def test_signing_config_is_present_in_the_wheel(built_dists):
    _sdist, wheel = built_dists
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
    assert "harness_aibom/signing_config_offline.json" in names


def test_wheel_signing_config_content_matches_the_source_file(built_dists):
    """Not just present -- actually the same bytes as the file `sign.py`
    reads at import time, so a stale or hand-edited copy in the built
    artifact would be caught too."""
    _sdist, wheel = built_dists
    with zipfile.ZipFile(wheel) as zf:
        packaged = zf.read("harness_aibom/signing_config_offline.json")
    source = (REPO_ROOT / "src" / "harness_aibom" / "signing_config_offline.json").read_bytes()
    assert packaged == source
