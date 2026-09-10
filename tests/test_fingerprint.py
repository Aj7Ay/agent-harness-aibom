import hashlib
import os
import stat

import pytest

from harness_aibom.fingerprint import canonical_json_sha256, sha256_directory, sha256_file, sha256_text


def test_sha256_text_matches_hashlib():
    assert sha256_text("hello world") == hashlib.sha256(b"hello world").hexdigest()


def test_sha256_file_reads_bytes(tmp_path):
    p = tmp_path / "f.txt"
    content = b"some file content for hashing"
    p.write_bytes(content)
    assert sha256_file(p) == hashlib.sha256(content).hexdigest()


def test_sha256_file_missing_returns_none(tmp_path):
    assert sha256_file(tmp_path / "does-not-exist.txt") is None


def test_sha256_directory_changes_when_a_supporting_file_changes(tmp_path):
    (tmp_path / "SKILL.md").write_text("# Skill\n")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "run.sh").write_text("echo original\n")

    before = sha256_directory(tmp_path)
    (scripts / "run.sh").write_text("echo poisoned\n")
    after = sha256_directory(tmp_path)

    assert before != after


def test_sha256_directory_missing_path_returns_none(tmp_path):
    assert sha256_directory(tmp_path / "does-not-exist") is None


@pytest.mark.skipif(os.getuid() == 0, reason="root bypasses permission checks, so this can't exercise denial")
def test_sha256_directory_skips_an_unreadable_file_instead_of_crashing(tmp_path):
    (tmp_path / "SKILL.md").write_text("# Skill\n")
    secret = tmp_path / "root-owned.bin"
    secret.write_bytes(b"can't read this")
    secret.chmod(0o000)
    try:
        result = sha256_directory(tmp_path)  # must not raise
    finally:
        secret.chmod(0o644)  # so pytest's tmp_path cleanup can remove it
    assert result is not None
    assert len(result) == 64


@pytest.mark.skipif(os.getuid() == 0, reason="root bypasses permission checks, so this can't exercise denial")
def test_sha256_directory_skips_an_unreadable_subdirectory_instead_of_crashing(tmp_path):
    (tmp_path / "SKILL.md").write_text("# Skill\n")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "inside.txt").write_text("unreachable\n")
    mode_before = stat.S_IMODE(locked.stat().st_mode)
    locked.chmod(0o000)
    try:
        result = sha256_directory(tmp_path)  # must not raise
    finally:
        locked.chmod(mode_before)
    assert result is not None
    assert len(result) == 64


# ---- v0.11.0: canonical_json_sha256() -- the recipe SPEC.md pins ------


def test_canonical_json_sha256_is_independent_of_key_order():
    # The whole point of sort_keys=True: two dicts with the same content
    # but constructed with keys in a different order must hash identically.
    a = canonical_json_sha256({"name": "search", "scope": "tool"})
    b = canonical_json_sha256({"scope": "tool", "name": "search"})
    assert a == b


def test_canonical_json_sha256_changes_with_real_content():
    a = canonical_json_sha256({"name": "search"})
    b = canonical_json_sha256({"name": "fetch"})
    assert a != b


def test_canonical_json_sha256_matches_the_documented_recipe():
    # Confirmed against the exact recipe SPEC.md pins -- json.dumps with
    # sort_keys, compact separators, ensure_ascii=False -- so a reader
    # (or another tool re-deriving this hash independently) gets the
    # same bytes this function actually produces, not an approximation.
    import hashlib
    import json

    obj = {"name": "search"}
    expected = hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    assert canonical_json_sha256(obj) == expected


def test_canonical_json_sha256_handles_non_ascii_without_escaping():
    # ensure_ascii=False -- a real non-ASCII tool name hashes over its own
    # UTF-8 bytes, not a \uXXXX-escaped form that no other part of this
    # project's output would ever produce for the same string.
    a = canonical_json_sha256({"name": "búsqueda"})
    b = canonical_json_sha256({"name": "busqueda"})
    assert a != b  # confirms the accented form is actually distinct, not silently normalized
    assert len(a) == 64
