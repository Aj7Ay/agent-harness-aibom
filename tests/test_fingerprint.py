import hashlib
import os
import stat

import pytest

from harness_aibom.fingerprint import sha256_directory, sha256_file, sha256_text


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
