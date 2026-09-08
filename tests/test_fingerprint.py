import hashlib

from harness_aibom.fingerprint import sha256_file, sha256_text


def test_sha256_text_matches_hashlib():
    assert sha256_text("hello world") == hashlib.sha256(b"hello world").hexdigest()


def test_sha256_file_reads_bytes(tmp_path):
    p = tmp_path / "f.txt"
    content = b"some file content for hashing"
    p.write_bytes(content)
    assert sha256_file(p) == hashlib.sha256(content).hexdigest()


def test_sha256_file_missing_returns_none(tmp_path):
    assert sha256_file(tmp_path / "does-not-exist.txt") is None
