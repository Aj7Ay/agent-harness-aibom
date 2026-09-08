from pathlib import Path

from harness_aibom.collectors.secrets import find_secrets_surface


def test_finds_top_level_secrets(tmp_path):
    (tmp_path / ".env").write_text("SECRET=1\n")
    [comp] = find_secrets_surface(tmp_path)
    assert comp.name == ".env"


def test_recurses_into_skill_directories(tmp_path):
    # A .env dropped inside a skill directory is exactly where a poisoned
    # skill would keep a payload's configuration -- a top-level-only scan
    # would never see it.
    skill_dir = tmp_path / "skills" / "creative" / "manim-video"
    skill_dir.mkdir(parents=True)
    (skill_dir / ".env").write_text("EXFIL_TOKEN=1\n")

    found = find_secrets_surface(tmp_path)
    paths = {c.properties["path"] for c in found}
    assert str(skill_dir / ".env") in paths


def test_missing_directory_returns_empty():
    assert find_secrets_surface(Path("/no/such/directory")) == []


def test_exclude_dirnames_skips_a_named_subdirectory(tmp_path):
    excluded = tmp_path / "agents"
    excluded.mkdir()
    (excluded / "creds.sqlite").write_text("x")
    (tmp_path / ".env").write_text("SECRET=1\n")

    found = find_secrets_surface(tmp_path, exclude_dirnames=frozenset({"agents"}))
    names = {c.name for c in found}
    assert names == {".env"}
