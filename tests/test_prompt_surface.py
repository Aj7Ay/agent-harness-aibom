from pathlib import Path

from harness_aibom.collectors.prompt_surface import find_prompt_surface


def test_finds_agents_md_and_claude_md(tmp_path):
    home = tmp_path
    (home / "AGENTS.md").write_text("# Agent instructions\n")
    (home / "CLAUDE.md").write_text("# Claude instructions\n")

    found = find_prompt_surface(home, home)
    names = {c.name for c in found}
    assert names == {"AGENTS.md", "CLAUDE.md"}
    for comp in found:
        assert comp.component_class == "prompt_surface"
        assert comp.properties["sha256"]


def test_recurses_into_subdirectories(tmp_path):
    home = tmp_path
    nested = home / "skills" / "devops"
    nested.mkdir(parents=True)
    (nested / "AGENTS.md").write_text("nested instructions\n")

    [comp] = find_prompt_surface(home, home)
    assert comp.name == "skills/devops/AGENTS.md"
    assert comp.properties["relPath"] == "skills/devops/AGENTS.md"


def test_unrecognized_filenames_are_ignored(tmp_path):
    home = tmp_path
    (home / "README.md").write_text("not a prompt surface\n")
    (home / "instructions.md").write_text("also not recognized -- no confirmed convention for this name\n")

    assert find_prompt_surface(home, home) == []


def test_missing_directory_returns_empty(tmp_path):
    assert find_prompt_surface(tmp_path / "does-not-exist", tmp_path) == []


def test_fingerprint_changes_when_content_changes(tmp_path):
    home = tmp_path
    (home / "AGENTS.md").write_text("version one\n")
    [before] = find_prompt_surface(home, home)

    (home / "AGENTS.md").write_text("version two -- content changed\n")
    [after] = find_prompt_surface(home, home)

    assert before.properties["sha256"] != after.properties["sha256"]
