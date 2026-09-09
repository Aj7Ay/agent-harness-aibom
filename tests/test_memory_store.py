from harness_aibom.collectors.memory_store import find_memory_store


def test_finds_chroma_sqlite_and_faiss_files(tmp_path):
    home = tmp_path
    (home / "chroma.sqlite3").write_bytes(b"fake sqlite bytes")
    (home / "index.faiss").write_bytes(b"fake faiss bytes")

    found = find_memory_store(home, home)
    names = {c.name for c in found}
    assert names == {"chroma.sqlite3", "index.faiss"}
    for comp in found:
        assert comp.component_class == "memory_store"
        # never fingerprinted -- content isn't read at all, unlike
        # prompt_surface/skill/hook/configuration.
        assert "sha256" not in comp.properties


def test_recurses_into_subdirectories(tmp_path):
    home = tmp_path
    nested = home / "agents" / "main"
    nested.mkdir(parents=True)
    (nested / "chroma.sqlite3").write_bytes(b"fake")

    [comp] = find_memory_store(home, home)
    assert comp.name == "agents/main/chroma.sqlite3"
    assert comp.properties["relPath"] == "agents/main/chroma.sqlite3"


def test_records_mode_and_world_readable(tmp_path):
    home = tmp_path
    target = home / "chroma.sqlite3"
    target.write_bytes(b"fake")
    target.chmod(0o644)

    [comp] = find_memory_store(home, home)
    assert comp.properties["mode"] == "0o644"
    assert comp.properties["worldReadable"] == "True"

    target.chmod(0o600)
    [comp] = find_memory_store(home, home)
    assert comp.properties["worldReadable"] == "False"


def test_generic_sqlite_and_json_files_are_not_matched(tmp_path):
    # Deliberately narrow patterns -- a generic "*.sqlite"/"*.json" would
    # be far too broad (secrets.py's own *.sqlite pattern already covers
    # the credential-store angle for generic sqlite files).
    home = tmp_path
    (home / "some_database.sqlite").write_bytes(b"fake")
    (home / "history.json").write_text("{}")

    assert find_memory_store(home, home) == []


def test_missing_directory_returns_empty(tmp_path):
    assert find_memory_store(tmp_path / "does-not-exist", tmp_path) == []
