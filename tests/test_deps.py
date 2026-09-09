from pathlib import Path

from harness_aibom.collectors.deps import discover_python_dependencies


def _make_dist_info(site_packages: Path, name: str, version: str) -> None:
    dist_info = site_packages / f"{name}-{version}.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: a package\n\nA long description.\n"
    )


def test_finds_packages_under_a_venv_style_site_packages(tmp_path):
    install_dir = tmp_path / "hermes-agent"
    site_packages = install_dir / "lib" / "python3.11" / "site-packages"
    _make_dist_info(site_packages, "PyYAML", "6.0.1")
    _make_dist_info(site_packages, "openai", "2.24.0")

    found = discover_python_dependencies(install_dir)
    names = {c.name for c in found}
    assert names == {"PyYAML", "openai"}

    pyyaml = next(c for c in found if c.name == "PyYAML")
    assert pyyaml.version == "6.0.1"
    assert pyyaml.properties["purl"] == "pkg:pypi/pyyaml@6.0.1"
    assert pyyaml.component_class == "dependency"


def test_missing_install_dir_returns_empty(tmp_path):
    assert discover_python_dependencies(tmp_path / "does-not-exist") == []


def test_install_dir_with_no_site_packages_returns_empty(tmp_path):
    install_dir = tmp_path / "compiled-binary-only"
    install_dir.mkdir()
    (install_dir / "hermes").write_text("#!/bin/sh\necho fake binary\n")
    assert discover_python_dependencies(install_dir) == []


def test_duplicate_package_across_two_site_packages_dirs_is_not_silently_collapsed(tmp_path):
    # Regression test: an independent reviewer found the previous version
    # of this function deduplicated by name alone across *different*
    # site-packages directories, "first sorted directory wins" -- a
    # second, disagreeing copy (a pipx venv beside a vendored tree, a
    # nested venv, etc.) was silently dropped rather than shown. Both
    # copies must now be visible, distinguishable by their relPath.
    install_dir = tmp_path / "install"
    _make_dist_info(install_dir / "venv-a" / "site-packages", "requests", "2.31.0")
    _make_dist_info(install_dir / "venv-b" / "site-packages", "requests", "2.31.0")

    found = discover_python_dependencies(install_dir)
    matches = [c for c in found if c.name == "requests"]
    assert len(matches) == 2
    rel_paths = {c.properties["relPath"] for c in matches}
    assert rel_paths == {
        "venv-a/site-packages/requests-2.31.0.dist-info",
        "venv-b/site-packages/requests-2.31.0.dist-info",
    }


def test_a_version_bump_masked_by_a_second_site_packages_copy_is_now_visible(tmp_path):
    # The concrete failure an independent reviewer reproduced: a stale
    # copy in one site-packages dir (sorts first) used to hide a real
    # version change in the *other* -- discover_python_dependencies()
    # reported only the stale 0.1.0, and a later bump of the real copy
    # to 2.0.0 produced no visible change at all, since the stale copy
    # never changed and was the only one ever looked at.
    install_dir = tmp_path / "install"
    _make_dist_info(install_dir / "other" / "lib" / "site-packages", "openai", "0.1.0")
    _make_dist_info(install_dir / "venv" / "lib" / "python3.12" / "site-packages", "openai", "1.99.1")

    before = {(c.properties.get("relPath"), c.version) for c in discover_python_dependencies(install_dir) if c.name == "openai"}
    assert before == {
        ("other/lib/site-packages/openai-0.1.0.dist-info", "0.1.0"),
        ("venv/lib/python3.12/site-packages/openai-1.99.1.dist-info", "1.99.1"),
    }

    # Bump only the real copy -- pip deletes the old dist-info and
    # creates a new one, so the directory name itself changes.
    import shutil

    shutil.rmtree(install_dir / "venv" / "lib" / "python3.12" / "site-packages" / "openai-1.99.1.dist-info")
    _make_dist_info(install_dir / "venv" / "lib" / "python3.12" / "site-packages", "openai", "2.0.0")

    after = {(c.properties.get("relPath"), c.version) for c in discover_python_dependencies(install_dir) if c.name == "openai"}
    assert after == {
        ("other/lib/site-packages/openai-0.1.0.dist-info", "0.1.0"),
        ("venv/lib/python3.12/site-packages/openai-2.0.0.dist-info", "2.0.0"),
    }
    # The stale copy is unaffected and the real bump is fully visible --
    # neither masked the other.
    assert before - after == {("venv/lib/python3.12/site-packages/openai-1.99.1.dist-info", "1.99.1")}
    assert after - before == {("venv/lib/python3.12/site-packages/openai-2.0.0.dist-info", "2.0.0")}


def test_dist_info_without_a_readable_metadata_file_is_skipped(tmp_path):
    install_dir = tmp_path / "install"
    site_packages = install_dir / "site-packages"
    site_packages.mkdir(parents=True)
    (site_packages / "broken-1.0.dist-info").mkdir()  # no METADATA file inside

    assert discover_python_dependencies(install_dir) == []


def test_metadata_header_stops_at_the_first_blank_line(tmp_path):
    # A long description that happens to contain "Name:"/"Version:"-
    # looking text must not be mistaken for the real header.
    install_dir = tmp_path / "install"
    site_packages = install_dir / "site-packages"
    dist_info = site_packages / "realpkg-1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        "Name: realpkg\nVersion: 1.0\n\nName: not-a-real-package\nVersion: 99.0\n"
    )

    [comp] = discover_python_dependencies(install_dir)
    assert comp.name == "realpkg"
    assert comp.version == "1.0"
