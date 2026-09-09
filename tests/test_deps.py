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


def test_duplicate_package_across_two_site_packages_dirs_counted_once(tmp_path):
    install_dir = tmp_path / "install"
    _make_dist_info(install_dir / "venv-a" / "site-packages", "requests", "2.31.0")
    _make_dist_info(install_dir / "venv-b" / "site-packages", "requests", "2.31.0")

    found = discover_python_dependencies(install_dir)
    assert len([c for c in found if c.name == "requests"]) == 1


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
