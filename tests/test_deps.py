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
    # relPath is version-independent (site_packages::name), distDir is the
    # exact, version-bearing dist-info directory -- see discover_python_
    # dependencies()'s comment for why identity can't be the dist-info dir.
    assert pyyaml.properties["relPath"] == "lib/python3.11/site-packages::PyYAML"
    assert pyyaml.properties["distDir"] == "lib/python3.11/site-packages/PyYAML-6.0.1.dist-info"


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
        "venv-a/site-packages::requests",
        "venv-b/site-packages::requests",
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
        ("other/lib/site-packages::openai", "0.1.0"),
        ("venv/lib/python3.12/site-packages::openai", "1.99.1"),
    }

    # Bump only the real copy -- pip deletes the old dist-info and
    # creates a new one, so the directory name itself changes.
    import shutil

    shutil.rmtree(install_dir / "venv" / "lib" / "python3.12" / "site-packages" / "openai-1.99.1.dist-info")
    _make_dist_info(install_dir / "venv" / "lib" / "python3.12" / "site-packages", "openai", "2.0.0")

    after = {(c.properties.get("relPath"), c.version) for c in discover_python_dependencies(install_dir) if c.name == "openai"}
    assert after == {
        ("other/lib/site-packages::openai", "0.1.0"),
        ("venv/lib/python3.12/site-packages::openai", "2.0.0"),
    }
    # The stale copy is unaffected; the real bump keeps the *same*
    # relPath identity across the upgrade (unlike the dist-info path,
    # which changed) -- exactly one entry differs, by version only.
    assert before - after == {("venv/lib/python3.12/site-packages::openai", "1.99.1")}
    assert after - before == {("venv/lib/python3.12/site-packages::openai", "2.0.0")}


def test_dist_info_without_a_readable_metadata_file_is_skipped(tmp_path):
    install_dir = tmp_path / "install"
    site_packages = install_dir / "site-packages"
    site_packages.mkdir(parents=True)
    (site_packages / "broken-1.0.dist-info").mkdir()  # no METADATA file inside

    assert discover_python_dependencies(install_dir) == []


def test_license_and_author_email_are_captured(tmp_path):
    install_dir = tmp_path / "install"
    site_packages = install_dir / "site-packages"
    dist_info = site_packages / "requests-2.31.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        "Name: requests\nVersion: 2.31.0\nLicense: MIT\n"
        "Author-email: Kenneth Reitz <me@kennethreitz.org>\n\nbody\n"
    )

    [comp] = discover_python_dependencies(install_dir)
    assert comp.properties["license"] == "MIT"
    assert comp.properties["supplierName"] == "Kenneth Reitz"
    assert comp.properties["supplierEmail"] == "me@kennethreitz.org"


def test_obfuscated_non_email_author_email_is_dropped_not_passed_through(tmp_path):
    # Regression test: an independent reviewer found a deliberately-
    # obfuscated, human-readable non-address (a real pattern some
    # packages use in Author-email to dodge scrapers) flowed straight
    # through into supplierEmail and, from there, into CycloneDX's
    # native contact.email field -- producing a document that failed
    # strict schema validation (idn-email format) while this package's
    # own `validate` command still reported it valid. The name half of
    # the same "Name <...>" form is still kept -- it's a real name,
    # independent of whether the email half is garbled.
    install_dir = tmp_path / "install"
    site_packages = install_dir / "site-packages"
    dist_info = site_packages / "oddpkg-1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        "Name: oddpkg\nVersion: 1.0\nAuthor-email: Jane Doe <jane at example dot com>\n\nbody\n"
    )

    [comp] = discover_python_dependencies(install_dir)
    assert comp.properties["supplierName"] == "Jane Doe"
    assert "supplierEmail" not in comp.properties


def test_bare_author_email_that_fails_the_shape_check_becomes_the_supplier_name(tmp_path):
    # Regression test: an independent reviewer found a *bare* (no "Name
    # <...>" form) Author-email that contains "@" but doesn't look like a
    # real email (e.g. "Contact us @ example.com") used to be dropped
    # entirely -- losing the real fact that a named contact exists, for
    # the sake of rejecting a fact that wasn't real. With no <...> form
    # to supply a name separately, the whole string becomes the supplier
    # name instead (free text, no schema risk), rather than nothing at
    # all.
    install_dir = tmp_path / "install"
    site_packages = install_dir / "site-packages"
    dist_info = site_packages / "oddpkg-1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        "Name: oddpkg\nVersion: 1.0\nAuthor-email: Contact us @ example.com\n\nbody\n"
    )

    [comp] = discover_python_dependencies(install_dir)
    assert comp.properties["supplierName"] == "Contact us @ example.com"
    assert "supplierEmail" not in comp.properties


def test_bare_author_and_bare_author_email_are_both_captured(tmp_path):
    install_dir = tmp_path / "install"
    site_packages = install_dir / "site-packages"
    dist_info = site_packages / "oddpkg-1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        "Name: oddpkg\nVersion: 1.0\nAuthor: Jane Doe\nAuthor-email: jane@example.com\n\nbody\n"
    )

    [comp] = discover_python_dependencies(install_dir)
    assert comp.properties["supplierName"] == "Jane Doe"
    assert comp.properties["supplierEmail"] == "jane@example.com"


def test_maintainer_is_used_only_when_author_is_entirely_absent(tmp_path):
    install_dir = tmp_path / "install"
    site_packages = install_dir / "site-packages"
    dist_info = site_packages / "oldpkg-1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        "Name: oldpkg\nVersion: 1.0\n"
        "Maintainer-email: New Team <team@example.com>\n\nbody\n"
    )

    [comp] = discover_python_dependencies(install_dir)
    assert comp.properties["supplierName"] == "New Team"
    assert comp.properties["supplierEmail"] == "team@example.com"


def test_a_partial_author_is_not_topped_up_from_maintainer(tmp_path):
    # Author: (bare name, no email) is still "Author present" -- must not
    # then also pull an email from an unrelated Maintainer-email.
    install_dir = tmp_path / "install"
    site_packages = install_dir / "site-packages"
    dist_info = site_packages / "pkg-1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        "Name: pkg\nVersion: 1.0\nAuthor: Jane Doe\n"
        "Maintainer-email: someone-else@example.com\n\nbody\n"
    )

    [comp] = discover_python_dependencies(install_dir)
    assert comp.properties["supplierName"] == "Jane Doe"
    assert "supplierEmail" not in comp.properties


def test_unknown_license_and_author_placeholders_are_not_emitted(tmp_path):
    # setuptools/distutils's long-standing literal default when a package
    # declares neither -- must read as absent, not as a license/author
    # named "UNKNOWN".
    install_dir = tmp_path / "install"
    site_packages = install_dir / "site-packages"
    dist_info = site_packages / "pkg-1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        "Name: pkg\nVersion: 1.0\nLicense: UNKNOWN\nAuthor: UNKNOWN\n\nbody\n"
    )

    [comp] = discover_python_dependencies(install_dir)
    assert "license" not in comp.properties
    assert "supplierName" not in comp.properties


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
