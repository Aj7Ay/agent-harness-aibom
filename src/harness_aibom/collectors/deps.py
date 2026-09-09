"""Best-effort Python dependency inventory for the *scanned harness's own*
installation -- not this package's own dependencies.

Confirmed generic, not harness-specific guessing: every Python package
installed the standard way (PEP 376/427) leaves a
`<name>-<version>.dist-info/METADATA` file next to it in some
`site-packages` directory, regardless of whether that directory sits
inside a venv, a pipx install, or a system Python -- this collector looks
for that universal convention under the harness's own `installDir`
(already captured from `hermes --version`/`openclaw --version`), rather
than assuming one specific layout the way earlier collectors in this
project were burned by (e.g. hook script storage locations, still
unconfirmed -- see hermes.py).

Absence is not an error, and never raises: not every harness reports an
`installDir`; not every `installDir` is reachable from wherever this scan
happens to run (a different machine, a container); and even when
reachable, this only finds anything if a `site-packages` directory
actually exists somewhere under it -- true for a venv or pipx install,
not for e.g. a single compiled binary with no Python packages alongside
it at all.
"""

from __future__ import annotations

from pathlib import Path

from ..model import Component
from ..paths import relative_to_or_none


def _parse_metadata(text: str) -> tuple[str | None, str | None]:
    """(name, version) from a PEP 566-shaped METADATA file's `Name:`/
    `Version:` header lines -- the two fields every such file has,
    regardless of packaging tool. Stops at the first blank line (the
    header/body boundary) so a `Name:`/`Version:`-looking line inside a
    long-description body is never mistaken for the real header.
    """
    name = version = None
    for line in text.splitlines():
        if not line.strip():
            break
        if line.startswith("Name:") and name is None:
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:") and version is None:
            version = line.split(":", 1)[1].strip()
        if name and version:
            break
    return name, version


def discover_python_dependencies(install_dir: Path) -> list[Component]:
    if not install_dir.is_dir():
        return []

    found: list[Component] = []
    # Deliberately NOT deduplicated by name across different site-packages
    # directories. Confirmed real bug from an earlier version of this
    # function that did: a pipx venv sitting beside a vendored tree (or
    # pip's own _vendor, or a nested venv) commonly produces a *second*
    # site-packages under the same installDir, and "first sorted directory
    # wins, skip the rest" picked an arbitrary copy -- silently, with no
    # signal that a second, disagreeing copy existed at all. Worse: since
    # the loser was never re-examined on a later scan either, a real
    # version bump to the *actually-running* copy could be invisible to
    # `diff` if the discarded copy happened to sort first and never
    # changed -- exactly the kind of drift a dependency inventory exists
    # to catch. Now: one component per (site_packages, name) pair, so two
    # disagreeing copies both show up, distinguishably, and `diff` never
    # has to silently pick a winner.
    #
    # `relPath` -- the identity `diff` actually keys on (diff.py prefers
    # relPath over path over bare name) -- is deliberately NOT the
    # dist-info directory itself, even though that's the real, literal
    # thing on disk. Confirmed real bug from an earlier version of *this*
    # fix that used the dist-info path as relPath: a dist-info directory
    # name embeds its own version (`openai-2.0.0.dist-info`), and pip
    # upgrades a package by deleting the old directory and creating a new
    # one, never renaming in place -- so relPath itself changed on every
    # single version bump, before `diff` ever got to compare `version`.
    # Every upgrade read as one entry removed and a new, unrelated-looking
    # one added, never as a "changed" entry -- which defeated the
    # `harness-aibom:version` comparison added for exactly this class, and
    # turned an N-package upgrade into 2N noisy diff lines a reviewer has
    # to manually re-pair by hand. Fixed by keying identity on the
    # `site_packages` directory (stable across an in-place upgrade) plus
    # the package name (needed since one site_packages dir holds many
    # packages), joined with "::" since a package name can itself contain
    # "/" (a namespace package) and would otherwise be ambiguous as a
    # path segment. The real dist-info path is kept too, as `distDir`, so
    # nothing about exactly which directory a given scan found is lost --
    # it's just no longer what identity is computed from. Two disagreeing
    # copies in *different* site_packages directories are still fully
    # distinguishable, since their relPath differs on the site_packages
    # part.
    #
    # rglob is safe here specifically because install_dir is a scoped,
    # single-package install directory (confirmed from `--version`
    # output), not an arbitrary/huge directory tree -- unlike a
    # filesystem-wide search, this can't run away.
    for site_packages in sorted(p for p in install_dir.rglob("site-packages") if p.is_dir()):
        for dist_info in sorted(site_packages.glob("*.dist-info")):
            metadata_path = dist_info / "METADATA"
            try:
                text = metadata_path.read_text(errors="replace")
            except OSError:
                continue
            name, version = _parse_metadata(text)
            if not name:
                continue

            comp = Component(component_class="dependency", name=name)
            comp.set("path", str(dist_info))
            comp.set("distDir", relative_to_or_none(dist_info, install_dir))
            site_packages_rel = relative_to_or_none(site_packages, install_dir)
            if site_packages_rel is not None:
                comp.set("relPath", f"{site_packages_rel}::{name}")
            if version:
                comp.version = version
                comp.set("purl", f"pkg:pypi/{name.lower().replace('_', '-')}@{version}")
            found.append(comp)
    return found
