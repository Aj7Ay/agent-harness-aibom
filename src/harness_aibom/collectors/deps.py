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
    seen: set[str] = set()
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
            if not name or name in seen:
                continue
            seen.add(name)

            comp = Component(component_class="dependency", name=name)
            if version:
                comp.version = version
                comp.set("purl", f"pkg:pypi/{name.lower().replace('_', '-')}@{version}")
            found.append(comp)
    return found
