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

import re
from pathlib import Path
from typing import NamedTuple

from ..model import Component
from ..paths import relative_to_or_none

#: "UNKNOWN" is setuptools/distutils's long-standing literal default for
#: Author/License when a package declares neither -- confirmed common in
#: the wild, not a real value a supplier or license field should ever
#: emit verbatim. Blank after stripping counts the same way.
_METADATA_PLACEHOLDERS = frozenset({"", "UNKNOWN"})

#: `Author-email`/`Maintainer-email` commonly follow RFC 822's
#: "Name <email>" display form (the shape a `[project.authors]` table in
#: pyproject.toml gets flattened into by every PEP 621-aware build
#: backend) -- extracted here so a package that never sets a bare
#: `Author:` line at all still yields a real supplier *name*, not just an
#: address.
_NAME_EMAIL_RE = re.compile(r"^(?P<name>.*?)\s*<(?P<email>[^<>]+)>\s*$")

#: A loose shape check, not full RFC 5321/6531 validation -- just enough
#: to reject something that obviously isn't an email address before it
#: reaches CycloneDX's native `contact.email` field, which the real
#: schema validates against the `idn-email` format. Confirmed real bug:
#: some packages write a deliberately-obfuscated, human-readable
#: non-address in `Author-email` (e.g. "jane at example dot com", to
#: dodge scrapers) -- with no check, that string flowed straight through
#: into a native CycloneDX field and produced a document that failed
#: strict schema validation while this package's own hand-rolled
#: `validate` command still reported it valid (that command only checks
#: envelope/componentClass shape, never CycloneDX's own format
#: constraints -- see SPEC.md section 5's "No JSON Schema file of our
#: own" limitation). Deliberately permissive on the *character set*
#: (idn-email allows non-ASCII local parts and domains) and strict only
#: on *shape*: exactly one "@", a non-empty local part, and a domain
#: with at least one ".".
_EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")


def _looks_like_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value))


class _Metadata(NamedTuple):
    name: str | None
    version: str | None
    license: str | None
    supplier_name: str | None
    supplier_email: str | None


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value if value not in _METADATA_PLACEHOLDERS else None


def _split_name_email(value: str | None) -> tuple[str | None, str | None]:
    """"Jane Doe <jane@example.com>" -> ("Jane Doe", "jane@example.com");
    a bare email or a bare name (no angle brackets) passes through as
    (None, value) / (value, None) respectively -- never guessed further
    than the RFC 822 form actually present. A value that doesn't look
    like a real email (see `_EMAIL_RE`) is never emitted as one, but
    isn't discarded outright either: with no `<...>` form to supply a
    name separately, the whole string becomes the supplier *name*
    instead (free text, no schema risk) -- confirmed real bug fixed
    here: a bare value containing "@" that failed the shape check (e.g.
    "Contact us @ example.com") used to be dropped entirely, losing a
    real fact (there IS a named contact here) for the sake of rejecting
    a fact that wasn't real (there's no actual email address). A name
    extracted from the "Name <...>" form is, as before, still kept even
    when its email half is garbled, since the two are independent facts.
    """
    value = _clean(value)
    if value is None:
        return None, None
    match = _NAME_EMAIL_RE.match(value)
    if match:
        name = _clean(match.group("name"))
        email = match.group("email").strip()
        return name, (email if _looks_like_email(email) else None)
    if "@" in value:
        return (None, value) if _looks_like_email(value) else (value, None)
    return value, None


def _parse_metadata(text: str) -> _Metadata:
    """The PEP 566-shaped METADATA header fields this collector uses --
    `Name:`/`Version:` (the two every such file has, regardless of
    packaging tool), `License:`, and a best-effort supplier name/email
    from `Author:`/`Author-email:`, falling back to `Maintainer:`/
    `Maintainer-email:` only when Author is entirely absent. Stops at the
    first blank line (the header/body boundary) so a header-line-looking
    string inside a long-description body is never mistaken for the real
    header.
    """
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            break
        for key in ("Name", "Version", "License", "Author", "Author-email", "Maintainer", "Maintainer-email"):
            prefix = f"{key}:"
            if line.startswith(prefix) and key not in fields:
                fields[key] = line[len(prefix):].strip()
                break

    author_name, author_email = _clean(fields.get("Author")), None
    if "Author-email" in fields:
        email_name, email_addr = _split_name_email(fields.get("Author-email"))
        author_name = author_name or email_name
        author_email = email_addr
    if author_name is None and author_email is None:
        # No Author at all -- Maintainer is the same shape, used only as
        # a fallback, never merged with a partial Author.
        author_name = _clean(fields.get("Maintainer"))
        if "Maintainer-email" in fields:
            email_name, email_addr = _split_name_email(fields.get("Maintainer-email"))
            author_name = author_name or email_name
            author_email = email_addr

    return _Metadata(
        name=_clean(fields.get("Name")),
        version=_clean(fields.get("Version")),
        license=_clean(fields.get("License")),
        supplier_name=author_name,
        supplier_email=author_email,
    )


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
            meta = _parse_metadata(text)
            if not meta.name:
                continue
            name = meta.name

            comp = Component(component_class="dependency", name=name)
            # Distinguishes this from an MCP launcher package (mcp.py
            # sets origin="mcp-launcher") -- see mcp.py's own comment for
            # why the distinction matters to security.py's
            # unpinned_dependency risk rule.
            comp.set("origin", "python-package")
            comp.set("path", str(dist_info))
            comp.set("distDir", relative_to_or_none(dist_info, install_dir))
            site_packages_rel = relative_to_or_none(site_packages, install_dir)
            if site_packages_rel is not None:
                comp.set("relPath", f"{site_packages_rel}::{name}")
            if meta.version:
                comp.version = meta.version
                comp.set("purl", f"pkg:pypi/{name.lower().replace('_', '-')}@{meta.version}")
            comp.set("license", meta.license)
            comp.set("supplierName", meta.supplier_name)
            comp.set("supplierEmail", meta.supplier_email)
            found.append(comp)
    return found
