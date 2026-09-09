"""Lightweight structural check for a harness-aibom document.

This is *not* a full CycloneDX 1.6 schema validator -- reproducing that
schema exactly here would be its own maintenance burden, and general
CycloneDX validity is better checked with a dedicated tool (this package's
own test suite validates its example output against `cyclonedx-python-lib`
for exactly that reason -- see tests/test_cyclonedx_schema.py). What this
checks is specific to harness-aibom: the envelope is present, every
component/service carries a recognized harness-aibom:componentClass in the
array it actually belongs in, and -- as of v0.8.0 -- the document's own
graph is internally consistent: no duplicate bom-ref, no dependency edge
that points at nothing, no malformed hash. None of that is checked by a
generic CycloneDX schema validator either -- a schema has no idea what a
*valid* bom-ref is beyond "a string", so it can't know `dependsOn:
["typo-ref"]` points at nothing. `find_orphan_components()` below is a
related but deliberately separate check: a component/service the
dependency graph never reaches from the root is still a *structurally
valid* document (schema-valid AND passes every check in
`validate_document()`), just possibly a scanner bug or a hand-edit gone
wrong -- see its own docstring for why that's a warning, not an error.
"""

from __future__ import annotations

import re

from .model import CDX_TYPE_FOR_CLASS, SERVICE_CLASSES

REQUIRED_TOP_LEVEL = ("bomFormat", "specVersion", "components")

#: cyclonedx.py's own ROOT_BOM_REF literal, duplicated here rather than
#: imported -- this module also validates hand-crafted documents that
#: never went through cyclonedx.py at all, so the real fallback is always
#: whatever `metadata.component['bom-ref']` says; this is only the
#: default when that's missing entirely (itself already flagged
#: elsewhere as a document with no identifiable root).
_DEFAULT_ROOT_BOM_REF = "harness-root"


def _properties_of(entry: dict) -> dict[str, str]:
    return {p.get("name"): p.get("value") for p in entry.get("properties", [])}


def validate_document(data: dict) -> list[str]:
    errors: list[str] = []

    for key in REQUIRED_TOP_LEVEL:
        if key not in data:
            errors.append(f"missing top-level field {key!r}")

    if "bomFormat" in data and data["bomFormat"] != "CycloneDX":
        errors.append(f"bomFormat must be 'CycloneDX', got {data['bomFormat']!r}")

    for i, comp in enumerate(data.get("components", [])):
        label = f"components[{i}] ({comp.get('name')!r})"
        cls = _properties_of(comp).get("harness-aibom:componentClass")

        if cls is None:
            errors.append(f"{label} missing harness-aibom:componentClass")
            continue
        if cls in SERVICE_CLASSES:
            errors.append(f"{label} has componentClass {cls!r}, which belongs in 'services', not 'components'")
            continue
        if cls not in CDX_TYPE_FOR_CLASS:
            errors.append(f"{label} has unknown componentClass {cls!r}")
            continue

        expected_type = CDX_TYPE_FOR_CLASS[cls]
        if comp.get("type") != expected_type:
            errors.append(f"{label} type={comp.get('type')!r}, expected {expected_type!r} for componentClass {cls!r}")

    for i, svc in enumerate(data.get("services", [])):
        label = f"services[{i}] ({svc.get('name')!r})"
        cls = _properties_of(svc).get("harness-aibom:componentClass")

        if cls is None:
            errors.append(f"{label} missing harness-aibom:componentClass")
        elif cls not in SERVICE_CLASSES:
            errors.append(f"{label} has componentClass {cls!r}, which belongs in 'components', not 'services'")

    errors += _check_referential_integrity(data)
    return errors


def _all_bom_refs(data: dict) -> dict[str, list[str]]:
    """bom-ref -> every location it was found at (root, `components[i]`,
    `services[i]`) -- a list, not a set, specifically so a bom-ref used
    twice shows up with more than one location instead of silently
    collapsing, the same "don't lose the second occurrence" discipline
    `report.py`'s `_split_properties()` already applies to repeated
    property names.
    """
    refs: dict[str, list[str]] = {}
    root_ref = data.get("metadata", {}).get("component", {}).get("bom-ref")
    if root_ref:
        refs.setdefault(root_ref, []).append("metadata.component")
    for i, comp in enumerate(data.get("components", [])):
        ref = comp.get("bom-ref")
        if ref:
            refs.setdefault(ref, []).append(f"components[{i}]")
    for i, svc in enumerate(data.get("services", [])):
        ref = svc.get("bom-ref")
        if ref:
            refs.setdefault(ref, []).append(f"services[{i}]")
    return refs


def _check_referential_integrity(data: dict) -> list[str]:
    """Duplicate bom-refs, dangling `dependencies[]` edges (both a
    dependency entry's own `ref` and every `dependsOn` target), and a
    malformed SHA-256 `hashes[]` entry. All genuinely broken, not merely
    unusual -- a generic CycloneDX consumer that trusts `dependsOn` to
    resolve, or trusts a `hashes[]` entry to actually be the digest it
    claims, would silently mis-render or fail on any of these. This is
    exactly the class of bug this project's own diff-identity fix (v0.2.3,
    SPEC.md) and blast-radius-direction fix (v0.5.1) were caught by a
    reviewer rather than this tool -- these checks are the ones that would
    have caught a bug in that same family automatically, on any document,
    not just this scanner's own output.
    """
    errors: list[str] = []
    refs_seen = _all_bom_refs(data)
    for ref, locations in refs_seen.items():
        if len(locations) > 1:
            errors.append(f"duplicate bom-ref {ref!r}: appears at {', '.join(locations)}")

    known_refs = set(refs_seen)
    for i, dep in enumerate(data.get("dependencies", [])):
        ref = dep.get("ref")
        if ref not in known_refs:
            errors.append(f"dependencies[{i}].ref {ref!r} does not match any known bom-ref")
        for target in dep.get("dependsOn", []):
            if target not in known_refs:
                errors.append(
                    f"dependencies[{i}] ({ref!r}) dependsOn {target!r}, which does not match any known bom-ref"
                )

    for i, comp in enumerate(data.get("components", [])):
        for h in comp.get("hashes", []):
            if h.get("alg") == "SHA-256":
                content = h.get("content") or ""
                if not re.fullmatch(r"[0-9a-f]{64}", content):
                    errors.append(f"components[{i}] ({comp.get('name')!r}) has a malformed SHA-256 hash: {content!r}")

    return errors


def find_orphan_components(data: dict) -> list[str]:
    """bom-refs (components/services only, never the root itself) that
    `dependencies[]` never actually reaches by walking from the root --
    present in the document, but structurally disconnected from the
    harness graph. Still a fully *valid* CycloneDX document (an orphan
    breaks no rule `validate_document()` checks above) -- most likely a
    scanner bug (a component was registered but never related to
    anything) or a hand-edit that removed an edge without removing the
    component it pointed at. Deliberately kept OUT of `validate_document()`
    and its error list for exactly that reason: see cli.py's
    `_run_validate`, which prints these as warnings (same "informational,
    not fatal" treatment `scan`'s own `doc.warnings` already gets), never
    fails the command by itself.
    """
    root_ref = data.get("metadata", {}).get("component", {}).get("bom-ref") or _DEFAULT_ROOT_BOM_REF
    edges: dict[str, list[str]] = {}
    for dep in data.get("dependencies", []):
        edges.setdefault(dep.get("ref"), []).extend(dep.get("dependsOn", []))

    reachable: set[str] = set()
    queue = [root_ref]
    while queue:
        node = queue.pop()
        if node in reachable:
            continue
        reachable.add(node)
        queue.extend(edges.get(node, []))

    all_refs = {c.get("bom-ref") for c in data.get("components", [])}
    all_refs |= {s.get("bom-ref") for s in data.get("services", [])}
    return sorted(ref for ref in all_refs if ref and ref not in reachable)
