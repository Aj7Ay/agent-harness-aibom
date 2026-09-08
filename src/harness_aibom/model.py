"""Core in-memory data model for a Harness AIBOM, independent of the
CycloneDX serialization in cyclonedx.py. See SPEC.md for the reasoning
behind the component taxonomy and relationship vocabulary defined here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: The fixed vocabulary of relationship verbs. Keep this small and closed --
#: every verb here must be meaningful to diff.py and to a human reading the
#: harness-aibom:relationship properties in the JSON output.
RELATIONSHIP_VERBS = {"uses", "loads", "invokes", "executes", "accesses", "approves", "pulls"}

#: harness-aibom componentClass -> CycloneDX 1.6 native `type`.
#: See SPEC.md section 2 for the reasoning behind each mapping.
CDX_TYPE_FOR_CLASS = {
    "runtime": "application",
    "model_endpoint": "service",
    "model": "machine-learning-model",
    "configuration": "file",
    "skill": "library",
    "mcp_server": "service",
    "hook": "file",
    "secrets_surface": "data",
}


def make_bom_ref(component_class: str, name: str) -> str:
    """Deterministic, human-readable bom-ref: `<class>:<slug(name)>`.

    Not guaranteed unique across an entire document by itself -- two
    same-named components in different directories (e.g. two `.env` files)
    would collide. HarnessDocument.add() disambiguates on insert.
    """
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip()).strip("-").lower() or "unnamed"
    return f"{component_class}:{slug}"


@dataclass
class Component:
    component_class: str
    name: str
    version: str | None = None
    bom_ref: str = ""
    properties: dict[str, str] = field(default_factory=dict)
    relationships: list[tuple[str, str]] = field(default_factory=list)  # (verb, target_bom_ref)

    def __post_init__(self) -> None:
        if self.component_class not in CDX_TYPE_FOR_CLASS:
            raise ValueError(f"unknown component_class {self.component_class!r}")
        if not self.bom_ref:
            self.bom_ref = make_bom_ref(self.component_class, self.name)

    @property
    def cdx_type(self) -> str:
        return CDX_TYPE_FOR_CLASS[self.component_class]

    def set(self, name: str, value) -> Component:
        """Set a harness-aibom:<name> property. A no-op for None/"" so
        collectors can call this unconditionally on fields that may be
        missing from whatever they scraped, instead of guarding every call.
        """
        if value is None or value == "":
            return self
        self.properties[name] = str(value)
        return self

    def relate(self, verb: str, target: Component | str) -> Component:
        if verb not in RELATIONSHIP_VERBS:
            raise ValueError(f"unknown relationship verb {verb!r}, expected one of {sorted(RELATIONSHIP_VERBS)}")
        target_ref = target.bom_ref if isinstance(target, Component) else target
        self.relationships.append((verb, target_ref))
        return self


@dataclass
class HarnessDocument:
    """One scanned harness: everything a collector found, plus the edges
    from the harness itself to each top-level thing it uses/loads/etc.

    The harness itself is *not* one more Component in `components` -- it is
    represented separately (as `bom.metadata.component` in cyclonedx.py) so
    it never collides with, say, a `runtime` component for the underlying
    binary. `root_relationships` holds the edges out of that root.
    """

    harness_name: str
    runtime_kind: str  # "hermes" | "openclaw"
    hostname: str
    components: list[Component] = field(default_factory=list)
    root_relationships: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add(self, component: Component, verb: str = "uses") -> Component:
        if verb not in RELATIONSHIP_VERBS:
            raise ValueError(f"unknown relationship verb {verb!r}, expected one of {sorted(RELATIONSHIP_VERBS)}")
        existing_refs = {c.bom_ref for c in self.components}
        if component.bom_ref in existing_refs:
            base, n = component.bom_ref, 2
            while f"{base}-{n}" in existing_refs:
                n += 1
            component.bom_ref = f"{base}-{n}"
        self.components.append(component)
        self.root_relationships.append((verb, component.bom_ref))
        return component

    def warn(self, message: str) -> None:
        self.warnings.append(message)
