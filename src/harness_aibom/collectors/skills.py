"""Shared skill discovery.

A real skill catalog isn't flat -- confirmed against a live Hermes box's
`~/.hermes/skills/`, it's grouped into category folders (`creative`,
`devops`, `productivity`, ...), each holding many individual skills one
level deeper (`creative/manim-video/SKILL.md`), each of those carrying its
own `scripts/`, `references/`, `templates/`. This module finds every
`SKILL.md` at any depth under a skills directory, so it works for that
nested layout and for a flat one-level layout alike.
"""

from __future__ import annotations

from pathlib import Path

from ..fingerprint import sha256_directory
from ..model import Component


def discover_skills(skills_dir: Path) -> list[Component]:
    if not skills_dir.is_dir():
        return []

    out = []
    for skill_md in sorted(skills_dir.rglob("SKILL.md")):
        skill_dir = skill_md.parent
        rel_parts = skill_dir.relative_to(skills_dir).parts

        comp = Component(component_class="skill", name="/".join(rel_parts))
        comp.set("path", str(skill_dir))
        if len(rel_parts) > 1:
            comp.set("category", rel_parts[0])
        # Hash the whole skill directory, not just SKILL.md -- scripts/
        # and references/ sitting next to it are exactly where a poisoned
        # skill would carry its payload, and a SKILL.md-only hash would
        # miss any change to them entirely.
        comp.set("sha256", sha256_directory(skill_dir))

        lines = skill_md.read_text(errors="replace").splitlines()
        if lines:
            comp.set("description", lines[0].lstrip("# ").strip()[:200])

        out.append(comp)
    return out
