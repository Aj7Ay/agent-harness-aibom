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

import os
from pathlib import Path

from ..fingerprint import sha256_directory
from ..model import Component
from ..paths import relative_to_or_none


def _find_skill_md_files(skills_dir: Path) -> list[Path]:
    # os.walk(onerror=...) skips a subdirectory it can't list instead of
    # raising -- confirmed necessary scanning root-owned skills as a
    # non-root user, a realistic lab condition. Path.rglob() would instead
    # propagate that PermissionError and abort discovery of every skill
    # after the unreadable one, not just that one skill.
    found = []
    for root, _dirs, files in os.walk(skills_dir, onerror=lambda exc: None):
        if "SKILL.md" in files:
            found.append(Path(root) / "SKILL.md")
    return sorted(found)


def discover_skills(skills_dir: Path, home: Path) -> list[Component]:
    """`home` is the harness's own scan root (e.g. what `--home` resolved
    to) -- used only to compute `relPath`, a host-independent identity for
    `diff` (see paths.py). Every real caller has it on hand already.
    """
    if not skills_dir.is_dir():
        return []

    out = []
    for skill_md in _find_skill_md_files(skills_dir):
        skill_dir = skill_md.parent
        rel_parts = skill_dir.relative_to(skills_dir).parts

        comp = Component(component_class="skill", name="/".join(rel_parts))
        comp.set("path", str(skill_dir))
        comp.set("relPath", relative_to_or_none(skill_dir, home))
        if len(rel_parts) > 1:
            comp.set("category", rel_parts[0])
        # Hash the whole skill directory, not just SKILL.md -- scripts/
        # and references/ sitting next to it are exactly where a poisoned
        # skill would carry its payload, and a SKILL.md-only hash would
        # miss any change to them entirely.
        comp.set("sha256", sha256_directory(skill_dir))

        try:
            lines = skill_md.read_text(errors="replace").splitlines()
        except OSError:
            # Found the file (it's in `files` above) but can't open it --
            # e.g. root-owned, scanning as non-root. Record the skill
            # without a description rather than crashing the scan.
            lines = []
        if lines:
            comp.set("description", lines[0].lstrip("# ").strip()[:200])

        out.append(comp)
    return out
