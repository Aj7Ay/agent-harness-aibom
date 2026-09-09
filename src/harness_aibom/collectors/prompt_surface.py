"""Prompt/instruction-surface discovery: well-known, cross-project
instruction filenames found anywhere under a harness's own directory.

Confirmed generic, not harness-specific guessing, the same way deps.py's
PEP 376/427 convention is: `AGENTS.md` is a real, public, cross-tool
convention (https://agents.md -- adopted by multiple independent coding
agents, not invented by this project), and `CLAUDE.md` is Claude Code's
own well-documented convention. Neither is confirmed specifically for
Hermes or OpenClaw from this project's source material -- unlike
`SKILL.md` (confirmed via the CAASP course material) or `config.yaml`
(same), there's no confirmed evidence either harness actually reads
these files. They're recorded here on the same "absence is not an
error, presence doesn't over-claim relevance" basis as secrets.py's
recursive credential-filename scan: if a file with one of these names
exists in the harness's own tree, it's worth an operator's attention
regardless of whether this specific harness is confirmed to load it,
since an agent's *effective* behavior is shaped by whatever instructions
it actually reads -- SPEC.md section 5 has named this exact gap
("instructions are part of the effective agent behavior") since v0.2.0.

Fingerprinted like a skill or hook (a sha256 of file content) -- unlike
secrets_surface/memory_store, an instruction file's content is meant to
be read and reasoned about, not kept private, and a fingerprint is
exactly the kind of "did this change since I last looked" signal this
class exists to provide.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..fingerprint import sha256_file
from ..model import Component
from ..paths import is_symlink_outside_home, relative_to_or_none

#: Exact filenames only, matched case-sensitively -- both are
#: conventionally written with this exact casing; a loose
#: case-insensitive or substring match would risk false positives the
#: way secrets.py's own broader patterns already do (see security.py's
#: HEURISTIC_PATTERNS) for comparatively little gain, since these are
#: specific, known filenames, not a family of naming variations the way
#: credential files are.
PROMPT_SURFACE_FILENAMES = frozenset({"AGENTS.md", "CLAUDE.md"})


def find_prompt_surface(directory: Path, home: Path) -> list[Component]:
    """`home` is the harness's own scan root, used only to compute
    `relPath` (see paths.py) -- same contract as
    `secrets.find_secrets_surface()`.
    """
    if not directory.is_dir():
        return []

    found: list[Component] = []
    for root, _dirs, files in os.walk(directory, onerror=lambda exc: None):
        for filename in sorted(files):
            if filename not in PROMPT_SURFACE_FILENAMES:
                continue
            file_path = Path(root) / filename
            comp = Component(component_class="prompt_surface", name=str(file_path.relative_to(directory)))
            comp.set("path", str(file_path))
            comp.set("relPath", relative_to_or_none(file_path, home))
            # symlink/pathOutsideHome (v0.6.1): the same check hooks.py
            # has made since v0.1.9 -- confirmed real gap fixed here, an
            # instruction file whose real content lives outside the
            # harness tree (e.g. a prompt-injection payload swapped in
            # via a symlink escaping --home) is exactly the case worth
            # naming, the same shape as the hook bug this mirrors.
            comp.set("symlink", file_path.is_symlink())
            if is_symlink_outside_home(file_path, home):
                comp.set("pathOutsideHome", True)
            # None (unreadable -- missing, permission denied) is a no-op
            # via Component.set(), same as every other opportunistic
            # fingerprint in this codebase; presence is still recorded
            # even when content can't be.
            comp.set("sha256", sha256_file(file_path))
            found.append(comp)
    return found
