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
import re
from pathlib import Path

import yaml

from ..fingerprint import sha256_directory
from ..model import Component
from ..paths import relative_to_or_none

#: Deterministic, closed-set markers this scanner looks for in a skill's
#: own SKILL.md prose -- v0.6.0, closing the gap SPEC.md has named since
#: v0.2.0 ("this scanner doesn't parse SKILL.md content to link a skill
#: to the servers/models it references"). Never an LLM, never fuzzy
#: inference: a skill's prose *mentioning* a configured server or a
#: shell tool is evidence the skill's author described some
#: relationship, not confirmation the skill actually invokes it at
#: runtime -- this scanner reads static files, never traces execution.
#: That's the "inferred" tier the security-analysis layer's blast-radius
#: work (SPEC.md section 11) deliberately left for later: everything
#: found here is recorded as a text mention, not a real graph edge.
#: Deliberately does NOT exclude "." from the character class -- most
#: real URLs have one in the hostname, and doing so would truncate
#: "https://api.example.com" at the first dot. Markdown/prose-adjacent
#: wrapping characters (quotes, angle brackets, a code-span backtick)
#: are excluded outright, since those never legitimately appear inside a
#: bare URL written in prose; trailing sentence punctuation a URL
#: happens to butt up against (a period, comma, closing paren/bracket)
#: is stripped afterward instead, in `_clean_url()`, so it doesn't also
#: eat a real mid-URL "." the way excluding it from the class would.
_URL_RE = re.compile(r"https?://[^\s<>\"'`]+")
_URL_TRAILING_PUNCTUATION = ".,;:)]}"


def _clean_url(url: str) -> str:
    return url.rstrip(_URL_TRAILING_PUNCTUATION)
_ENV_VAR_RE = re.compile(r"\$\{?([A-Z][A-Z0-9_]{2,})\}?\b")

#: Common CLI tool names indicating the skill's own prose describes
#: shell/network/execution activity -- a fixed, closed set, matched as
#: whole words only (never a substring -- "curly" must never match
#: "curl").
_SHELL_INDICATOR_WORDS = ("curl", "wget", "ssh", "git", "python", "pip", "npm", "npx", "docker", "kubectl")
_SHELL_INDICATOR_RE = re.compile(r"\b(" + "|".join(_SHELL_INDICATOR_WORDS) + r")\b")


def analyze_skill_content(text: str, known_server_names: frozenset[str] = frozenset()) -> dict[str, list[str]]:
    """Deterministic, closed-set matches over one skill's own SKILL.md
    text. `known_server_names` are the MCP server names this same scan
    already found in the harness's config -- a name is only reported as
    "referenced" if it's a real, configured server, never a guess at
    what an unrecognized name might mean. Every value is a sorted,
    deduplicated list; keys whose list would be empty are omitted
    entirely by the caller (`Component.set()` no-ops on ""), so a skill
    that mentions nothing stays unnoted rather than cluttered with empty
    properties.
    """
    return {
        "referencedServers": sorted(name for name in known_server_names if re.search(rf"\b{re.escape(name)}\b", text)),
        "urls": sorted({_clean_url(u) for u in _URL_RE.findall(text)}),
        "shellIndicators": sorted(set(_SHELL_INDICATOR_RE.findall(text))),
        "envVarReferences": sorted(set(_ENV_VAR_RE.findall(text))),
    }


#: YAML frontmatter at the very top of a file, `---`-delimited -- v0.8.2.
#: This is a real, documented, cross-project convention (Claude Code's own
#: Agent Skills format: `name`/`description` as the two fields that
#: matter for this scanner, `license`/`allowed-tools` optional), the same
#: "real, confirmed convention, not harness-specific guessing" basis
#: `prompt_surface.py`'s AGENTS.md/CLAUDE.md filenames already stand on
#: (SPEC.md section 13) -- not confirmed specifically for Hermes/OpenClaw
#: from this project's own source material, but a real filename/format
#: fact this scanner is allowed to recognize on sight either way.
_FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?\r?\n)---\r?\n?", re.DOTALL)


def _parse_frontmatter(text: str) -> dict:
    """The parsed frontmatter block, or `{}` for a SKILL.md with none at
    all (real and valid -- frontmatter isn't required) or malformed YAML.
    Never raises: same "record what's actually there, don't crash the
    scan over one bad file" discipline this module already applies to an
    unreadable SKILL.md below.
    """
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}
    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _strip_frontmatter(text: str) -> str:
    """`text` with a leading frontmatter block (if any) removed -- so the
    heading-based description fallback below reads the first line of the
    actual markdown body, not the literal `---` delimiter or a YAML
    `key: value` line a frontmatter-bearing SKILL.md with no `description:`
    field would otherwise produce.
    """
    match = _FRONTMATTER_RE.match(text)
    return text[match.end():] if match else text


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


def discover_skills(skills_dir: Path, home: Path, known_server_names: frozenset[str] = frozenset()) -> list[Component]:
    """`home` is the harness's own scan root (e.g. what `--home` resolved
    to) -- used only to compute `relPath`, a host-independent identity for
    `diff` (see paths.py). Every real caller has it on hand already.

    `known_server_names` (v0.6.0) -- the MCP server names this same scan
    already found in the harness's config -- feeds `analyze_skill_content()`
    below; defaults to empty (no server-reference analysis) so existing
    callers/tests are unaffected.
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
        sha256 = sha256_directory(skill_dir)
        comp.set("sha256", sha256)
        # v0.9.0: a real, directly *observed* fact (this scanner hashed
        # the directory's actual bytes itself) -- set alongside the
        # sha256 it describes so a reader can contrast it with this same
        # component's own `contentAnalysisConfidence` below, which is
        # genuinely *inferred* (a text mention in this skill's own prose,
        # never confirmation of runtime behavior). `skill_dir` is always
        # a real directory here (its own SKILL.md was just found inside
        # it), so this is never conditional the way digestConfidence is.
        if sha256:
            comp.set("sha256Confidence", "observed")

        try:
            text = skill_md.read_text(errors="replace")
        except OSError:
            # Found the file (it's in `files` above) but can't open it --
            # e.g. root-owned, scanning as non-root. Record the skill
            # without a description/content-analysis rather than
            # crashing the scan.
            text = ""
        if text:
            frontmatter = _parse_frontmatter(text)
            fm_name = frontmatter.get("name")
            fm_description = frontmatter.get("description")
            fm_license = frontmatter.get("license")
            allowed_tools = frontmatter.get("allowed-tools")

            # The declared `name:` is informational only -- `comp.name`
            # itself (directory-derived, above) stays the real identity
            # this component's bom-ref and `diff` matching are keyed on;
            # a SKILL.md author's own declared name is additive, same
            # "never replace the identity a real field already carries"
            # reasoning as every other harness-aibom: property.
            if isinstance(fm_name, str) and fm_name.strip():
                comp.set("frontmatterName", fm_name.strip())
            if isinstance(fm_license, str) and fm_license.strip():
                comp.set("license", fm_license.strip())
            if isinstance(allowed_tools, list):
                comp.set("allowedTools", ",".join(str(t) for t in allowed_tools))
            elif isinstance(allowed_tools, str) and allowed_tools.strip():
                comp.set("allowedTools", allowed_tools.strip())

            # A real `description:` field is a more reliable source than
            # guessing from the first markdown heading -- prefer it when
            # present, falling back to the heading heuristic otherwise.
            # `descriptionSource` records which one actually won, so a
            # reader never mistakes a heading-derived guess for an
            # author's own declared description.
            if isinstance(fm_description, str) and fm_description.strip():
                comp.set("description", fm_description.strip()[:200])
                comp.set("descriptionSource", "frontmatter")
            else:
                body = _strip_frontmatter(text)
                first_line = body.splitlines()[0] if body.splitlines() else ""
                comp.set("description", first_line.lstrip("# ").strip()[:200])
                comp.set("descriptionSource", "heading")

            analysis = analyze_skill_content(text, known_server_names)
            comp.set("referencedServers", ",".join(analysis["referencedServers"]))
            comp.set("shellIndicators", ",".join(analysis["shellIndicators"]))
            comp.set("envVarReferences", ",".join(analysis["envVarReferences"]))
            # URLs are the one field capped -- a skill's reference
            # material can legitimately cite dozens of documentation
            # links, and this property exists to flag "this skill talks
            # to the network", not to catalog every URL exhaustively
            # (the full text is still available via --home for anyone
            # who needs that).
            comp.set("urls", ",".join(analysis["urls"][:20]))
            # v0.9.0: formalizes the confidence distinction this module's
            # own docstring for analyze_skill_content() already states in
            # prose -- "a text mention... never confirmation the skill
            # actually invokes it at runtime" -- as a real, queryable
            # property, set only when there's actually something inferred
            # to tag (never fabricated for a skill whose analysis found
            # nothing at all). Deliberately scoped to exactly these four
            # fields, not the whole component: `sha256Confidence` above
            # covers the one other fact on this same component that has
            # a real, documented observed/inferred distinction; `path`,
            # `category`, etc. were never ambiguous in the first place,
            # so they get no confidence tag at all (see SPEC.md).
            if any(analysis.values()):
                comp.set("contentAnalysisConfidence", "inferred")

        out.append(comp)
    return out
