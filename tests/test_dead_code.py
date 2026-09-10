"""A real, if narrow, dead-code check -- two shipped features were once
defined but never actually wired up (`contentChangedSinceApproval`,
v0.1.7, and `classify_secret_confidence`, v0.3.0 -- see SPEC.md sections
5 and 12), both eventually caught by an external reviewer, not this test
suite. This is the "one grep away" check that should catch the next one
before a reviewer has to.

Scope, stated honestly: only TOP-LEVEL functions in `src/harness_aibom/`
(via `ast`'s own `tree.body`, not a full `ast.walk()`) -- class methods
are deliberately excluded. A common method name (`add`, `get`, `set`)
would produce far more false negatives than a module-level function name
ever does (this codebase's own naming is already distinctive enough at
module level -- `classify_secret_confidence`, `enrich_bom_with_vulnerabilities`
-- that a real collision with unrelated text is effectively never a
concern), so a method-level version of this same check would need a much
smarter analysis (real call-graph tracing) to be trustworthy, not
attempted here. Narrower and reliable beats broader and noisy.
"""

import ast
import re
from pathlib import Path

SRC_ROOT = Path(__file__).parent.parent / "src" / "harness_aibom"
TEST_ROOT = Path(__file__).parent

#: Real public API this project intentionally exposes, used only from
#: within its own defining module (so the "referenced anywhere else"
#: check below would otherwise flag it) or from a context this simple
#: text-based check can't see (e.g. `pyproject.toml`'s own entry-point
#: reference). Every entry needs its own one-line reason -- that
#: requirement is what stops this from quietly becoming a place to bury
#: something that's actually unused.
ALLOWLIST: dict[tuple[str, str], str] = {
    # (module filename, function name): why it's not dead, despite only
    # ever being referenced from within its own module.
}


def _public_top_level_functions(text: str) -> list[str]:
    tree = ast.parse(text)
    return [node.name for node in tree.body if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")]


def test_every_public_top_level_function_is_referenced_somewhere():
    py_files = sorted(SRC_ROOT.rglob("*.py"))
    test_files = sorted(TEST_ROOT.rglob("*.py"))
    file_texts = {f: f.read_text() for f in py_files + test_files}

    unreferenced = []
    for f in py_files:
        for name in _public_top_level_functions(file_texts[f]):
            if (f.name, name) in ALLOWLIST:
                continue
            # Total occurrences of this exact identifier across the
            # WHOLE codebase (its own module included) -- a genuinely
            # unused function's own `def name(` line is the only
            # occurrence there is. Real usage anywhere (a call, an
            # import, a test) always adds at least one more.
            pattern = re.compile(rf"\b{re.escape(name)}\b")
            total_occurrences = sum(len(pattern.findall(text)) for text in file_texts.values())
            if total_occurrences <= 1:
                unreferenced.append(f"{f.relative_to(SRC_ROOT.parent.parent)}:{name}")

    assert not unreferenced, (
        "these public functions are defined but never referenced anywhere else in the "
        f"codebase -- either wire them up, make them private (a leading underscore), or "
        f"add a one-line reason to this test's own ALLOWLIST: {unreferenced}"
    )


def test_allowlist_entries_have_a_real_reason():
    # The allowlist's own value must be a real, non-empty explanation --
    # an empty string would defeat the "requires a comment" discipline
    # this check exists to enforce.
    for key, reason in ALLOWLIST.items():
        assert reason and reason.strip(), f"{key} has no reason recorded"


def test_dead_code_check_catches_a_genuinely_unused_function():
    # Proof this check has real teeth, not just that today's codebase
    # happens to pass it -- a function used nowhere but its own
    # definition line must be flagged.
    text = "def totally_unused_function():\n    pass\n"
    functions = _public_top_level_functions(text)
    assert "totally_unused_function" in functions
    pattern = re.compile(r"\btotally_unused_function\b")
    assert len(pattern.findall(text)) == 1  # only the def line -- would be flagged
