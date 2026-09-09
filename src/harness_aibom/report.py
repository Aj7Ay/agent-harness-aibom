"""Render a harness-aibom CycloneDX document as a single, offline, static
HTML file -- no CDN, no JavaScript framework, no external dependency,
same "works with nothing else installed" principle as the rest of this
tool. Renders every property of every component; nothing is summarized
away or dropped, since the whole point of an AIBOM is to be a complete
record, not a curated one.

Collapsible sections use plain `<details>`/`<summary>` -- no JavaScript
needed at all for that. The one chart (component count by class) is
hand-rolled inline SVG with a native `<title>` hover tooltip -- no
charting library, same offline principle.

**v0.4.0: a small amount of embedded vanilla JavaScript** -- the one
deliberate exception to "no JavaScript needed at all" above. Live
text search and a componentClass filter across potentially hundreds of
entries genuinely can't be done in pure HTML/CSS the way expand/collapse
could; this is the "AIBOM Explorer" step an independent reviewer asked
for. Still single-file, still fully offline, still no CDN/framework --
`_JS` is a plain inline `<script>` block, no build step, no external
runtime. Everything that CAN stay JS-free still is: per-entry raw JSON
uses `<details>`/`<pre>`, same as every other collapsible section --
though as of v0.5.1 its content is populated lazily by `_JS` from one
shared, compact embedded copy of the whole document, rather than each
`<details>` server-embedding its own full pretty-printed copy (which
had roughly doubled the file's size for data most viewers never open).

Color: each componentClass gets a fixed categorical color, used
consistently everywhere it appears on the page (badges, group headers,
individual entries, and the bar chart) -- color follows the entity, never
its position or count, so a filtered or re-ordered view never repaints
what a color already means. The eight classes this renderer knows about
fill the eight-slot categorical palette exactly (dataviz skill,
palette.md's documented default order, unmodified -- already validated
for an adjacent-bar chart: worst adjacent CVD Delta E 9.1 light / 8.4
dark). A class this renderer doesn't recognize (a future componentClass)
gets a neutral gray, never a generated ninth hue.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from . import security

#: componentClasses shown in this order when present; anything else
#: (a future class this file doesn't know about yet) is appended after,
#: sorted alphabetically -- so a new class never silently goes missing.
#: "dependency" and "tool" (added for the standalone MCP package and
#: per-tool components -- see collectors/mcp.py, collectors/deps.py) are
#: placed here in their natural reading position rather than falling
#: through to the alphabetical catch-all: "dependency" right after
#: "runtime" (it's that runtime's own package inventory), "tool" right
#: after "skill" (both are units of capability a harness exposes, just
#: declared by different sources). "prompt_surface"/"memory_store"
#: (v0.6.0) sit right after "configuration" -- all three are files the
#: harness itself reads to decide how to behave.
_COMPONENT_CLASS_ORDER = (
    "runtime", "dependency", "configuration", "prompt_surface", "memory_store",
    "model", "skill", "tool", "hook", "secrets_surface",
)
_SERVICE_CLASS_ORDER = ("model_endpoint", "mcp_server")

#: Fixed categorical color per componentClass -- (light, dark), palette.md's
#: default 8-slot order, unmodified. Reused everywhere a class appears.
_CLASS_COLORS: dict[str, tuple[str, str]] = {
    "runtime": ("#2a78d6", "#3987e5"),  # slot 1 blue
    "configuration": ("#eb6834", "#d95926"),  # slot 2 orange
    "model": ("#1baf7a", "#199e70"),  # slot 3 aqua
    "skill": ("#eda100", "#c98500"),  # slot 4 yellow
    "hook": ("#e87ba4", "#d55181"),  # slot 5 magenta
    "secrets_surface": ("#008300", "#008300"),  # slot 6 green
    "model_endpoint": ("#4a3aa7", "#9085e9"),  # slot 7 violet
    "mcp_server": ("#e34948", "#e66767"),  # slot 8 red
}
_UNKNOWN_CLASS_COLOR = ("#898781", "#898781")  # muted gray -- never a generated 9th hue

#: "dependency" and "tool" are known classes this renderer fully
#: understands, but the categorical palette's 8 slots (above) are already
#: exactly full -- the dataviz skill's fixed rule is that a 9th series
#: never gets a *generated* hue, it folds into "Other" or gets a
#: secondary encoding instead. These get the secondary encoding: two
#: distinct near-neutral, low-chroma shades (not full categorical hues
#: competing with the validated 8, so the palette stays exactly what it
#: was validated as), still visibly different from both each other and
#: from _UNKNOWN_CLASS_COLOR. An independent reviewer found that without
#: this, a known class this renderer explicitly emits (tool, dependency)
#: rendered pixel-identical to a genuinely unrecognized future class --
#: on a 425-component document, 424 of 425 entries were the same flat
#: gray, and tools, dependencies, and true-unknowns were indistinguishable
#: from one another in the chart/dot legend (text labels next to each
#: still disambiguate them in every other context on the page).
_KNOWN_UNPALETTED_CLASS_COLORS: dict[str, tuple[str, str]] = {
    "dependency": ("#6b7680", "#8b96a0"),  # cool slate
    "tool": ("#8a7a6b", "#a8988a"),  # warm taupe
    "prompt_surface": ("#7a7568", "#9a9486"),  # warm gray (v0.6.0)
    "memory_store": ("#68767a", "#86999e"),  # cool gray (v0.6.0)
}

_NOT_RECORDED = "not recorded (deterministic scan)"

_CSS = """
:root {
  --bg: #f9f9f7; --surface: #fcfcfb; --fg: #0b0b0b; --secondary: #52514e;
  --muted: #898781; --border: #e1e0d9; --baseline: #c3c2b7; --code-bg: #f3f4f6;
"""

for _cls, (_light, _dark) in {**_CLASS_COLORS, **_KNOWN_UNPALETTED_CLASS_COLORS}.items():
    _CSS += f"  --class-{_cls}: {_light};\n"
_CSS += "  --class-unknown: #898781;\n}\n"

_CSS += """
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d0d0d; --surface: #1a1a19; --fg: #ffffff; --secondary: #c3c2b7;
    --muted: #898781; --border: #2c2c2a; --baseline: #383835; --code-bg: #1a1d24;
"""
for _cls, (_light, _dark) in {**_CLASS_COLORS, **_KNOWN_UNPALETTED_CLASS_COLORS}.items():
    _CSS += f"    --class-{_cls}: {_dark};\n"
_CSS += "    --class-unknown: #898781;\n  }\n}\n"

_CSS += """
* { box-sizing: border-box; }
body {
  background: var(--bg); color: var(--fg);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  max-width: 960px; margin: 0 auto; padding: 2rem 1.25rem 4rem;
  line-height: 1.5;
}
header h1 { margin-bottom: 0.25rem; word-break: break-word; }
.muted { color: var(--secondary); font-size: 0.9rem; }
.small { font-size: 0.75rem; color: var(--muted); }
section { margin-top: 2rem; }
h2 { border-bottom: 1px solid var(--border); padding-bottom: 0.35rem; }
table { border-collapse: collapse; width: 100%; margin: 0.5rem 0; }
table.summary th, table.summary td { text-align: left; padding: 0.25rem 0.6rem; border-bottom: 1px solid var(--border); }
table.props th, table.props td { text-align: left; padding: 0.2rem 0.6rem; font-size: 0.9rem; vertical-align: top; word-break: break-word; }
table.props th { color: var(--secondary); font-weight: 500; width: 12rem; white-space: nowrap; }
details.group { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 0.6rem 0.9rem; margin-bottom: 0.75rem; }
details.group > summary { cursor: pointer; font-weight: 600; }
.count { color: var(--muted); font-weight: normal; }
.entry { border-top: 1px solid var(--border); padding: 0.6rem 0; }
.entry:first-of-type { border-top: none; }
.entry-header { display: flex; gap: 0.5rem; align-items: baseline; flex-wrap: wrap; }
.badge { background: var(--code-bg); border-radius: 4px; padding: 0.05rem 0.4rem; font-size: 0.75rem; color: var(--secondary); }
.class-dot { display: inline-block; width: 0.55rem; height: 0.55rem; border-radius: 50%; margin-right: 0.3rem; flex: none; }
.kpi-row { display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 0.75rem 0 1.25rem; }
.kpi-tile { flex: 1 1 130px; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 0.75rem 1rem; }
.kpi-label { color: var(--secondary); font-size: 0.8rem; }
.kpi-value { font-size: 1.7rem; font-weight: 600; margin-top: 0.15rem; }
.chart-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1rem 1.25rem; margin: 0.75rem 0 1.25rem; }
.chart-card svg { display: block; width: 100%; height: auto; }
.chart-card text { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
.bar-row-label { font-size: 12px; fill: var(--secondary); text-anchor: end; }
.bar-value-label { font-size: 12px; fill: var(--fg); }
footer { margin-top: 3rem; border-top: 1px solid var(--border); padding-top: 0.75rem; }
.scan-warnings {
  background: #fdf1d9; border-left: 4px solid #fab219; border-radius: 6px;
  padding: 0.75rem 1rem; margin: 0.75rem 0 1.25rem;
}
@media (prefers-color-scheme: dark) { .scan-warnings { background: #3a2f13; } }
.scan-warnings ul { margin: 0.4rem 0 0; padding-left: 1.2rem; }
.scan-warnings li { font-size: 0.9rem; }
.arch-card svg { display: block; width: 100%; height: auto; }
.arch-box { fill: var(--surface); stroke-width: 2; }
.arch-label { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; font-size: 12px; font-weight: 600; fill: var(--fg); }
.arch-count { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; font-size: 11px; fill: var(--secondary); }
.arch-edge { stroke: var(--baseline); stroke-width: 1.5; }
.security-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1rem; margin: 0.75rem 0 1.25rem; }
.security-grid table.summary th { background: var(--surface); }
/* Status palette (dataviz skill, fixed -- never themed, never reused for
   series identity): good #0ca30c, warning #fab219, serious #ec835a,
   critical #d03b3b. Always paired with a text label, never color alone. */
.risk-list { list-style: none; margin: 0.5rem 0; padding: 0; }
.risk-list li { padding: 0.5rem 0; border-top: 1px solid var(--border); display: flex; gap: 0.6rem; align-items: baseline; flex-wrap: wrap; }
.risk-list li:first-child { border-top: none; }
.risk-badge { display: inline-block; border-radius: 4px; padding: 0.1rem 0.5rem; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.02em; flex: none; }
.risk-badge.sev-critical { background: #d03b3b; color: #fff; }
.risk-badge.sev-serious { background: #ec835a; color: #fff; }
.risk-badge.sev-warning { background: #fab219; color: #1a1a19; }
.risk-clean { color: #0ca30c; font-weight: 600; }
.mcp-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 0.75rem 1rem; margin-bottom: 0.75rem; }
.mcp-card-header { display: flex; gap: 0.5rem; align-items: baseline; flex-wrap: wrap; margin-bottom: 0.4rem; }
.status-pill { display: inline-block; border-radius: 4px; padding: 0.05rem 0.45rem; font-size: 0.72rem; font-weight: 600; }
.status-pill.ok { background: rgba(12,163,12,0.15); color: #0ca30c; }
.status-pill.bad { background: rgba(208,59,59,0.15); color: #d03b3b; }
.status-pill.na { background: var(--code-bg); color: var(--secondary); }
.mcp-tool-list { list-style: none; margin: 0.4rem 0 0; padding: 0; display: flex; flex-wrap: wrap; gap: 0.35rem; }
.mcp-tool-list li { background: var(--code-bg); border-radius: 4px; padding: 0.1rem 0.45rem; font-size: 0.78rem; }
.coverage-list { list-style: none; margin: 0.3rem 0; padding: 0; }
.coverage-list li { padding: 0.15rem 0; font-size: 0.85rem; }
.explorer-nav {
  position: sticky; top: 0; z-index: 10; background: var(--bg);
  border-bottom: 1px solid var(--border); margin: 0 -1.25rem 1rem; padding: 0.6rem 1.25rem;
  display: flex; flex-wrap: wrap; gap: 0.15rem 0.9rem; font-size: 0.82rem;
}
.explorer-nav a { color: var(--secondary); text-decoration: none; white-space: nowrap; }
.explorer-nav a:hover { color: var(--fg); text-decoration: underline; }
.filter-bar { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: center; margin: 0.75rem 0 1rem; }
.filter-bar input[type=search] {
  flex: 1 1 220px; padding: 0.4rem 0.6rem; border: 1px solid var(--border); border-radius: 6px;
  background: var(--surface); color: var(--fg); font-size: 0.9rem;
}
.filter-bar select {
  padding: 0.4rem 0.6rem; border: 1px solid var(--border); border-radius: 6px;
  background: var(--surface); color: var(--fg); font-size: 0.9rem;
}
.filter-status { font-size: 0.82rem; color: var(--secondary); }
.entry[hidden], .group[hidden] { display: none !important; }
.arch-box[data-node] { cursor: pointer; }
pre.raw-json {
  background: var(--code-bg); border-radius: 6px; padding: 0.6rem 0.8rem; font-size: 0.78rem;
  overflow-x: auto; white-space: pre; margin: 0.4rem 0 0;
}
"""

#: v0.4.0's one deliberate exception to "no JavaScript needed at all" (see
#: module docstring) -- live search and a componentClass filter across
#: potentially hundreds of entries. Plain global functions, not an IIFE:
#: this is a single generated page, so there's no module-collision risk
#: to guard against, and no build step or bundler to justify one.
#:
#: v0.5.1: architecture-diagram nodes are found by a delegated
#: `click` listener reading a `data-goto` attribute, NOT a server-
#: rendered `onclick="goToClass('...')"` attribute. Confirmed real: an
#: independent reviewer found that `_esc()` (`html.escape`) is the wrong
#: escaper for "a value embedded inside a JS string literal that is
#: itself inside an HTML attribute" -- the browser HTML-decodes the
#: attribute (turning `&#x27;` back into a literal `'`) *before* handing
#: the attribute's text to the JS parser, so a componentClass containing
#: a quote (reachable only by hand-editing or otherwise supplying a
#: harness-aibom document this scanner didn't itself produce -- `report`
#: accepts any JSON file, and collector-produced componentClass values
#: are the only thing actually restricted to a fixed vocabulary) broke
#: out of the JS string and ran arbitrary script. `data-goto` sidesteps
#: the whole nested-grammar problem: `_esc()` still protects the HTML
#: attribute context correctly, and `getAttribute()` returns that exact
#: decoded string with no further parsing step, so there is no second
#: grammar left to escape for. `goToClass()` itself no longer builds a
#: CSS selector by string concatenation either (the same class of
#: mistake, flagged even though the `<select>`-sourced value reaching it
#: couldn't itself carry a `"` past the HTML-attribute boundary) -- it
#: compares `data-class` values in a loop instead.
_JS = """
function normalizeText(s) { return (s || '').toLowerCase(); }

function applyFilters() {
  var searchBox = document.getElementById('search-box');
  var classFilter = document.getElementById('class-filter');
  var q = normalizeText(searchBox ? searchBox.value : '');
  var cls = classFilter ? classFilter.value : '';
  var entries = document.querySelectorAll('.entry[data-class]');
  var shown = 0;
  entries.forEach(function (entry) {
    var matchesClass = !cls || entry.getAttribute('data-class') === cls;
    var matchesSearch = !q || (entry.getAttribute('data-search') || '').indexOf(q) !== -1;
    var visible = matchesClass && matchesSearch;
    entry.hidden = !visible;
    if (visible) shown++;
  });
  document.querySelectorAll('.group[data-class]').forEach(function (group) {
    group.hidden = !group.querySelector('.entry:not([hidden])');
  });
  var status = document.getElementById('filter-status');
  if (status) {
    status.textContent = (q || cls) ? (shown + ' of ' + entries.length + ' shown') : (entries.length + ' total');
  }
}

function findGroupForClass(cls) {
  var groups = document.querySelectorAll('.group[data-class]');
  for (var i = 0; i < groups.length; i++) {
    if (groups[i].getAttribute('data-class') === cls) return groups[i];
  }
  return null;
}

function goToClass(cls) {
  var classFilter = document.getElementById('class-filter');
  var searchBox = document.getElementById('search-box');
  if (classFilter) classFilter.value = cls || '';
  if (searchBox) searchBox.value = '';
  applyFilters();
  var target = cls ? findGroupForClass(cls) : document.getElementById('components');
  if (target) target.scrollIntoView({behavior: 'smooth', block: 'start'});
}

document.addEventListener('DOMContentLoaded', function () {
  var searchBox = document.getElementById('search-box');
  var classFilter = document.getElementById('class-filter');
  if (searchBox) searchBox.addEventListener('input', applyFilters);
  if (classFilter) classFilter.addEventListener('change', applyFilters);
  document.addEventListener('click', function (event) {
    var node = event.target.closest && event.target.closest('[data-goto]');
    if (node) goToClass(node.getAttribute('data-goto'));
  });
  applyFilters();
});

// v0.5.1: raw JSON (per entry, and the whole document) is rendered
// lazily from one shared, compact embedded blob instead of a second,
// pretty-printed copy per entry -- an independent reviewer found the
// previous approach (every entry AND the whole document each carrying
// their own full `json.dumps(..., indent=2)`) roughly doubled the
// file's size for no benefit most viewers never open. `<details
// data-bom-ref="...">` is populated into its own `<pre>` the first time
// it's actually opened; the root document itself uses the sentinel ref
// "__bom__". Same principle as search/filter (v0.4.0): this needs
// JavaScript and has no fallback for a JS-disabled viewer, consistent
// with that already being true of every other interactive piece of
// this report.
var BOM_DATA = null;
(function () {
  var dataEl = document.getElementById('bom-data');
  if (!dataEl) return;
  try { BOM_DATA = JSON.parse(dataEl.textContent); } catch (e) { BOM_DATA = null; }
})();

function findByRef(ref) {
  if (!BOM_DATA) return null;
  if (ref === '__bom__') return BOM_DATA;
  var root = BOM_DATA.metadata && BOM_DATA.metadata.component;
  if (root && root['bom-ref'] === ref) return root;
  var lists = [BOM_DATA.components || [], BOM_DATA.services || []];
  for (var i = 0; i < lists.length; i++) {
    for (var j = 0; j < lists[i].length; j++) {
      if (lists[i][j]['bom-ref'] === ref) return lists[i][j];
    }
  }
  return null;
}

document.addEventListener('toggle', function (event) {
  var details = event.target;
  if (!details || details.tagName !== 'DETAILS' || !details.hasAttribute('data-bom-ref')) return;
  if (!details.open || details.dataset.rendered) return;
  var data = findByRef(details.getAttribute('data-bom-ref'));
  var pre = details.querySelector('pre.raw-json');
  if (pre && data) {
    pre.textContent = JSON.stringify(data, null, 2);
    details.dataset.rendered = '1';
  }
}, true); // capture: 'toggle' does not bubble
"""


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _split_properties(entry: dict) -> tuple[dict[str, str], list[str]]:
    """(single-valued properties, relationship strings).

    `harness-aibom:relationship` can appear more than once on one entry
    -- a plain `{p["name"]: p["value"] for p in ...}` dict comprehension
    would silently collapse repeats down to the last one, dropping every
    earlier relationship. Kept as a separate list specifically so that
    can't happen.
    """
    single: dict[str, str] = {}
    relationships: list[str] = []
    for prop in entry.get("properties", []):
        if prop["name"] == "harness-aibom:relationship":
            relationships.append(prop["value"])
        else:
            single[prop["name"]] = prop["value"]
    return single, relationships


def _extract_warnings(entry: dict) -> list[str]:
    """Same collapsing hazard as relationships: `harness-aibom:warning`
    can repeat on the root entry (one per scan warning), so this can't
    be read through a plain name->value dict comprehension either."""
    return [p["value"] for p in entry.get("properties", []) if p["name"] == "harness-aibom:warning"]


def _render_warnings_banner(warnings: list[str]) -> str:
    if not warnings:
        return ""
    items = "".join(f"<li>{_esc(w)}</li>" for w in warnings)
    return (
        "<div class='scan-warnings'>"
        f"<strong>⚠ {len(warnings)} scan warning{'s' if len(warnings) != 1 else ''}</strong> "
        "<span class='muted'>(this document may be incomplete)</span>"
        f"<ul>{items}</ul>"
        "</div>"
    )


def _component_class(entry: dict) -> str:
    for prop in entry.get("properties", []):
        if prop["name"] == "harness-aibom:componentClass":
            return prop["value"]
    return "unknown"


def _class_color_var(cls: str) -> str:
    """CSS var name for `cls`'s dot/bar color -- one of the 8 validated
    categorical hues, one of the two known-but-unpaletted near-neutral
    shades (dependency/tool), or the shared "genuinely unrecognized"
    gray, in that priority order. The one place this 3-tier fallback is
    decided, reused by every renderer below so the three tiers can't
    drift out of sync with each other.
    """
    if cls in _CLASS_COLORS or cls in _KNOWN_UNPALETTED_CLASS_COLORS:
        return f"--class-{cls}"
    return "--class-unknown"


def _class_dot(cls: str) -> str:
    var_name = _class_color_var(cls)
    return f"<span class='class-dot' style='background:var({var_name})' aria-hidden='true'></span>"


def _render_props_table(props: dict[str, str]) -> str:
    if not props:
        return "<p class='muted'><em>no properties</em></p>"
    rows = "".join(
        f"<tr><th>{_esc(k.removeprefix('harness-aibom:'))}</th><td>{_esc(v)}</td></tr>"
        for k, v in sorted(props.items())
    )
    return f"<table class='props'>{rows}</table>"


def _render_relationships(relationships: list[str]) -> str:
    if not relationships:
        return ""
    items = "".join(f"<li>{_esc(r)}</li>" for r in relationships)
    return f"<details><summary>relationships ({len(relationships)})</summary><ul>{items}</ul></details>"


def _search_blob(entry: dict, cls: str) -> str:
    """Lowercased text blob an entry is matched against by the v0.4.0
    search box -- name, bom-ref, type, version, every property's own key
    (minus the harness-aibom: prefix) and value, and every relationship
    string. Deliberately broad: an independent reviewer's own examples
    were "search world-readable -> find the affected secret", "search
    sha256 -> find fingerprinted objects" -- both need property *values*
    searchable, not just names.
    """
    parts = [entry.get("name", ""), entry.get("bom-ref", ""), entry.get("type", ""), entry.get("version", ""), cls]
    for prop in entry.get("properties", []):
        parts.append(prop["name"].removeprefix("harness-aibom:"))
        parts.append(prop["value"])
    return " ".join(str(p) for p in parts if p).lower()


def _render_reachable_list(bom_ref: str, index: dict[str, dict], key: str, label: str, blurb: str) -> str:
    """Shared renderer for both directions -- `compute_supply_chain()`
    (what this depends on) and `compute_blast_radius()` (what would be
    affected if this were compromised, the reverse traversal -- see
    SPEC.md section 11's v0.5.1 note for why these are two different,
    both-real questions, not one function pretending to answer both).
    """
    reachable = (index.get(bom_ref) or {}).get(key, [])
    if not reachable:
        return ""
    items = "".join(f"<li>{_esc(ref)}</li>" for ref in reachable)
    return (
        f"<details><summary>{label} ({len(reachable)} reachable, observed)</summary>"
        f"<p class='muted small'>{blurb}</p>"
        f"<ul>{items}</ul></details>"
    )


def _render_entry(entry: dict, cls: str, ctx: dict) -> str:
    single, relationships = _split_properties(entry)
    single.pop("harness-aibom:componentClass", None)

    header_bits = [_class_dot(cls), f"<strong>{_esc(entry.get('name', ''))}</strong>"]
    # A `model` component's version is set to the model name itself
    # (ollama.py), so "v" + version would just repeat the name right
    # after it (e.g. "qwen3:8b vqwen3:8b") -- only show it when it's
    # actually a distinct value.
    if entry.get("version") and entry["version"] != entry.get("name"):
        header_bits.append(f"<span class='muted'>v{_esc(entry['version'])}</span>")
    if entry.get("type"):  # absent for services -- they have no CDX `type`
        header_bits.append(f"<span class='badge'>{_esc(entry['type'])}</span>")

    # v0.5.0: capability + reachability, both fixed/explainable
    # classifications (security.py), never a guess at actual runtime
    # behavior -- see SPEC.md section 11. `tool` needs the document-wide
    # mcp_servers lookup (v0.5.1) to inherit its parent server's own
    # reachability rather than guessing one from its own riskClass.
    capability = security.classify_capabilities(entry)
    reachability = security.classify_reachability(entry, ctx["mcp_servers"])
    surface_line = f"<p class='muted small'>capability: {_esc(capability)} &middot; reachability: {_esc(reachability)}</p>"

    endpoints_html = ""
    if entry.get("endpoints"):
        endpoints_html = f"<p class='muted'>endpoints: {_esc(', '.join(entry['endpoints']))}</p>"

    # Raw JSON per entry -- native <details>, same as every other
    # collapsible section, but its content is populated lazily by the
    # `toggle` listener in `_JS` (from the single shared `#bom-data`
    # blob, see `render_html`) rather than server-embedded here. See
    # SPEC.md section 10 for the original v0.4.0 design and section 12
    # for why v0.5.1 stopped embedding it directly.
    raw_json = f"<details data-bom-ref='{_esc(entry.get('bom-ref', ''))}'><summary>Raw JSON</summary><pre class='raw-json'></pre></details>"

    bom_ref = entry.get("bom-ref", "")
    supply_chain_html = _render_reachable_list(
        bom_ref, ctx["supply_chains"], "reachable", "Depends on",
        "Everything this component itself relies on, transitively -- an exact graph traversal, not a guess.",
    )
    blast_radius_html = _render_reachable_list(
        bom_ref, ctx["blast_radii"], "reachable", "Blast radius",
        "Everything that would be affected if this component were compromised -- the reverse of "
        "\"Depends on\" above, an exact graph traversal over the same recorded relationships.",
    )

    return (
        f"<div class='entry' data-class='{_esc(cls)}' data-search='{_esc(_search_blob(entry, cls))}'>"
        f"<div class='entry-header'>{' '.join(header_bits)}"
        f" <span class='small'>{_esc(bom_ref)}</span></div>"
        f"{surface_line}"
        f"{endpoints_html}"
        f"{_render_props_table(single)}"
        f"{blast_radius_html}"
        f"{supply_chain_html}"
        f"{_render_relationships(relationships)}"
        f"{raw_json}"
        "</div>"
    )


def _group_by_class(entries: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for entry in entries:
        grouped.setdefault(_component_class(entry), []).append(entry)
    return grouped


def _render_group(cls: str, entries: list[dict], ctx: dict) -> str:
    body = "".join(_render_entry(e, cls, ctx) for e in sorted(entries, key=lambda e: e.get("name", "")))
    return (
        f"<details open class='group' data-class='{_esc(cls)}'>"
        f"<summary>{_class_dot(cls)}{_esc(cls)} <span class='count'>({len(entries)})</span></summary>"
        f"{body}"
        "</details>"
    )


def _render_groups(grouped: dict[str, list[dict]], preferred_order: tuple[str, ...], ctx: dict) -> str:
    # Preferred classes first, in a fixed reading order; anything this
    # renderer doesn't specifically know about still gets shown, appended
    # afterward rather than silently dropped -- see module docstring.
    order = list(preferred_order) + sorted(set(grouped) - set(preferred_order))
    return "".join(_render_group(cls, grouped[cls], ctx) for cls in order if cls in grouped)


def _render_kpi_row(tiles: list[tuple[str, int]]) -> str:
    cells = "".join(
        f"<div class='kpi-tile'><div class='kpi-label'>{_esc(label)}</div>"
        f"<div class='kpi-value'>{count}</div></div>"
        for label, count in tiles
    )
    return f"<div class='kpi-row'>{cells}</div>"


def _render_bar_chart(class_counts: dict[str, int]) -> str:
    """One horizontal bar per componentClass, colored to match its badge
    everywhere else on the page. Horizontal, not vertical: several of
    these class names (`secrets_surface`, `model_endpoint`) are long
    enough that vertical axis labels would need to rotate or truncate.
    A native SVG `<title>` gives each bar a hover tooltip with no
    JavaScript; every value is already directly labeled on the bar too
    (and repeated in the summary table below), so the tooltip enhances,
    it never gates.
    """
    if not class_counts:
        return "<p class='muted'><em>nothing to chart</em></p>"

    order = [c for c in (*_COMPONENT_CLASS_ORDER, *_SERVICE_CLASS_ORDER) if c in class_counts]
    order += sorted(set(class_counts) - set(order))  # an unrecognized class, still shown
    max_count = max(class_counts.values()) or 1

    row_h = 28
    bar_h = 18
    label_w = 150
    plot_w = 380
    chart_w = label_w + plot_w + 46
    chart_h = row_h * len(order)

    rows = []
    for i, cls in enumerate(order):
        count = class_counts[cls]
        y = i * row_h
        bar_len = max(4, round((count / max_count) * plot_w, 1))
        color_var = f"var({_class_color_var(cls)})"
        rows.append(
            "<g>"
            f"<title>{_esc(cls)}: {count}</title>"
            f"<text x='{label_w - 10}' y='{y + bar_h / 2}' dominant-baseline='central' "
            f"class='bar-row-label'>{_esc(cls)}</text>"
            f"<rect x='{label_w}' y='{y}' width='{bar_len}' height='{bar_h}' rx='3' fill='{color_var}'/>"
            f"<text x='{label_w + bar_len + 8}' y='{y + bar_h / 2}' dominant-baseline='central' "
            f"class='bar-value-label'>{count}</text>"
            "</g>"
        )

    # No width/height attributes: only the viewBox's intrinsic aspect
    # ratio, with sizing left entirely to the `.chart-card svg { width:
    # 100%; height: auto }` CSS rule. A fixed pixel height alongside
    # width="100%" would make the browser box the element at (container
    # width x that fixed height) -- wider than the viewBox's own aspect
    # ratio once the container is wider than `chart_w`, which it always is
    # here -- and letterbox the chart small and centered in mostly empty
    # space instead of filling the card.
    return (
        f"<svg viewBox='0 0 {chart_w} {chart_h}' role='img' "
        f"aria-label='Component count by class'>{''.join(rows)}</svg>"
    )


def _graph_levels(graph: dict) -> list[list[str]]:
    """Group `graph`'s nodes into rows by BFS depth from the root, for the
    architecture diagram's layout -- a node closer to the root (fewer
    hops in the real dependency graph) reads higher up the page, matching
    how the graph is actually structured rather than an arbitrary order.
    """
    children: dict[str, list[str]] = {}
    for a, b in graph["edges"]:
        children.setdefault(a, []).append(b)

    level_of: dict[str, int] = {security.ROOT_LABEL: 0}
    order = [security.ROOT_LABEL]
    queue = [security.ROOT_LABEL]
    while queue:
        node = queue.pop(0)
        for child in children.get(node, []):
            if child not in level_of:
                level_of[child] = level_of[node] + 1
                order.append(child)
                queue.append(child)

    # A node with no path from the root at all (shouldn't happen -- every
    # top-level thing is a direct root relationship -- but never silently
    # dropped if it somehow did) still gets shown, one row down.
    for node in graph["nodes"]:
        if node not in level_of:
            level_of[node] = 1
            order.append(node)

    rows: dict[int, list[str]] = {}
    for node in order:
        rows.setdefault(level_of[node], []).append(node)
    return [rows[k] for k in sorted(rows)]


def _render_architecture_graph(graph: dict) -> str:
    """The harness's own structure -- one box per componentClass (not per
    instance; see security.build_architecture_graph for why), positioned
    by real BFS depth from the root and connected by real edges from the
    document's own dependency graph. This is what answers "what is this
    agent made of and how are the pieces connected" -- a question the
    per-class counts in the Summary section below can't answer on their
    own, since a flat count list carries no structure.
    """
    nodes = graph["nodes"]
    if len(nodes) <= 1:
        return "<p class='muted'><em>nothing to diagram</em></p>"

    levels = _graph_levels(graph)
    box_w, box_h = 172, 46
    col_gap, row_gap = 22, 68

    def row_width(n: int) -> float:
        return n * box_w + max(0, n - 1) * col_gap

    chart_w = max(row_width(len(row)) for row in levels) + 40
    chart_h = len(levels) * row_gap + box_h + 24

    positions: dict[str, tuple[float, float]] = {}
    for level_idx, row in enumerate(levels):
        start_x = (chart_w - row_width(len(row))) / 2
        y = 20 + level_idx * row_gap
        for i, node in enumerate(row):
            x = start_x + i * (box_w + col_gap)
            positions[node] = (x + box_w / 2, y)

    edge_svg = []
    for a, b in graph["edges"]:
        if a not in positions or b not in positions:
            continue
        ax, ay = positions[a]
        bx, by = positions[b]
        edge_svg.append(f"<line x1='{ax}' y1='{ay + box_h}' x2='{bx}' y2='{by}' class='arch-edge'/>")

    box_svg = []
    for node, (cx, top) in positions.items():
        count = nodes.get(node, 0)
        is_root = node == security.ROOT_LABEL
        label = "harness root" if is_root else node
        stroke = "var(--fg)" if is_root else f"var({_class_color_var(node)})"
        x = cx - box_w / 2
        # Clickable (v0.4.0): jumps to and filters the Components/Services
        # section to this class, via a delegated click listener reading
        # `data-goto` (v0.5.1 -- see _JS's own comment for why this isn't
        # a server-rendered `onclick` attribute). An empty `data-goto` on
        # the root node clears the filter instead, since "harness root"
        # isn't a real componentClass anything below is filterable by.
        target = "" if is_root else node
        tooltip = "reset filter" if is_root else f"filter to {label}"
        box_svg.append(
            f"<g data-goto='{_esc(target)}'>"
            f"<title>{_esc(label)}: {count} ({tooltip})</title>"
            f"<rect x='{x}' y='{top}' width='{box_w}' height='{box_h}' rx='8' "
            f"class='arch-box' data-node='{_esc(node)}' style='stroke:{stroke}'/>"
            f"<text x='{cx}' y='{top + box_h / 2 - 6}' text-anchor='middle' class='arch-label'>{_esc(label)}</text>"
            f"<text x='{cx}' y='{top + box_h / 2 + 12}' text-anchor='middle' class='arch-count'>{count}</text>"
            "</g>"
        )

    # Same reasoning as _render_bar_chart: no width/height attributes, so
    # `.arch-card svg { width: 100%; height: auto }` sizes it from the
    # viewBox's own aspect ratio instead of letterboxing.
    return (
        f"<svg viewBox='0 0 {chart_w} {chart_h}' role='img' aria-label='Harness architecture'>"
        f"{''.join(edge_svg)}{''.join(box_svg)}</svg>"
    )


def _render_security_summary(bom: dict) -> str:
    s = security.compute_security_summary(bom)
    coverage = security.compute_coverage(bom)
    found, total = coverage["score"]
    fingerprintable = s["total_components"] + s["total_services"]

    inventory_rows = "".join(
        f"<tr><td>{_esc(label)}</td><td>{value}</td></tr>"
        for label, value in [
            ("Agent runtime", s["runtime"]),
            ("Model endpoints", s["model_endpoints"]),
            ("Models", s["models"]),
            ("Skills", s["skills"]),
            ("MCP servers", s["mcp_servers"]),
            ("MCP tools", s["mcp_tools"]),
            ("Hooks", s["hooks"]),
            ("Executable tools", s["executable_tools"]),
            ("Secrets surfaces", s["secrets_surfaces"]),
            ("Dependencies", s["dependencies"]),
            ("Prompt surfaces", s["prompt_surfaces"]),
            ("Memory stores", s["memory_stores"]),
        ]
    )

    not_collected = "".join(f"<li>✗ {_esc(c)} <span class='muted'>(not collected)</span></li>" for c in coverage["not_collected"])
    found_items = "".join(f"<li>✓ {_esc(c)}</li>" for c in coverage["found"])
    empty_items = "".join(f"<li>· {_esc(c)} <span class='muted'>(none found)</span></li>" for c in coverage["empty"])

    return f"""
    <div class="security-grid">
      <table class="summary">
        <tr><th colspan="2">Inventory</th></tr>
        {inventory_rows}
      </table>
      <table class="summary">
        <tr><th colspan="2">Integrity</th></tr>
        <tr><td>Fingerprinted components</td><td>{s['fingerprinted']} / {fingerprintable}</td></tr>
        <tr><td>AIBOM coverage</td><td>{found} / {total} known categories</td></tr>
        <tr><td>Baseline comparison</td><td class="muted">not available for a single scan &mdash; use <code>harness-aibom diff</code></td></tr>
      </table>
    </div>
    <details><summary>AIBOM coverage detail ({found} / {total})</summary>
      <ul class="coverage-list">{found_items}{empty_items}{not_collected}</ul>
    </details>
    """


_SEVERITY_CSS_CLASS = {"high": "sev-critical", "medium": "sev-serious", "low": "sev-warning"}
_SEVERITY_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def _render_risk_observations(bom: dict) -> str:
    observations = security.compute_risk_observations(bom)
    if not observations:
        return (
            "<p class='risk-clean'>✓ No configured risk rule fired against this document.</p>"
            "<p class='muted'>This reflects only the specific, named rules this scanner checks "
            "(world-readable secrets, at both confidence tiers; plaintext/unauthenticated MCP "
            "transport; unpinned MCP launcher packages; Python packages missing a version; models "
            "with no content digest; world-readable memory-store files) &mdash; not a general clean "
            "bill of health.</p>"
        )
    items = "".join(
        "<li>"
        f"<span class='risk-badge {_SEVERITY_CSS_CLASS.get(o['severity'], 'sev-warning')}'>"
        f"{_esc(_SEVERITY_LABEL.get(o['severity'], o['severity'].upper()))}</span>"
        # o['rule'] itself, not just its prose summary -- confirmed real
        # gap: this section's own intro text says "each observation names
        # the exact rule that fired", but the rule name never actually
        # reached the page; only the free-text summary did.
        f"<code class='small'>{_esc(o['rule'])}</code>"
        f"<span>{_esc(o['summary'])}</span>"
        f"<span class='small'>{_esc(', '.join(c for c in o['components'] if c))}</span>"
        "</li>"
        for o in observations
    )
    return f"<ul class='risk-list'>{items}</ul>"


def _render_mcp_security(services: list[dict]) -> str:
    servers = [e for e in services if _component_class(e) == "mcp_server"]
    if not servers:
        return "<p class='risk-clean'>✓ No MCP servers discovered.</p>"

    cards = []
    for server in sorted(servers, key=lambda e: e.get("name", "")):
        props, _rel = _split_properties(server)
        transport = props.get("harness-aibom:transport", "unknown")
        tls = props.get("harness-aibom:tls")
        auth = props.get("harness-aibom:authConfigured")

        if tls == "True":
            tls_pill = "<span class='status-pill ok'>TLS</span>"
        elif tls == "False":
            tls_pill = "<span class='status-pill bad'>no TLS</span>"
        else:  # "n/a" for stdio -- there's no network transport to secure
            tls_pill = "<span class='status-pill na'>n/a (stdio)</span>"

        if auth == "True":
            auth_pill = "<span class='status-pill ok'>auth configured</span>"
        elif auth == "False":
            auth_pill = "<span class='status-pill bad'>no auth</span>"
        else:
            auth_pill = ""

        tools_html = ""
        server_tools = props.get("harness-aibom:toolCount")
        if server_tools:
            tools_html = f"<p class='muted small'>{_esc(server_tools)} tool(s) &mdash; see Components/tool below</p>"

        purl = server.get("purl") or props.get("harness-aibom:purl")
        purl_html = f"<p class='muted small'>package: {_esc(purl)}</p>" if purl else ""

        cards.append(
            "<div class='mcp-card'>"
            f"<div class='mcp-card-header'>{_class_dot('mcp_server')}<strong>{_esc(server.get('name', ''))}</strong> "
            f"<span class='badge'>{_esc(transport)}</span> {tls_pill} {auth_pill}</div>"
            f"{tools_html}{purl_html}"
            "</div>"
        )
    return "".join(cards)


def _render_skill_category_breakdown(skills: list[dict]) -> str:
    if not skills:
        return ""
    by_category: dict[str, int] = {}
    for entry in skills:
        props, _rel = _split_properties(entry)
        category = props.get("harness-aibom:category", "(uncategorized)")
        by_category[category] = by_category.get(category, 0) + 1
    rows = "".join(
        f"<tr><td>{_esc(cat)}</td><td>{count}</td></tr>"
        for cat, count in sorted(by_category.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    return (
        f"<details><summary>Skills by category ({len(by_category)})</summary>"
        f"<table class='summary'><tr><th>category</th><th>count</th></tr>{rows}</table></details>"
    )


_EXPLORER_NAV_LINKS = (
    ("#architecture", "Architecture"),
    ("#security-summary", "Security"),
    ("#risk", "Risk"),
    ("#attack-surface", "Attack surface"),
    ("#mcp", "MCP"),
    ("#components", "Components"),
    ("#services", "Services"),
    ("#metadata", "Metadata"),
    ("#external-references", "External refs"),
    ("#vulnerabilities", "Vulnerabilities"),
    ("#compositions", "Compositions"),
    ("#raw-bom", "Raw BOM"),
)


def _render_explorer_nav() -> str:
    links = "".join(f"<a href='{href}'>{_esc(label)}</a>" for href, label in _EXPLORER_NAV_LINKS)
    return f"<nav class='explorer-nav'>{links}</nav>"


def _render_filter_bar(class_counts: dict[str, int]) -> str:
    """The v0.4.0 search box + componentClass filter -- see `_JS` for the
    behavior. `class_counts` (already computed in render_html for the bar
    chart) drives the filter dropdown's options, so it can never offer a
    class that isn't actually present in this document.
    """
    options = "".join(
        f"<option value='{_esc(cls)}'>{_esc(cls)} ({count})</option>"
        for cls, count in sorted(class_counts.items())
    )
    return f"""
    <div class="filter-bar">
      <input type="search" id="search-box" placeholder="Search components, services... (name, bom-ref, any property)">
      <select id="class-filter">
        <option value="">All classes</option>
        {options}
      </select>
      <span id="filter-status" class="filter-status"></span>
    </div>
    """


def _render_metadata_section(bom: dict, root: dict) -> str:
    tools = bom.get("metadata", {}).get("tools", {}).get("components", [])
    tool_rows = "".join(
        f"<tr><td>{_esc(t.get('name'))}</td><td>{_esc(t.get('version'))}</td></tr>" for t in tools
    )
    rows = [
        ("bomFormat", bom.get("bomFormat")),
        ("specVersion", bom.get("specVersion")),
        ("version", bom.get("version")),
        ("serialNumber", bom.get("serialNumber", _NOT_RECORDED)),
        ("timestamp", bom.get("metadata", {}).get("timestamp", _NOT_RECORDED)),
        ("root bom-ref", root.get("bom-ref")),
    ]
    row_html = "".join(f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>" for k, v in rows)
    tools_table = (
        f"<table class='summary'><tr><th>generating tool</th><th>version</th></tr>{tool_rows}</table>"
        if tool_rows
        else ""
    )
    return f"<table class='summary'>{row_html}</table>{tools_table}"


def _render_empty_cyclonedx_section(bom: dict, key: str, message: str) -> str:
    """A dedicated section for a native CycloneDX 1.6 array this scanner
    doesn't populate yet (vulnerabilities, compositions) -- shown
    explicitly rather than silently absent, same "nothing summarized
    away" principle as every other section, but honest about the
    difference between "checked, found none" (this scanner doesn't
    check at all) and an actual empty result. `externalReferences` has
    its own dedicated renderer (`_render_external_references()`) as of
    v0.6.0, since that one IS populated, per-component.
    """
    entries = bom.get(key, [])
    if entries:
        # Not expected today (nothing in this codebase emits these yet),
        # but never silently drop real data if a future collector does.
        return f"<pre class='raw-json'>{_esc(json.dumps(entries, indent=2))}</pre>"
    return f"<p class='muted'><em>{_esc(message)}</em></p>"


def _render_external_reference_url(url: str) -> str:
    """A clickable link ONLY for an http(s) URL, plain escaped text
    otherwise -- `report` renders any JSON file handed to it, not just
    ones this scanner produced, so `url` here is untrusted input, not
    something this codebase always controls the shape of (unlike the
    registry URLs `_registry_url_for_purl()` itself builds, which are
    always http(s) by construction). `_esc()` alone protects the HTML
    *attribute* syntax, but does nothing about the URL *scheme* --
    without this check, a hand-crafted document setting
    externalReferences[].url to a `javascript:` URI would render as a
    real, clickable `<a href="javascript:...">` link, exactly the kind
    of injection this project's own v0.5.1 XSS fix (SPEC.md section 12)
    was written to close elsewhere on this same page.
    """
    if url.startswith(("http://", "https://")):
        return f"<a href='{_esc(url)}'>{_esc(url)}</a>"
    return _esc(url)


def _render_external_references(bom: dict) -> str:
    """CycloneDX's `externalReferences[]` exists at both the document
    level (never populated by this scanner) and per-component (v0.6.0:
    a registry-page URL for any component with a `purl` -- see
    cyclonedx.py's `_registry_url_for_purl()`). Confirmed real gap this
    fixes: before this function existed, the section unconditionally
    said "not collected by this scanner" even once a document's own
    dependency components actually carried one, which would have been a
    document contradicting the very section describing it.
    """
    rows = "".join(
        f"<tr><td>{_esc(comp.get('name', ''))}</td><td>{_esc(ref.get('type', ''))}</td>"
        f"<td>{_render_external_reference_url(str(ref.get('url', '')))}</td></tr>"
        for comp in bom.get("components", [])
        for ref in comp.get("externalReferences", [])
    )
    doc_level = bom.get("externalReferences", [])
    if not rows and not doc_level:
        return "<p class='muted'><em>External references are not collected by this scanner.</em></p>"
    table = (
        f"<table class='summary'><tr><th>component</th><th>type</th><th>url</th></tr>{rows}</table>"
        if rows
        else ""
    )
    doc_level_html = (
        f"<pre class='raw-json'>{_esc(json.dumps(doc_level, indent=2))}</pre>" if doc_level else ""
    )
    return f"{table}{doc_level_html}"


def _render_raw_bom(compact_size: int) -> str:
    # Lazily populated from the shared #bom-data blob (see _JS and
    # render_html) via the sentinel ref "__bom__", not embedded again
    # here -- `compact_size` is the one real copy's own byte count
    # (compact, not pretty-printed, since that's what's actually shipped
    # in the file), shown so the summary line stays honest about size.
    return (
        f"<details data-bom-ref='__bom__'><summary>Raw CycloneDX AIBOM ({compact_size} bytes, compact)</summary>"
        "<pre class='raw-json'></pre></details>"
    )


#: Reading order for the attack-surface breakdown -- most-exposed first,
#: so a reader scanning top to bottom sees the highest-attention tiers
#: before the purely-local ones. Anything this renderer doesn't
#: specifically know about (a future reachability tag) still gets shown,
#: appended after, alphabetically -- same principle as every other
#: ordered listing in this file.
_REACHABILITY_ORDER = ("network", "loopback", "process", "filesystem+process", "credential-store", "model-provider", "filesystem", "unknown")


def _render_attack_surface(bom: dict) -> str:
    surface = security.compute_attack_surface(bom)
    by_tier = surface["by_tier"]
    if not by_tier:
        return "<p class='muted'><em>nothing to show</em></p>"

    order = list(_REACHABILITY_ORDER) + sorted(set(by_tier) - set(_REACHABILITY_ORDER))
    rows = "".join(f"<tr><td>{_esc(tier)}</td><td>{len(by_tier[tier])}</td></tr>" for tier in order if tier in by_tier)
    table = f"<table class='summary'><tr><th>reachability</th><th>count</th></tr>{rows}</table>"

    crosses = surface["crosses_network_boundary"]
    boundary_note = (
        f"<p class='muted'>{len(crosses)} component(s) cross a network trust boundary "
        "(a non-loopback endpoint) -- see the <code>network</code> tier's Raw JSON entries below for "
        "exactly which.</p>"
        if crosses
        else "<p class='risk-clean'>✓ Nothing in this document reaches beyond loopback or the local filesystem.</p>"
    )
    return f"{table}{boundary_note}"


def render_html(bom: dict) -> str:
    """Build the full HTML document for a harness-aibom CycloneDX dict."""
    metadata = bom.get("metadata", {})
    root = metadata.get("component", {})
    root_single, root_relationships = _split_properties(root)
    scan_warnings = _extract_warnings(root)

    harness_name = root.get("name", "harness")
    runtime_kind = root_single.get("harness-aibom:runtimeKind", "unknown")
    hostname = root_single.get("harness-aibom:hostname", "unknown")
    timestamp = metadata.get("timestamp", _NOT_RECORDED)
    serial = bom.get("serialNumber", _NOT_RECORDED)

    components = bom.get("components", [])
    services = bom.get("services", [])
    comp_groups = _group_by_class(components)
    svc_groups = _group_by_class(services)
    all_groups = {**comp_groups, **svc_groups}

    kpi_tiles = [
        ("Components", len(components)),
        ("Services", len(services)),
        ("Models", len(comp_groups.get("model", []))),
        ("Secrets surfaces", len(comp_groups.get("secrets_surface", []))),
        ("Hooks", len(comp_groups.get("hook", []))),
    ]
    class_counts = {cls: len(entries) for cls, entries in all_groups.items()}
    architecture_graph = security.build_architecture_graph(bom)
    # Every per-entry adjacency map / lookup is built exactly once here
    # and reused for every rendered entry below -- security.py's own
    # per-call functions would otherwise rebuild each from scratch once
    # per entry (O(entries x edges) instead of O(entries + edges)).
    # `supply_chains` (forward: what a component depends on) and
    # `blast_radii` (backward: what depends on a component -- the
    # correct "what's affected if this is compromised" direction, v0.5.1)
    # are deliberately two different traversals over the same edges, not
    # one function pretending to answer both questions -- see SPEC.md
    # section 11.
    dependency_children = security.build_dependency_children(bom)
    dependency_parents = security.build_dependency_parents(bom)
    mcp_servers = security.index_mcp_servers(bom)
    ctx = {
        "mcp_servers": mcp_servers,
        "supply_chains": {
            ref: security.compute_supply_chain(bom, ref, dependency_children)
            for entry in components + services
            if (ref := entry.get("bom-ref"))
        },
        "blast_radii": {
            ref: security.compute_blast_radius(bom, ref, dependency_parents)
            for entry in components + services
            if (ref := entry.get("bom-ref"))
        },
    }

    summary_rows = "".join(
        f"<tr><td>{_class_dot(cls)}{_esc(cls)}</td><td>{len(entries)}</td></tr>"
        for cls, entries in sorted(all_groups.items())
    )

    # Inferred from the input document itself, not a separate CLI flag:
    # when the scan that produced `bom` was run with --deterministic,
    # `serial`/`timestamp` are both the _NOT_RECORDED sentinel already --
    # embedding wall-clock time here regardless would still make two
    # renders of the same deterministic document differ byte-for-byte,
    # defeating the whole point of --deterministic (hashing/signing the
    # AIBOM as a baseline). Confirmed real: two renders one second apart
    # produced two different files even from a --deterministic scan.
    deterministic_input = serial == _NOT_RECORDED and timestamp == _NOT_RECORDED
    generated_line = (
        "Generated by agent-harness-aibom (deterministic input; no render timestamp)"
        if deterministic_input
        else f"Generated by agent-harness-aibom · {_esc(datetime.now(timezone.utc).isoformat(timespec='seconds'))}"
    )

    # The one real copy of the whole document, embedded once (compact,
    # not pretty-printed) for every "Raw JSON" reveal (per-entry and the
    # top-level Raw BOM) to render lazily from client-side -- see _JS.
    # `.replace("</", "<\\/")`: a `</script` substring inside the JSON
    # (a component name/property value could contain literal text like
    # that) would otherwise be read by the HTML *parser* as this
    # <script> tag's own closing tag, truncating the embedded data and
    # leaving whatever followed to render as page markup instead of
    # JSON -- `\/` is a valid JSON escape for `/`, so this changes
    # nothing about the parsed value, only how the raw bytes look to the
    # HTML tokenizer before JSON.parse ever sees them.
    bom_data_json = json.dumps(bom, separators=(",", ":")).replace("</", "<\\/")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harness AIBOM Report — {_esc(harness_name)}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>{_esc(harness_name)}</h1>
  <p class="muted">
    runtime: <strong>{_esc(runtime_kind)}</strong> ·
    host: <strong>{_esc(hostname)}</strong> ·
    scanned: {_esc(timestamp)} ·
    serial: {_esc(serial)}
  </p>
</header>

{_render_explorer_nav()}

{_render_warnings_banner(scan_warnings)}

<section id="architecture">
  <h2>Architecture</h2>
  <p class="muted">What this agent is made of and how the pieces connect &mdash; one box per
    category (not per component), positioned by real depth in the document's own dependency
    graph. Click a box to jump to and filter Components/Services below.</p>
  <div class="arch-card chart-card">{_render_architecture_graph(architecture_graph)}</div>
</section>

<section id="security-summary">
  <h2>Security summary</h2>
  {_render_security_summary(bom)}
</section>

<section id="risk">
  <h2>Risk observations</h2>
  <p class="muted">Explainable, rule-based findings only &mdash; never a single opaque risk score.
    Each observation names the exact rule that fired; verify it against the components listed.</p>
  {_render_risk_observations(bom)}
</section>

<section id="attack-surface">
  <h2>Attack surface</h2>
  <p class="muted">Every component grouped by where it actually sits &mdash; filesystem, a local
    process, loopback, network, a credential store, or a model provider &mdash; a fixed,
    explainable classification (see SPEC.md section 11), never a guess at behavior this
    scanner didn't observe.</p>
  {_render_attack_surface(bom)}
</section>

<section id="mcp">
  <h2>MCP security</h2>
  {_render_mcp_security(services)}
</section>

<section id="summary">
  <h2>Summary</h2>
  {_render_kpi_row(kpi_tiles)}
  <div class="chart-card">{_render_bar_chart(class_counts)}</div>
  <table class="summary">
    <tr><th>componentClass</th><th>count</th></tr>
    {summary_rows or "<tr><td colspan='2'><em>nothing found</em></td></tr>"}
  </table>
  {_render_relationships(root_relationships)}
</section>

{_render_filter_bar(class_counts)}

<section id="components">
  <h2>Components</h2>
  {_render_skill_category_breakdown(comp_groups.get("skill", []))}
  {_render_groups(comp_groups, _COMPONENT_CLASS_ORDER, ctx) or "<p><em>none found</em></p>"}
</section>

<section id="services">
  <h2>Services</h2>
  {_render_groups(svc_groups, _SERVICE_CLASS_ORDER, ctx) or "<p><em>none found</em></p>"}
</section>

<section id="metadata">
  <h2>Metadata</h2>
  {_render_metadata_section(bom, root)}
</section>

<section id="external-references">
  <h2>External references</h2>
  {_render_external_references(bom)}
</section>

<section id="vulnerabilities">
  <h2>Vulnerabilities</h2>
  {_render_empty_cyclonedx_section(bom, "vulnerabilities", "Vulnerability data is not collected by this scanner.")}
</section>

<section id="compositions">
  <h2>Compositions</h2>
  <p class="muted">CycloneDX's own completeness declarations for this document -- see the
    AIBOM coverage detail under Security summary above for what this scanner does and doesn't
    include.</p>
  {_render_empty_cyclonedx_section(bom, "compositions", "Composition/completeness declarations are not collected by this scanner.")}
</section>

<section id="raw-bom">
  <h2>Raw BOM</h2>
  {_render_raw_bom(len(bom_data_json))}
</section>

<footer class="muted">
  {generated_line} ·
  every property of every component is rendered, nothing summarized away.
</footer>
<script type="application/json" id="bom-data">{bom_data_json}</script>
<script>{_JS}</script>
</body>
</html>
"""
