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
from datetime import datetime, timezone

#: componentClasses shown in this order when present; anything else
#: (a future class this file doesn't know about yet) is appended after,
#: sorted alphabetically -- so a new class never silently goes missing.
_COMPONENT_CLASS_ORDER = ("runtime", "configuration", "model", "skill", "hook", "secrets_surface")
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

_NOT_RECORDED = "not recorded (deterministic scan)"

_CSS = """
:root {
  --bg: #f9f9f7; --surface: #fcfcfb; --fg: #0b0b0b; --secondary: #52514e;
  --muted: #898781; --border: #e1e0d9; --baseline: #c3c2b7; --code-bg: #f3f4f6;
"""

for _cls, (_light, _dark) in _CLASS_COLORS.items():
    _CSS += f"  --class-{_cls}: {_light};\n"
_CSS += "  --class-unknown: #898781;\n}\n"

_CSS += """
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d0d0d; --surface: #1a1a19; --fg: #ffffff; --secondary: #c3c2b7;
    --muted: #898781; --border: #2c2c2a; --baseline: #383835; --code-bg: #1a1d24;
"""
for _cls, (_light, _dark) in _CLASS_COLORS.items():
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


def _component_class(entry: dict) -> str:
    for prop in entry.get("properties", []):
        if prop["name"] == "harness-aibom:componentClass":
            return prop["value"]
    return "unknown"


def _class_dot(cls: str) -> str:
    var_name = f"--class-{cls}" if cls in _CLASS_COLORS else "--class-unknown"
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


def _render_entry(entry: dict, cls: str) -> str:
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

    endpoints_html = ""
    if entry.get("endpoints"):
        endpoints_html = f"<p class='muted'>endpoints: {_esc(', '.join(entry['endpoints']))}</p>"

    return (
        "<div class='entry'>"
        f"<div class='entry-header'>{' '.join(header_bits)}"
        f" <span class='small'>{_esc(entry.get('bom-ref', ''))}</span></div>"
        f"{endpoints_html}"
        f"{_render_props_table(single)}"
        f"{_render_relationships(relationships)}"
        "</div>"
    )


def _group_by_class(entries: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for entry in entries:
        grouped.setdefault(_component_class(entry), []).append(entry)
    return grouped


def _render_group(cls: str, entries: list[dict]) -> str:
    body = "".join(_render_entry(e, cls) for e in sorted(entries, key=lambda e: e.get("name", "")))
    return (
        "<details open class='group'>"
        f"<summary>{_class_dot(cls)}{_esc(cls)} <span class='count'>({len(entries)})</span></summary>"
        f"{body}"
        "</details>"
    )


def _render_groups(grouped: dict[str, list[dict]], preferred_order: tuple[str, ...]) -> str:
    # Preferred classes first, in a fixed reading order; anything this
    # renderer doesn't specifically know about still gets shown, appended
    # afterward rather than silently dropped -- see module docstring.
    order = list(preferred_order) + sorted(set(grouped) - set(preferred_order))
    return "".join(_render_group(cls, grouped[cls]) for cls in order if cls in grouped)


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
        color_var = f"var(--class-{cls})" if cls in _CLASS_COLORS else "var(--class-unknown)"
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


def render_html(bom: dict) -> str:
    """Build the full HTML document for a harness-aibom CycloneDX dict."""
    metadata = bom.get("metadata", {})
    root = metadata.get("component", {})
    root_single, root_relationships = _split_properties(root)

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

    summary_rows = "".join(
        f"<tr><td>{_class_dot(cls)}{_esc(cls)}</td><td>{len(entries)}</td></tr>"
        for cls, entries in sorted(all_groups.items())
    )

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

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

<section>
  <h2>Summary</h2>
  {_render_kpi_row(kpi_tiles)}
  <div class="chart-card">{_render_bar_chart(class_counts)}</div>
  <table class="summary">
    <tr><th>componentClass</th><th>count</th></tr>
    {summary_rows or "<tr><td colspan='2'><em>nothing found</em></td></tr>"}
  </table>
  {_render_relationships(root_relationships)}
</section>

<section>
  <h2>Components</h2>
  {_render_groups(comp_groups, _COMPONENT_CLASS_ORDER) or "<p><em>none found</em></p>"}
</section>

<section>
  <h2>Services</h2>
  {_render_groups(svc_groups, _SERVICE_CLASS_ORDER) or "<p><em>none found</em></p>"}
</section>

<footer class="muted">
  Generated by agent-harness-aibom · {_esc(generated_at)} ·
  every property of every component is rendered, nothing summarized away.
</footer>
</body>
</html>
"""
