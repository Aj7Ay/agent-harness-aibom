# Harness AIBOM Specification (v0.1)

This document describes the data model `agent-harness-aibom` produces. It
answers a narrower question than a general-purpose AI BOM scanner: **what
exactly constitutes a deployed agent harness** — not just "which models and
libraries exist on this machine," but the runtime binary, the model
endpoint(s) it talks to, the configuration and skills it loads, the MCP
servers and hooks it can reach, and the secrets surface around all of that.

The facts this spec is grounded in come from two places already running in
the Practical DevSecOps CAASP course material, not from guessing:

- `~/pdso/Course/caasp/operationalizing-agentic-ai-security/endpoint-detection-for-hermes-agent/`
  and `~/pdso/Course/simple-lab-2-hermes-numbat.md` — Hermes CLI output,
  `~/.hermes/config.yaml` shape, `~/.hermes/skills/`, `hermes hooks doctor`.
- `~/pdso/Course/caasp/attacking-defending-memory-context-tools/auditing-hermes-mcp-connections/`
  — the MCP server audit shape (name/endpoint/TLS/auth/tools).
- `~/pdso/docker/devsecops-box-gpu-oc/README.md` — the OpenClaw gateway:
  `~/.openclaw/openclaw.json`, the Gateway token in `/opt/openclaw/.env`, and
  the per-agent SQLite credential store.

Anywhere a detail wasn't confirmed from that material (e.g. the exact
`openclaw --version` output format), this doc and the code say so rather
than inventing specifics.

**v0.1.1 update:** this spec was checked against a real, live Hermes box
(`devsecops-box-gpu-hm`) on 2026-09-08. Two assumptions from the first draft
were wrong; both are corrected below (§2, §3) rather than left as
documented guesses. See §5 for what that run confirmed and what still
needs a real box to check.

**v0.1.3 update:** an independent sandbox test (synthetic Hermes + OpenClaw
homes, fake CLIs, a mock Ollama server) found that the v0.1.2 output was
**not actually valid CycloneDX 1.6** — `model_endpoint` and `mcp_server`
used component `type: "service"`, which isn't in CycloneDX's `type` enum
at all; `service` is a distinct top-level concept in CycloneDX
(`bom.services[]`), not a component type. Verified directly against
`cyclonedx-python-lib`'s strict JSON Schema validator, which rejected every
v0.1.2 example document on that one field. Fixed in §1/§2 below: those two
classes now serialize into `bom.services[]`. The same test also found a
crash on an unreadable skill file, a secrets scan that missed anything
inside a skill directory, and several CLI rough edges — all fixed, see §5.

**v0.1.4 update:** the same reviewer re-tested v0.1.3 and confirmed every
fix above, then found one more real defect the recursive secrets scan
(from the previous fix) had exposed: `diff` indexed components by
`(componentClass, name)`, and `name` was just a file's basename, so two
different `.env` files in different directories — now common, since the
scan recurses into skill directories — collided under one dict key. The
second scanned always silently overwrote the first, so a real permission
change to one of them could vanish from a diff entirely, `--exit-code`
included. Reproduced and confirmed before fixing (§4).

**v0.1.5 update:** the same reviewer re-tested v0.1.4, confirmed the fix
and the whole regression suite, then found the v0.1.4 fix traded one
problem for another: keying on the *absolute* `path` broke comparing two
different machines with the same layout (a golden baseline vs. a lab VM,
one student's box vs. another's) — `/home/alice` and `/home/bob` share no
absolute paths, so an identical harness on two machines diffed as
everything added and everything removed. Fixed with a `relPath` property
(path relative to `--home`) that `diff` now prefers over the absolute
path; also had to stop comparing the absolute `path` field itself once two
entries are matched, since it's inherently host-specific noise at that
point. See §4.

**v0.1.6 update:** the same reviewer found a real defect in MCP server
extraction, confirmed against their own example config: a *stdio*-
transport entry (`command`/`args`/`env`, no `url`) has none of the fields
`mcp.py` looked for, so it came out as `tls=False, authConfigured=False`
— both actively wrong. There's no network transport for "no TLS" to
describe, and `env` routinely carries the real credential the old code
never looked at; `command`/`args` (the actually dangerous part) weren't
recorded at all. Fixed with a `transport` field, `tls: "n/a"` for stdio,
`env`'s *names* (never values) counted toward `authConfigured`, and
`command`/`args` recorded verbatim. See §2's `mcp_server` row.

**v0.1.7 update:** the same reviewer proposed a large roadmap (tool-level
hashing, prompt-surface tracking, memory-store inventory, a policy
command, CycloneDX 1.7, a Python dependency inventory, and more) alongside
two smaller, low-risk items. The larger items are real product decisions,
not bug fixes, and are intentionally *not* in this release — see the
project's own tracking for that discussion. The two small items shipped
here:
- **Hook script fingerprinting**, best-effort like the rest of hook
  parsing (§5): `contentChangedSinceApproval` is now parsed from the
  "script unchanged since approval" status line (confirmed real text from
  course material) instead of being discarded, and `path`/`relPath`/
  `sha256` are set opportunistically when the collector's guess at the
  script's location on disk happens to be right — it doesn't know the
  real location for certain, so a missing `sha256` means "not found at a
  guessed path," not "no script exists." Deliberately the *same*
  property names `configuration` and `skill` already use, not a
  hook-specific `scriptSha256`/`scriptPath` — `diff` (§4) picks a found
  hook script up as its identity and flags a changed one as
  `fingerprint_changed` with no hook-specific code at all.
- **`scan --deterministic`**: omits `serialNumber` and
  `metadata.timestamp` so two scans of an unchanged box produce
  byte-identical output — a prerequisite for hashing or signing the AIBOM
  itself as a baseline, which the roadmap already calls for (cosign).

**v0.1.8 update:** the same reviewer re-tested v0.1.5–v0.1.7, confirmed
every fix, then found four real defects in the two v0.1.7 additions,
ranked by severity:
- **A (high).** `contentChangedSinceApproval` never actually fired: the
  code checked for the ✓/✗ marker *before* checking for a script name, so
  the no-name status line describing the previous hook was dropped before
  ever reaching the new branch — a shipped feature that was dead code
  against the confirmed real text. Fixed by checking for a name first.
- **B (high).** `_attach_script_fingerprint` could hash the wrong file
  entirely: a relative captured name was tried as-is first, which
  resolves against the process's *current working directory* — an
  unrelated file merely sitting wherever `harness-aibom scan` happened to
  be run from could get reported as the hook's own fingerprint. Fixed by
  only ever trying a relative name joined onto a known root
  (`hermes_dir/"hooks"`, `home`), never bare. Reproduced exactly as
  reported (a decoy script in cwd) before and after fixing.
- **C (medium).** `authConfigured` was true for *any* non-empty `env` on
  a stdio MCP server, so e.g. `NODE_ENV`/`LOG_LEVEL` alone read as
  credential-bearing — a false positive. Fixed: only env var *names*
  matching a credential-shaped pattern (`KEY`/`TOKEN`/`SECRET`/
  `PASSWORD`/`CREDENTIAL`/`AUTH`) count, recorded separately in
  `authEnvKeys`; `envKeys` still records every name as raw evidence.
- **D (low).** SSE-transport detection tested `"sse" in endpoint` as a
  plain substring anywhere in the URL, so `assets.example.com` (containing
  "sse" inside "assets") misread as SSE. Fixed: parses the URL and checks
  the actual path.

All four confirmed against the reviewer's exact reproductions, both
before and after fixing. See §2 (`hook`, `mcp_server` rows) and §4.

**v0.1.9 update:** the same reviewer re-tested v0.1.8, confirmed all four
fixes, then found two more real defects in the same hook-fingerprint code
— both edge cases the v0.1.8 fixes hadn't fully closed:
- **Medium.** `pathOutsideHome` only fired when the *captured name
  itself* was written as an absolute path — missing exactly the case the
  flag exists to catch: a hook that sits inside `--home` on the surface
  but is actually a symlink resolving somewhere else entirely
  (`~/.hermes/hooks/audit.sh -> /tmp/evil/payload.sh`). Fixed by driving
  the flag off the *resolved* candidate instead — `rel_path is None`,
  regardless of whether the input name looked absolute. Also added a
  `symlink` property recording whether the guessed location was itself a
  symlink (`path` already carries the resolved target, so there's no
  separate `symlinkTarget` — that would just repeat `path`).
- **Low.** A status line that repeats the hook's own script name (e.g.
  `"pre-commit.sh CHANGED since approval"`) matched the name regex,
  skipped the no-name branch entirely, then failed the marker check and
  was silently dropped — one of three plausible real formats for that
  line still lost the signal. Fixed by checking for the "since approval"
  phrase completely unconditionally, before any name or marker logic —
  simpler than trying to enumerate which combinations of "has a marker"
  and "repeats the name" are and aren't real, none of which is actually
  confirmed either way.

Both confirmed against the reviewer's exact reproductions, both before
and after fixing.

**v0.1.10 update:** the same reviewer re-tested v0.1.9, confirmed both
fixes, then found one high-severity regression the "Low" fix above had
introduced, plus one further defect:
- **High (regression).** The v0.1.9 fix for "status line repeats the
  hook's name" made the "since approval" check fully unconditional — but
  a line can be *both* a real hook entry (marker + name) *and* mention
  "since approval" in the same breath (e.g.
  `"✓ pre-commit.sh allowlisted (unchanged since approval)"`), and the
  unconditional check swallowed that shape entirely: every hook silently
  dropped, `found_any` never set, so the best-effort warning never fired
  either. A reader had no way to tell "this box has no hooks" from "the
  parser dropped them" — the worst failure mode a scanner has. Fixed by
  making the actual discriminator explicit: a line carrying *both* a
  marker *and* a name is always a new hook entry (which may also carry
  its own content-changed signal, read from the same line), and only a
  line that mentions "since approval" *without* being such an entry is a
  status continuation. Also added a guard: if the output contains any
  ✓/✗ marker lines but zero hooks were extracted, that's now a warning
  instead of a silent empty result — so this whole class of failure
  can't recur invisibly even for a fourth line shape nobody's found yet.
- **Medium.** `mcp_server` (and `model_endpoint`) are services (§1),
  carrying neither `path` nor `relPath` — so two same-named MCP servers
  collapsed into one `diff` entry the same way two same-named `.env`
  files used to (§4), and a TLS downgrade on one of them vanished
  silently. Fixed with per-document disambiguation using each entry's
  `endpoint` (or `command`+`args` for a stdio server) when a name turns
  out to be shared — see §4 for the trade-off this involves.

Both confirmed against the reviewer's exact reproductions, both before
and after fixing.

**v0.1.11 update:** shipped `tests/test_hook_parsing_matrix.py` and
`tests/test_diff_identity_matrix.py`, consolidating every hook-output
shape and diff-identity edge case found so far into two table-driven
suites (§7), specifically to close the gap that let the v0.1.9
regression through — a fix for one shape was never checked against the
others already known to matter.

**v0.1.12 update:** the same reviewer found that v0.1.11's own sdist
didn't actually ship what it claimed to: `tests/*.py` was included by
setuptools' default sdist file list, but `tests/fixtures/`'s non-`.py`
support files (YAML, JSON, shell scripts, a symlink) weren't — 26 of 104
tests then failed for anyone installing from the sdist, in a way that
reads as defects in the code rather than a packaging gap. Nothing in this
project's actual workflow (CI, `uv sync --extra dev`, this README) ever
tests from a downloaded sdist, only from a git checkout, so there was
nothing to preserve by including `tests/` at all — fixed by excluding it
from the sdist entirely (`MANIFEST.in`: `prune tests`) rather than trying
to enumerate every fixture file type going forward.

The same review also found that the disambiguation added in v0.1.10 was
computed separately per document, which broke exactly the case it hadn't
been tested against: an MCP server `name` unique in `before` (one entry,
undisambiguated) but duplicated in `after` (two entries, both
disambiguated) never matched on either side — the persisting server read
as removed, and *both* after-side entries read as added. Fixed by
deciding which base identities need disambiguating from the union of
*both* documents (`diff._ambiguous_keys()`), not from each document in
isolation, so the same logical server gets the same treatment regardless
of which scan happens to have the duplicate. See §4.

**v0.2.0 update:** the same reviewer measured a real 15-entry document
against what a bill of materials is supposed to answer ("what parts is
this made of," "what else is affected if part X is compromised") and
found it couldn't answer either one: zero `purl`s, zero dependency edges
beyond a flat root star, `toolCount` instead of named tools. Fixed the
tractable core of that critique here — the report/CLI bugs from the same
review round too (§8, and the sdist-testing gap from v0.1.12's own
reviewer separately confirmed clean):

- **`tool` components** (§2): one per declared tool name, with a
  name-only `riskClass` heuristic, instead of a bare `toolCount`.
  Deliberately does *not* add a schema-hash field this scanner has no
  data to back (§5).
- **`purl` + `versionPinned`** on stdio `mcp_server` entries (§2),
  parsed from `command`/`args` for `npx`/`uvx` launchers specifically —
  the package identity was already being collected and then discarded.
- **A real dependency graph** (§1): `configuration -> model_endpoint ->
  model` and `configuration -> mcp_server -> tool`, via a new
  `HarnessDocument.add_child()`, instead of every relationship
  collapsing into one root star.
- **Native `hashes[]`** alongside the existing `harness-aibom:sha256`
  property (additive, not a replacement — `diff.py` still keys on the
  property by name).
- The five `report` bugs from the same round (§8): UTF-8 write
  encoding, refusing to overwrite the input file, rejecting non-dict
  input, catching write failures, and a deterministic report footer.
- Scan warnings now reach the document itself, not just stderr, and
  `report` renders them as a banner (§8) — otherwise a partial scan
  looks indistinguishable from a complete one.

**Deliberately deferred, not silently dropped** — each because doing it
without real data to ground it would mean inventing unconfirmed specifics
or claiming detection capability this scanner doesn't have, the same
discipline this whole spec has followed from v0.1.1 onward:

- A Python dependency inventory for the *scanned harness's own*
  site-packages (not this package's) needs a confirmed real venv layout
  for Hermes/OpenClaw on an actual box, which isn't available.
- `prompt_surface` (`AGENTS.md`/`CLAUDE.md`/instruction files) and
  `memory_store` (conversation/vector stores) are both real gaps the
  same review named, but adding them alongside everything else in this
  pass — untested against any real box's actual file layout — was a
  bigger risk than the value of rushing them in.
- Full native-field migration (`modelCard`, `evidence.occurrences`,
  `externalReferences`, `licenses`, `supplier`) beyond the additive
  `hashes[]` above would touch nearly every property this spec defines
  and every test that references one by its `harness-aibom:` name —
  correctly described by the same review as needing its own release.
  (`licenses`/`supplier` narrowed, not fully closed, as of v0.2.4: a
  `dependency` component gets both, since `deps.py` already reads the
  METADATA file they come from — `modelCard`, `evidence.occurrences`,
  and `externalReferences` are still untouched.)
- Linking a skill to the servers/models its own prose actually
  references would need parsing `SKILL.md`'s content, which this
  scanner doesn't do.
- `policy`, severity-in-`diff`, `report --diff`, and `merge`/`gap`
  commands are new subcommands, not fixes to this release's scope.

**v0.2.1 update:** the same reviewer re-tested v0.2.0 end-to-end (purl
derivation, tool components, the new dependency graph, hashes, warnings,
the five report fixes — all confirmed clean, no regressions) and then
measured the release against the two things it had just added: `purl` and
tool components. Two real gaps, plus three smaller ones from the same
pass:

- **`purl` is now a native CycloneDX field on real `component` entries,
  not just a `harness-aibom:` property.** Checked directly against the
  real schema (`cyclonedx.schema._res.bom-1.6.SNAPSHOT.schema.json`):
  `purl` is a first-class field on `component`, absent on `service`. A
  stdio `mcp_server`'s launcher package now also exists as its own
  standalone `dependency` component (§2) — a real `application ->
  library` edge a generic SBOM/vuln tool can actually resolve, alongside
  the server's own `harness-aibom:purl` property (kept, additive, since
  `diff.py` keys on the property by exact name).
- **A Python dependency inventory for the scanned harness's own install**
  — deferred in v0.2.0 for lack of a confirmed real venv layout — is
  implemented via `collectors/deps.py`, walking `<installDir>/**/
  site-packages/*.dist-info/METADATA`. This isn't harness-specific
  guessing: PEP 376/427's `.dist-info/METADATA` layout is a universal
  Python packaging convention, true for a venv, a pipx install, or a
  system Python alike, unlike the still-unconfirmed hook-script-location
  guessing in `hermes.py`. Wired into Hermes (which captures `installDir`
  from `hermes --version`); wired into OpenClaw too but a no-op there
  until `openclaw --version`'s output format is confirmed and captures
  its own `installDir` (§5).
- **`tool`'s `riskClass` keyword list expanded** (§2) after a reviewer
  probe found common git-style tool names (`git_commit`, `git_push`,
  `git_status`) reading as `unknown`. Added `commit`/`push`/`apply`/
  `patch`/`install`/`set` (write) and `status` (read). Still a name-only
  heuristic (§5) — this closes a real coverage gap in that heuristic, not
  the heuristic's inherent limit.
- **Two `tool` components can collide under the same base identity** the
  same way two same-named `mcp_server` entries already could (§4): a
  tool's name is `<server_name>/<tool_name>`, so two servers sharing a
  config `name` produce tools that also share a name. Confirmed this
  already falls back correctly to `diff.py`'s existing positional
  fallback (no new code needed) — pinned with a dedicated case in
  `tests/test_diff_identity_matrix.py` rather than left as an
  accidentally-correct, untested path.
- **The HTML report's class ordering** (§8) now places `tool` and
  `dependency` in their natural reading position (`dependency` right
  after `runtime`, `tool` right after `skill`) instead of falling through
  to the alphabetical catch-all for classes the renderer doesn't
  specifically know about. Both still render in the shared neutral gray,
  not a new hue — the dataviz skill's 8-slot categorical palette is
  already exactly full (§8).

**Confirmed correct as-is, not changed:** the reviewer also asked whether
`tool` should get a schema-derived fingerprint (e.g. hashing its input
schema) the same way a `hook` or `skill` gets a `sha256`. It still
shouldn't, for the same reason as v0.2.0: this scanner reads static config
files, never performs a live MCP protocol handshake, so it has no schema
to hash, only a bare name (§2, §5). The only way to close that gap for
real is a future `--probe` mode that actually connects to each configured
MCP server and asks it to describe its own tools — live network I/O this
scanner doesn't do today, and a large enough change (new failure modes,
new consent/safety questions about connecting to a possibly-untrusted
server) to belong to its own release rather than being folded in here.

**v0.2.2 update:** the same reviewer measured v0.2.1's two headline
features (native purl, the Python dependency inventory) against a 425-
component document and found one real bug in the dependency inventory
itself, plus three smaller gaps:

- **`deps.py` silently masked a real version change.** It deduplicated by
  package name across *every* `site-packages` directory found under
  `installDir`, keeping whichever sorted first and discarding the rest --
  not a contrived case: a pipx venv beside a vendored tree, pip's own
  `_vendor`, or a nested venv all produce a second `site-packages`.
  Reproduced exactly as reported: a stale `openai-0.1.0` in one directory
  masked the real, actually-running copy entirely; bumping the real copy
  from 1.99.1 to 2.0.0 and diffing produced no `dependency:openai` entry
  at all, in either scan. Fixed by no longer deduplicating across
  directories: one component per `(site_packages, name)` pair, each
  carrying `path` to its own dist-info directory (§2), so two disagreeing
  copies both show up, distinguishably, and nothing is ever silently
  dropped. (This bullet's original `relPath` design used the dist-info
  directory itself as the diffable identity -- corrected in v0.2.3, §2,
  once that turned out to have its own real problem.)
- **A component's top-level `version` field wasn't itself compared by
  `diff`.** `diff.py` only ever compares `properties[]`; a version change
  was only visible if it happened to also change some other compared
  property (e.g. a `purl` that embeds the version) -- a `dependency` that
  gained a version where it previously had none read as a `purl`
  *addition*, not a version change, and the reverse read as a removal.
  Fixed root-cause, not just for `dependency`: `component.version` (when
  set) is now always additionally mirrored as a `harness-aibom:version`
  property (alongside the native top-level field, same reasoning as
  `hashes[]`/`purl`), so `diff` compares it directly for every class that
  carries a version (`model`, `runtime`, `dependency`).
- **`tool`/`dependency` were pixel-identical to a genuinely unrecognized
  future class in the report** (§8), both falling through to the same
  flat gray as classes this renderer doesn't know about at all -- on the
  425-component document, 424 of 425 entries rendered as one
  indistinguishable gray. The categorical palette's 8 slots (dataviz
  skill) are exactly full, so this isn't a 9th/10th generated hue: two
  new near-neutral, low-chroma shades (`_KNOWN_UNPALETTED_CLASS_COLORS`)
  give `tool` and `dependency` their own distinct-but-muted look, visibly
  different from each other and from `_UNKNOWN_CLASS_COLOR`'s true
  "renderer doesn't recognize this" gray.
- **A docstring in `mcp.py` contradicted the code it described**, still
  claiming CycloneDX's component schema "has no top-level `purl` slot" --
  true for a *service*, false for a *component*, and the very reason the
  standalone `dependency` component exists in the first place (§2). Left
  uncorrected, the next person to read it would conclude the native field
  was impossible and leave it alone. Fixed to state plainly that the
  `dependency` component gets the real native field.

**v0.2.3 update:** the same reviewer re-tested v0.2.2 and found the fix
above for the masking bug had traded it for a different, real problem in
the same code:

- **A `dependency`'s diff identity was the dist-info directory itself,
  which embeds the package's own version** (`openai-2.0.0.dist-info`) --
  and pip upgrades a package by deleting the old dist-info directory and
  creating a new one, never renaming in place. So the identity itself
  changed on every single version bump, before `diff` ever got to compare
  `version`: every upgrade read as one entry removed and an unrelated-
  looking one added, never as `changed`. Concretely, an N-package upgrade
  produced 2N diff lines instead of N, each pair needing to be manually
  matched back up by a human reader -- and the `harness-aibom:version`
  mirror added in v0.2.2 specifically to make version changes visible to
  `diff` almost never actually fired for a `dependency`, the class it was
  aimed at, since pip never mutates a dist-info directory's `version`
  field in place the way this scanner's own test had (unrealistically)
  assumed.
- Fixed by keying `relPath` (§2) on the *containing* `site_packages`
  directory plus the package name (`<site_packages>::<name>`) instead of
  the dist-info directory -- stable across an in-place upgrade, since
  `site_packages` itself doesn't move or get renamed. The exact dist-info
  directory a scan found is still recorded, just under a new property,
  `distDir`, no longer as the diff identity. Two disagreeing copies in
  *different* `site_packages` directories are still fully distinguishable
  (that's what v0.2.2 fixed, and it still holds): their `relPath` differs
  on the `site_packages` half.

**v0.2.4 update:** the smallest item from the same reviewer's remaining-
work list, picked first because it's closest to free: a `dependency`
component now carries native `licenses[]`/`supplier` fields, parsed from
the same Python package `METADATA` file `deps.py` already reads (§2) --
no new file access, no new collector.

- **`License:`** -- promoted to a native `licenses[]` entry (`cyclonedx.
  py`'s `_license_dict()`). Deliberately `license.id` (the valid-SPDX-
  identifier slot) only on an *exact* match against a small, fixed
  allowlist of common SPDX ids (`MIT`, `Apache-2.0`, ...), never a
  normalization guess (`"Apache 2.0"` -> `"Apache-2.0"`, `"MIT License"`
  -> `"MIT"`): CycloneDX's schema validates `license.id` against the real
  SPDX license-id enum, and a wrong guess would fail strict validation.
  Anything not an exact match falls back to `license.name` (free text,
  no enum constraint) instead of being guessed or dropped. The
  historical setuptools/distutils placeholder `License: UNKNOWN` (and the
  same for `Author:`) is treated as absent, not emitted verbatim.
- **`Author:`/`Author-email:`, falling back to `Maintainer:`/
  `Maintainer-email:` only when Author is entirely absent** -- promoted
  to a native `supplier` (`organizationalEntity`) with `name`/
  `contact[].email`. `Author-email` commonly carries the RFC 822 "Name
  <email>" display form (the shape `[project.authors]` in a
  `pyproject.toml` gets flattened into by every PEP 621-aware build
  backend, often with no separate bare `Author:` line at all) -- parsed
  out so a package that only ever set `Author-email` still yields a real
  supplier name, not just an address. A partial `Author` (name only, no
  email) is never topped up from an unrelated `Maintainer-email`.

## 1. Format: CycloneDX 1.6, extended

The root `bom.metadata.component` describes the harness itself
(`type: application`, name `<runtime>@<hostname>`). Every discovered thing
becomes either a CycloneDX **component** (`bom.components[]`) or a
CycloneDX **service** (`bom.services[]`), whichever CycloneDX itself
distinguishes them as — a config file or a skill is a component; a
network-reachable thing like a model endpoint or an MCP server is a
service (§2 says which is which; `model.py`'s `SERVICE_CLASSES` is the
source of truth). Fields CycloneDX has no slot for go in that entry's
`properties[]` under a `harness-aibom:` namespace (e.g.
`harness-aibom:componentClass`, `harness-aibom:sha256`) — components and
services both support `properties[]`, so this works identically for both.
A CycloneDX-aware tool that ignores unknown property names still gets a
valid, useful BOM either way; `harness-aibom`'s own `diff`/`validate`
commands are the only consumers that need to understand them.

**Relationships.** CycloneDX's native `dependencies[]` only expresses
untyped "depends-on" edges, referencing bom-refs from either array. The
*verb* (`uses`, `loads`, `invokes`, `executes`, `accesses`, `approves`,
`pulls`) is layered on top as repeated `harness-aibom:relationship`
properties (`"<verb>:<bom-ref>"`) on the *source* entry of that edge.
Nothing exotic — still valid CycloneDX, just extra properties.

**The graph itself has real depth, not a flat star.** `HarnessDocument`
(model.py) has two ways to register a component: `add()` relates it to
the harness root — for things with no more specific parent in this data
model (`runtime`, `configuration`, `skill`, `hook`, `secrets_surface`) —
and `add_child(component, parent, verb)` relates it to an actual parent
component instead. `configuration` declares its `model_endpoint`(s) and
`mcp_server`(s) (`configuration -> model_endpoint`, `configuration ->
mcp_server`); an endpoint serves the model(s) reachable through it
(`model_endpoint -> model`); a server declares its own tools (`mcp_server
-> tool`). `cyclonedx.py` turns each component's own `relationships` into
*that component's* `dependencies[]` entry, not another root edge.
Confirmed real complaint, fixed here: a v1 draft of this spec had every
single relationship collapse into `harness-root -> everything`
regardless of what actually declared what — a document with 15 entries
had exactly 1 dependency edge and zero non-root nodes with children,
which a generic SBOM tool can't use for impact analysis at all (v1 called
this "a deliberate trade-off"; on reflection it was more of a shortcut
than a defensible design decision, so it's fixed rather than kept). Not
every relationship in this data model has a real parent to attach to yet
— a skill isn't (yet) *graph-linked* to the servers or models its own
content might reference. v0.6.0 (§13) added deterministic parsing of
`SKILL.md`'s prose (`analyze_skill_content()`), but only to record what
it finds as *properties* on the skill itself (`referencedServers`, a
text mention, not confirmation the skill invokes it at runtime) — not as
a real `dependencies[]` edge, which would need its own design pass on
what "inferred" means for the graph (§11, §13). So skills, hooks, and
secrets surfaces still hang directly off the root in the actual
dependency graph. That's a real remaining gap, not claimed otherwise.

## 2. Component taxonomy (v1)

**Components** (`bom.components[]`, each with a CycloneDX `type`):

| `componentClass` | CDX `type` | Key properties | Source |
|---|---|---|---|
| `runtime` | `application` | `version`, `installDir`, `installMethod`, `upstreamHash`, `pythonVersion`, `sdkVersion` | `hermes --version` / `openclaw --version` |
| `model` | `machine-learning-model` (native CDX ML-BOM type) | `digest`, `sizeBytes`, `modifiedAt`, `family`, `parameterSize`, `quantizationLevel`, `contextLength`, `thinking`, `ollamaNumCtx` | Ollama `GET /api/tags`, cross-referenced against the configured default model |
| `configuration` | `file` | `path`, `relPath` (path relative to `--home`; see §4), `sha256` | `~/.hermes/config.yaml`, `~/.openclaw/openclaw.json` |
| `skill` | `library` | `path`, `relPath`, `category` (if nested), `sha256` (of the whole skill directory), `description` (`descriptionSource`: `"frontmatter"` when a real `description:` field won, `"heading"` when it fell back to the first markdown heading -- v0.8.2); `referencedServers`/`urls`/`shellIndicators`/`envVarReferences` (v0.6.0, opportunistic -- only set when `analyze_skill_content()` actually finds something; a *text mention* in the skill's own `SKILL.md` prose, never confirmation the skill invokes it at runtime -- see §13); `frontmatterName`/`license`/`allowedTools` (v0.8.2, opportunistic -- only set when the SKILL.md's own `---`-delimited YAML frontmatter declares them; `frontmatterName` is informational only, `comp.name` itself stays directory-derived, the real bom-ref/diff identity) | `~/.hermes/skills/<category>/<name>/SKILL.md`, any depth |
| `hook` | `file` | `approvalStatus`, `approvedAt`, `rawLine`, `contentChangedSinceApproval` (bool, from the "since approval" status line, checked unconditionally regardless of marker or repeated script name), `path`/`relPath`/`sha256`/`mode`/`symlink` (opportunistic, same `path`/`relPath`/`sha256` names as `configuration`/`skill` — set only when a guessed file location happens to exist, never resolved against the current working directory; absence means "not found," not "no script"), `pathOutsideHome` (bool, driven off the resolved location, so a symlink escaping `--home` is caught too, not just a literally-absolute captured path) | `hermes hooks doctor` (best-effort text parse, see §5) |
| `secrets_surface` | `data` | `path`, `relPath` (absent when the scanned file isn't under `--home`, e.g. OpenClaw's `env_dir`), `mode`, `worldReadable`, `note` | recursive filesystem scan for `.env`, `*credentials*`, `*token*`, `*.pem`, `*.key`, `*.sqlite` under the harness's own directory, skill directories included; `name` is the path relative to the scanned root (not just the basename), so two `.env` files in different directories read as two distinct entries |
| `prompt_surface` (v0.6.0) | `file` | `path`, `relPath`, `sha256` (fingerprinted -- an instruction file's content is meant to be read, not kept private), `symlink` (bool, v0.7.0), `pathOutsideHome` (bool, v0.7.0 -- set only when `symlink` is true and its *resolved* target lands outside `--home`, same `is_symlink_outside_home()` helper `hook` uses) | recursive filesystem scan for exact filenames `AGENTS.md`/`CLAUDE.md` under the harness's own directory -- real, cross-project conventions (agents.md; Claude Code's own), not confirmed specifically for Hermes/OpenClaw, recorded on the same "absence isn't an error, presence doesn't over-claim relevance" basis as `secrets_surface` |
| `memory_store` (v0.6.0) | `data` | `path`, `relPath`, `mode`, `worldReadable` -- never fingerprinted, never opened to read content at all, same secrets-never-leak discipline as `secrets_surface` (§3); `symlink`, `pathOutsideHome` (v0.7.0, same semantics as `prompt_surface` above) | recursive filesystem scan for `chroma.sqlite3` (Chroma's own literal default filename), `*.faiss`/`*.index` (FAISS's own index-file extensions) -- deliberately narrower than a generic `*.sqlite`/`*.json` pattern |
| `tool` | `application` | `server` (parent server's name), `riskClass` (`read`/`write`/`exec`/`network`/`unknown`, a heuristic over the tool's own *name* — see below) | one per name in a `mcp_server` entry's `tools` list |
| `dependency` | `library` | `version`, native `purl` (see below); Python packages only -- one component per `(site_packages, name)` pair, never deduplicated across different `site_packages` directories, so two disagreeing copies both show up rather than one silently masking the other (v0.2.2); `path` (the exact dist-info directory found) and `distDir` (the same, relative to `installDir`); `relPath` is deliberately `<site_packages relative to installDir>::<name>`, NOT the dist-info directory -- a dist-info directory's name embeds its own version, so using it as the diffable identity made every version bump read as removed+added instead of `changed` (v0.2.3); native `licenses[]` from `METADATA`'s `License:`, native `supplier` from `Author:`/`Author-email:` (falling back to `Maintainer:`/`Maintainer-email:`) -- Python packages only (v0.2.4); `origin` (`"mcp-launcher"` or `"python-package"`, set by `mcp.py`/`deps.py` respectively) distinguishes the two sources this table's own "Source" column names, by a real recorded fact rather than an inferred absence -- security.py's `unpinned_dependency`-family risk rules key on it (v0.5.1, §12) | (a) a stdio `mcp_server`'s own launcher package (`npx`/`uvx`, parsed the same way as the server's `purl` property below), added as a child of that server; (b) an entry from the scanned harness's own Python install, via `collectors/deps.py` (§5) |

**Services** (`bom.services[]`, no `type` field — see §1):

| `componentClass` | Key properties | Source |
|---|---|---|
| `model_endpoint` | `provider`, `apiMode`, `endpoints[]` (native CDX field) | `config.yaml` / `openclaw.json` |
| `mcp_server` | `transport` (`stdio`/`http`/`sse`, SSE detected from the URL's actual path, not a substring test), `endpoint`, `endpoints[]` (native CDX field, URL-based transports only), `tls` (bool, or `"n/a"` for stdio), `authConfigured` (bool — declared auth *or* a credential-shaped `env` var name), `envKeys` (every env var name, raw evidence), `authEnvKeys` (only the names that look credential-shaped), `command`, `args`, `purl` (best-effort, stdio servers launched via `npx`/`uvx` only — see below), `versionPinned` (bool, alongside `purl`), `toolCount` | `mcp_servers` list inside either config file |

`model` deliberately uses CycloneDX's native `machine-learning-model` type
rather than a generic one — it's a real ML-BOM component, not just a file.

**`tool`'s `riskClass` is a name-only heuristic, not a schema analysis.**
An independent reviewer's own measurement of a real scan — 15 entries,
zero with a `purl`, three MCP servers reduced to a bare `toolCount` —
argued that a *count* can't detect the attack that matters (a tool's
declared behavior silently changing, a "rug pull"). That's correct, and
turning `toolCount: 3` into three named, riskClass-tagged components is a
real improvement: an over-privilege review can now see *which* tools a
server exposes and roughly what they do. What it deliberately does
**not** do is detect a rug pull itself: this scanner reads static config
files, never performs a live MCP protocol handshake, so it has no tool
*description* or *input schema* to hash — only the bare name the config
happens to list. Hashing just the name would only ever catch a rename,
and shipping that under a name like `definitionSha256` would claim
detection capability the tool doesn't have. See §5.

**`mcp_server`'s `purl` is also best-effort, from the launcher only.**
`npx -y @scope/pkg@1.2.3` and `uvx pkg==1.2.3` are recognized (npm and
PyPI respectively); anything else gets no `purl` rather than a guess. A
missing version (`npx -y @scope/pkg` with nothing pinned) sets
`versionPinned: false` — the launcher fetches whatever it resolves as
"latest" at every invocation, which is itself worth flagging, not just an
absent field. As of v0.2.1, the same parse also produces a standalone
`dependency` component (above) carrying a native CycloneDX `purl` field —
`component` has one natively (confirmed against the real schema),
`service` does not, so `mcp_server` itself keeps `purl` as a
`harness-aibom:` property only, and the `dependency` child is what a
generic SBOM/vuln-scanning tool (one that only reads native fields) can
actually resolve.

## 3. Fingerprinting rules

`configuration` is SHA-256 over the config file's bytes. `skill` is
SHA-256 over **every file in the skill's directory**, not just `SKILL.md`
— confirmed against a live box that real skills carry `scripts/`,
`references/`, and `templates/` alongside `SKILL.md` (e.g.
`research/arxiv/scripts/`, `productivity/google-workspace/scripts/`), and
those scripts are exactly where a poisoned skill would carry its payload.
A `SKILL.md`-only hash would miss any change to them entirely; the first
draft of this spec hashed only `SKILL.md`, which was wrong for that
reason. Files are hashed in sorted relative-path order so the digest
doesn't depend on filesystem ordering.

`model.digest` is taken verbatim from Ollama's own manifest digest, never
recomputed.

`secrets_surface` is **fingerprint-exempt by design**: hashing or reading
`.env`/token/SQLite contents would turn the AIBOM itself into a secrets
leak. It records path, POSIX mode, and world-readability only — never file
contents, never a hash derived from contents. The scan recurses through the
whole harness directory, skill directories included — a `.env` dropped
inside a skill is exactly where a poisoned skill would keep a payload's
configuration, and a top-level-only scan would never see it.

This is a promise, not just an assumption — an independent reviewer
pointed out that the stdio MCP `env` handling (§2's `mcp_server` row) is
exactly the kind of new code path that could accidentally start reading a
value instead of just a name. `tests/test_redaction.py` proves it: it
plants one unique string in a `.env`, an MCP server's `env`, an MCP
server's `auth.token`, a skill's `SKILL.md`, and a hook script, then
greps the fully serialized CycloneDX JSON for it.

Both `sha256_directory` and secrets-surface discovery tolerate permission
errors rather than crashing the scan: a subdirectory that can't be listed
(root-owned skills, scanned as a non-root user — a realistic lab condition)
is skipped, not fatal, and a file that's found but can't be opened still
has its path folded into the skill's hash, just not its content.

## 4. Diffing

`harness-aibom diff before.json after.json` indexes both documents by
`(componentClass, identity)`, where `identity` is, in order of
preference: the entry's `harness-aibom:relPath` property (its path
relative to `--home`), then `harness-aibom:path` (the absolute path),
then `name` (`model`, `runtime`, and the two service classes carry none
of the above). It reports `added` / `removed` / `changed` keys. A change
to `harness-aibom:sha256` or `harness-aibom:digest` is flagged with
`fingerprint_changed: true` — this is the mechanism for catching a
poisoned skill or a swapped model between two scans of the same harness.
The absolute `harness-aibom:path` field itself is never compared for a
matched pair (`diff.IGNORED_FIELDS`) — see the v0.1.5 reasoning below for
why.

This three-tier fallback replaced two narrower, each-wrong-in-turn
attempts, both confirmed by the same independent reviewer:

- **v0.1.0–v0.1.3 keyed on `name` alone**, which isn't unique once the
  secrets scan recurses into skill directories (§3) — two different
  `.env` files can both be named `.env`, collide under one dict key, and
  the second one scanned silently overwrites the first, hiding a real
  change to whichever file lost that collision.
- **v0.1.4 fixed that by keying on the absolute `path` instead**, which
  fixed the collision but broke comparing two *different* machines with
  the same layout — a golden baseline vs. a lab VM, one student's box vs.
  another's. `/home/alice` and `/home/bob` share no absolute paths, so an
  identical harness scanned on both diffed as everything added and
  everything removed, and every unchanged file's `path` field itself
  showed up as "changed" too, purely from the differing home directory.
- **v0.1.5 adds `relPath`** (path relative to `--home`), preferred over
  `path`: unique like `path`, but host-independent like `name` was
  supposed to be. Not every entry has one — OpenClaw's `env_dir` defaults
  to `/opt/openclaw`, entirely outside `--home` — those fall back to
  `path`, still unique, just not portable across machines.

Deliberately never keyed on `bom-ref`: its numeric `-2` disambiguation
suffix (model.py's `HarnessDocument.add()`) is insertion-order-dependent,
so adding one new component earlier in a later scan can shift every
following bom-ref and make untouched files look renamed.

`hook` components have this exposure only partially closed as of v0.1.7:
when `_attach_script_fingerprint` (hermes.py) actually finds the script
file at one of its guessed locations, the hook gets `path`/`relPath` and
diffs correctly like everything else. When it doesn't find the file —
still the common case, since the real storage location isn't confirmed
(§5) — there's nothing to key on but the bare script *name* parsed from
`hermes hooks doctor` text, and two hook scripts sharing a basename in
different directories would still collide.

**Same-name disambiguation for classes with no `path`/`relPath` at
all.** `model_endpoint` and `mcp_server` are services (§1) — they never
carry a path, so their identity always falls all the way to `name`, and
two services can share a config `name` the same way two `.env` files
could share a basename (confirmed real by an independent reviewer: two
`mcp_server` entries both named `"fs"` collapsed into one `diff` entry,
and a TLS downgrade on one of them vanished silently). `_index()`
disambiguates when a name turns out to be shared, using each entry's
`endpoint` (or `command`+`args` for a stdio server, §2) as a
content-derived tiebreaker, falling back to position only as a genuine
last resort. If the tiebreaking field itself is what changed between two
scans (e.g. a duplicate-named server's own `endpoint`), that reads as one
entry removed and one added rather than one changed. Still visible,
which is what matters — silence was the actual bug — just not as precise
as an unambiguous name would allow. A server whose `name` is unique in
the document is entirely unaffected by any of this and keeps plain
`changed` semantics for an endpoint change, same as always.

Whether a name "turns out to be shared" is decided from **the union of
both documents being compared** (`diff._ambiguous_keys()`), not from each
document checked in isolation — confirmed real bug fixed in v0.1.12: a
per-document check meant a name unique in `before` (one entry, no
disambiguator needed there) but duplicated in `after` (two entries,
disambiguated there) got a *different* key shape on each side and never
matched at all, so the persisting server read as removed and both
after-side entries read as added. Deciding from the union means the same
logical server gets the same disambiguated identity on both sides
regardless of which particular scan happens to hold the duplicate.

## 5. Known limitations (v0.1)

**Confirmed correct against a live Hermes box:** `hermes --version`'s
output shape (§2's `runtime` fields), `~/.hermes/config.yaml`'s `model.*`
keys, Ollama model discovery via `/api/tags` (including two models pulled
side by side, `qwen3:8b` and `llama3.1:8b`), and `.env` secrets-surface
detection with correct file mode.

**Corrected after that run** (both were wrong in the first draft, now
fixed above): the skill directory is nested by category, not flat (§2);
skill fingerprinting must cover the whole directory, not just `SKILL.md`
(§3).

**Also confirmed:** the live box had zero hooks registered, and
`hermes hooks doctor` says so plainly ("No shell hooks configured —
nothing to check."). That's a correct, clean result, not a parsing
failure — the collector no longer warns in that case. The `✓`/`✗`-per-line
format itself is confirmed from course material for a box *with* hooks
registered, but per-hook script-name extraction inside that format still
isn't checked against a live box that actually has one — that box would
need `numbat hook install` run on it first.

**Fixed in v0.1.3**, from an independent sandbox test:

- Output wasn't valid CycloneDX 1.6 (`service` isn't a component `type`,
  see the update note above) — the most important of these, since
  `validate`'s hand-rolled checks didn't catch it either (they checked
  structure, not the CycloneDX type enum), so the defect was invisible
  until checked against a real validator. `tests/test_cyclonedx_schema.py`
  now does that on every test run, specifically to keep this class of bug
  from going unnoticed again.
- A `PermissionError` reading an unreadable `SKILL.md` (or listing an
  unreadable skill subdirectory) crashed the whole scan instead of
  producing a `warning[...]` and continuing.
- The secrets scan only looked at the harness's top-level directory, never
  inside skill directories (§3).
- `validate`/`diff` printed a raw Python traceback for a missing or
  malformed input file instead of a clean error message.
- `diff` always exited 0, even when it found changes, making it unusable
  as a CI gate — added `diff --exit-code`.
- `--home relative/path` vs. `--home /abs/relative/path` for the same
  directory produced different `path` property values, showing up as
  false changes in a diff — `scan` now resolves `--home` to an absolute
  path before recording anything.
- `--pretty` had no way to turn it off — switched to
  `argparse.BooleanOptionalAction` (`--no-pretty` now exists).
- OpenClaw's `.env` directory (`/opt/openclaw` by default) had no CLI
  override — added `scan --openclaw-env-dir`.

**Still open:**

- **A component entirely outside `--home` breaks cross-host diffing.**
  `relPath` (§4) fixes cross-host comparison for everything actually
  under the scanned home directory, but OpenClaw's `env_dir` defaults to
  `/opt/openclaw`, outside `--home` by definition — those components
  still only have the absolute `path` to fall back to, and two different
  machines' `/opt/openclaw/.env` will never share that. Not a bug to fix
  so much as an inherent limit of what `relPath` can mean for a location
  that was never inside the harness's own home in the first place.
- **A stdio MCP server's `command` isn't fingerprinted.** It's recorded
  verbatim, but not hashed: `command` is very often `npx`/`uvx` resolving
  a package name at invocation time, not a single static file that
  exists on disk to hash before the server ever runs — a hash here would
  be misleading (it would "verify" the launcher, not what the launcher
  actually fetches and runs) more often than useful.
- **`openclaw --version` isn't parsed into a semantic version** — its exact
  output format wasn't in the source material, so the collector records the
  first line verbatim. Not yet checked against a live OpenClaw box. As a
  direct consequence, OpenClaw's `_collect_dependencies` (v0.2.1, §2) is
  wired up but a permanent no-op today: it has no `installDir` property to
  look under until this is fixed, since that's the same value it's
  missing here.
- **No remote/SSH scanning.** `harness-aibom scan` reads the filesystem and
  runs subprocesses on whatever machine it's invoked on. Scanning a remote
  lab VM means installing the package there (or SSHing in) — there's no
  built-in remote transport in v0.1.
- **No JSON Schema file of our own.** `validate` is hand-rolled structural
  checking (envelope + componentClass/array/type consistency), not a full
  CycloneDX 1.6 schema validator — reproducing that schema exactly would be
  its own maintenance burden. `tests/test_cyclonedx_schema.py` covers real
  CycloneDX-schema validity instead, via `cyclonedx-python-lib`, but that
  check runs in this package's own test suite, not in `harness-aibom
  validate` itself — a document could still drift from schema validity
  between test runs and releases without `validate` catching it.
- **The dependency graph has real depth as of v0.2.0 (§1), but not for
  every class.** `configuration -> model_endpoint -> model` and
  `configuration -> mcp_server -> tool` are real parent/child edges now;
  `skill`, `hook`, and `secrets_surface` still hang directly off the
  root in the actual dependency *graph* — v0.6.0 (§13) added
  deterministic `SKILL.md`-content parsing, but only as properties on
  the skill itself (a text mention), not a real graph edge, so this
  specific gap (a skill's *place in the dependency graph* not reflecting
  what it references) is narrowed, not closed. The verb
  on every edge (`uses`, `loads`, ...) is still only in
  `harness-aibom:relationship` properties, not a native CycloneDX field
  (§1 explains why: `dependencies[]` itself is untyped in CycloneDX).
- **`tool`'s `riskClass` is name-only, and there is no schema-level rug-
  pull detection.** This scanner reads static config files, never a live
  MCP protocol handshake, so it has no tool description or input schema
  to hash — only whatever bare name the config happens to list. A tool
  whose *declared name* stays the same but whose actual behavior changes
  server-side is invisible to this scanner by construction, not by an
  oversight that could be patched without adding live introspection.
- **Skill/secrets-surface bom-refs can collide by name** (e.g. two `.env`
  files in different directories). `HarnessDocument.add()` disambiguates
  with a numeric suffix so the document stays valid, but the disambiguation
  is order-dependent, not content-addressed. `diff` itself no longer has
  this problem as of v0.1.4 (§4) — this is about `bom-ref` specifically,
  which `diff` deliberately avoids keying on for that exact reason.
- **`hook` components can still collide in `diff`** if two hook scripts
  share a basename in different directories — there's no `path` property
  for them to key on yet, since hook data only comes from text-parsing
  `hermes hooks doctor`'s output, which doesn't include a full path (§4).

## 6. Explicitly out of scope for this spec

Cisco AI BOM comparison, cosign signing/provenance, and the full course lab
sequence are downstream work built *on* this package, not part of it.

## 7. Regression test matrices

`tests/test_hook_parsing_matrix.py` and `tests/test_diff_identity_matrix.py`
exist specifically so a change to hook parsing or `diff` identity gets
checked against *every* known real or reported shape at once, not one
report at a time. This project shipped a real regression (v0.1.9) where a
fix for one hook-output shape silently broke a different, already-working
one — a gap these two files exist to close going forward. Add a new row
to the relevant table (never a one-off test elsewhere) whenever a new
hook-output shape or diff-identity edge case is found.

`tests/test_diff_identity_matrix.py` also covers the identity-resolution
edge cases an independent reviewer's own probes had found and this
project's suite hadn't: a name unique in one document but duplicated in
the other (both directions), a change to the *middle* one of three
same-named entries, and the positional-fallback disambiguator (for
same-named services with no `endpoint`/`command`/`args` to key on at
all) — including a test that pins its known, accepted limitation: a
third, equally indistinguishable entry inserted *between* two existing
ones shifts every later position, and no scheme could avoid that without
some content-derived property to key on instead.

`tests/test_redaction.py` proves the secrets-never-leak promise (§3)
directly rather than only asserting it in comments.

## 8. HTML report

`harness-aibom report aibom.json -o report.html` renders any harness-aibom
document (from `scan`, with or without `--deterministic`) as a single,
self-contained, offline static HTML file — no CDN, no JavaScript
framework, no external dependency, same principle as the rest of this
tool. Collapsible sections (`<details>`/`<summary>`) need no JavaScript at
all.

The renderer (`report.py`) shows **every property of every component and
service** — nothing is summarized away or curated out, since the whole
point of an AIBOM is to be a complete record. Components are grouped by
`componentClass`, in the same reading order as §2's tables, with anything
this renderer doesn't specifically recognize still shown (appended after,
alphabetically) rather than silently dropped. `model` components show the
full Ollama-sourced provenance (§2) when it was captured — digest, size,
family, parameter size, quantization level — not just the model name.

Two correctness details worth noting for anyone touching this file:
- `harness-aibom:relationship` can repeat on one entry (every component
  the harness root touches adds one more "relationship" property to the
  *root* entry) — `_split_properties()` collects those into a list
  explicitly, since a plain `{p["name"]: p["value"] for p in properties}`
  dict comprehension would silently keep only the last repeat.
- Every user-controlled string (names, paths, property values) goes
  through `html.escape()` before reaching the page — confirmed with a
  test that plants HTML-special characters in a component name and
  asserts they never appear unescaped.

**Color for a class outside the 8-slot categorical palette (v0.2.2).**
`tool` and `dependency` are classes this renderer fully understands, but
the validated 8-hue palette (`_CLASS_COLORS`) is already exactly full —
the dataviz skill's rule is that a 9th series never gets a *generated*
hue. Rather than folding both into the same flat gray used for a class
this renderer genuinely doesn't recognize at all (confirmed real: on a
425-component document, 424 of 425 entries rendered pixel-identical),
they get `_KNOWN_UNPALETTED_CLASS_COLORS` — two near-neutral, low-chroma
shades distinct from each other and from `_UNKNOWN_CLASS_COLOR`, without
adding a real categorical hue to the validated set. `_class_color_var()`
is the one place all three tiers (validated hue / known-unpaletted /
true-unknown) are decided, reused by the dot, bar chart, and summary
table so they can't drift out of sync with each other.

Diff-mode HTML reports (color-coded added/removed/changed, from `diff`'s
own output) are deliberately out of scope for this first version — noted
as a natural next step, not attempted alongside the single-scan case.

## 9. Security analysis layer (v0.3.0)

**The problem this closes.** Up through v0.2.4, `report` answered "what
did I find" — a flat inventory (KPI row, a bar chart, per-class groups).
An independent reviewer's critique of a real 180-component document was
specific: the report needed to answer "what is this agent made of, how
are the pieces connected, what can they reach, and what's the impact if
one changes" — an architecture-and-risk reading, not just a count.

**`security.py` (new module).** Pure functions over an already-built
`bom` dict — no rendering, no filesystem access, independently testable
from `report.py`'s HTML generation, the same separation `cyclonedx.py`
(serialization) already has from `report.py` (rendering). Every number
each function returns is derived directly from data already in the
document; none of it is invented, estimated, or scored by an opaque
model. Five things, matching the reviewer's own "P0 — must have" list
(scoped deliberately to that list — see "Deliberately deferred" below):

1. **`build_architecture_graph()`** — a graph of the harness's structure
   at the **componentClass level, not the instance level**. This is the
   central design decision of this whole section: an instance-level graph
   (one box per component) wouldn't fix the reviewer's complaint, it
   would just be the same "180 things" inventory problem in diagram
   form — 73 skills would mean 73 boxes. Grouping by class collapses
   that into one node ("skill (73)") while still drawing every edge that
   actually exists between classes in the document's own real
   `dependencies[]` graph (aggregated, never invented) — e.g.
   `configuration -> mcp_server -> tool`. `report.py`'s
   `_render_architecture_graph()` lays this out as an inline SVG,
   positioned by real BFS depth from the root (closer to the root reads
   higher on the page), one row per depth — same offline, no-JavaScript,
   no-charting-library principle as the existing bar chart (§8), and the
   same `.chart-card svg { width: 100%; height: auto }` fix for
   letterboxing.
2. **`compute_security_summary()`** — real counts (`len()` over
   already-grouped entries) for categories the old KPI row didn't have:
   MCP servers/tools, executable tools (`riskClass == "exec"`),
   dependencies, and fingerprint coverage (how many of the document's
   components/services carry a native `hashes[]`, i.e. were actually
   fingerprinted, out of how many exist at all).
3. **`compute_risk_observations()`** — explainable, rule-based findings,
   **deliberately never a single opaque risk score**: the reviewer's own
   language was "use explainable rules", not an AI-generated number. Each
   observation names the exact rule that fired, a severity, and the
   bom-refs it matched, so a reader can go verify it against the document
   itself. The five rules today: a world-readable `secrets_surface`
   file; an MCP server on a network transport without TLS; an MCP server
   with no authentication configured; a `dependency` package with no
   pinned version (only possible for an MCP launcher package — a Python
   package found via `deps.py` always has one, since it's read from an
   already-installed dist-info); a `model` with no content digest.
   Absence of an observation is rendered explicitly as "no configured
   rule fired", never silently — a blank section reading as "nothing to
   report" would be indistinguishable from "nothing was checked".
4. **`classify_secret_confidence()`** — "high" or "heuristic" per
   `secrets_surface` entry, by re-matching its filename against a
   two-tier partition of `secrets.py`'s own `SECRET_NAME_PATTERNS`: exact/
   near-exact shapes (`.env`, `*.pem`, `*.key`) are "high"; broad
   substring/extension matches the reviewer specifically named as noisy
   (`*token*` matches `tokenize.js` as happily as a real credential;
   `*.sqlite` matches every SQLite database, credential or not) are
   "heuristic". `tests/test_security.py` asserts the two tiers' union
   equals `SECRET_NAME_PATTERNS` exactly, so a future change to that list
   can't silently drift out of sync with this classification.
5. **`compute_coverage()`** — a checklist against `COLLECTIBLE_CLASSES`
   (every componentClass this scanner can currently emit) plus
   `NOT_YET_COLLECTED` (`prompt_surface`, `memory_store` — real, named
   gaps this project has already documented, not new ones). "N / M known
   categories" is an honest completeness signal in a way a raw component
   count isn't: 180 components tells you nothing about whether an entire
   category was never even attempted.

**One place the reviewer's own mockup was corrected, not implemented as
written.** Their sketch of the security-summary panel included a
"Changed since baseline: 0" line. `report` operates on a *single* scan —
it has no second document to compare against, so a literal "0" there
would look like a verified fact ("nothing changed") when it's actually
just an absent measurement. Emitting it would repeat the exact failure
mode this whole project has spent five patch releases fixing (a
document that looks complete when it's actually silently missing
something). Implemented instead as an explicit line: "Baseline
comparison: not available for a single scan — use `harness-aibom diff`."

**Rendering (`report.py`).** Four new sections, added *above* the
existing Summary/Components/Services sections rather than replacing
them — the reviewer was explicit that the existing inventory view stays
valuable, this is an addition, not a rewrite: **Architecture** (the
class-level graph), **Security summary** (the inventory/integrity
tables), **Risk observations** (the rule-based findings list), and
**MCP security** (one card per `mcp_server` with TLS/auth status as
color-coded pills, instead of reading those two facts out of a generic
properties table). A **Skills by category** breakdown
(`_render_skill_category_breakdown()`) was added inside the existing
Components section, grouping already-known skills by their real
`category` property — deliberately NOT the richer per-skill
"references these tools/servers/endpoints" view from the reviewer's
mockup, since that needs parsing `SKILL.md` content, which this scanner
still doesn't do (§5, unchanged by this release).

**Color, status pills, and the dataviz skill's fixed status palette.**
The severity badges (Risk observations) and TLS/auth pills (MCP
security) use the *status* palette, not the categorical one — good
`#0ca30c`, warning `#fab219`, serious `#ec835a`, critical `#d03b3b`,
fixed values confirmed from `references/palette.md`, mode-invariant (same
hex in light and dark) rather than swapped like the categorical
`--class-*` variables. Every pill/badge pairs its color with a text
label (`TLS`/`no TLS`, `HIGH`/`MEDIUM`/`LOW`, ...), never color alone,
per the skill's "status colors... ship with an icon + label" rule.

**Deliberately deferred, not silently dropped** — the reviewer's own
staged list (P1/P2), kept out of this release for the same reason every
prior deferral in this spec was: building it without real data to ground
it, or folding it into an already-large release, would cost more in risk
than it returns:
- **Blast-radius analysis** (click a component, see everything it can
  reach) — the reviewer's own highest-value P1 item, but a genuinely new
  interaction model for a static, JavaScript-free HTML file; needs its
  own design pass on how to do that without JavaScript, or a decision to
  finally add a minimal script for it.
- **Provenance/evidence detail per component**, **baseline comparison
  built into `report` itself** (`report --diff`), and **explainable risk
  *rules* beyond the five above** are all P1 — real value, not attempted
  alongside the P0 set in one release.
- **Skill-content relationship extraction** (linking a skill to the
  servers/models its own `SKILL.md` prose references), **`prompt_surface`**,
  **`memory_store`**, **a `policy` command**, and **a CI/CD security
  gate** are P2 — new collectors, new subcommands, or both; SPEC.md has
  named these gaps since v0.2.0 and they remain open here.

## 10. AIBOM Explorer (v0.4.0)

**The full roadmap this section is one step of** is kept outside this repo,
in the assistant's own persistent memory (`aibom-explorer-roadmap` /
`security-py-architecture`), not duplicated here — an independent
reviewer's 37-item review after v0.3.0 shipped, staged into v0.4.0
("AIBOM Explorer", built here) through v0.7.0 ("DevSecOps": `report
--diff`, a `policy` command, SARIF output, AIBOM signing). Each future
release still gets its own versioned update note here, same as every
release before it — this section only records what v0.4.0 itself
changed.

**The one deliberate architectural exception this release makes.**
Every report through v0.3.0 needed zero JavaScript — `<details>`/
`<summary>` covered every collapsible section, including the v0.3.0
security-analysis panels. Live text search and a componentClass filter
across a document with hundreds of entries genuinely cannot be done in
pure HTML/CSS the way expand/collapse could. `report.py` now embeds a
small, plain (`_JS`), inline `<script>` block — global functions, no
IIFE, no build step, no bundler, still zero external dependencies and
still a single offline file. Everything that *can* stay JS-free still
is: the per-entry raw JSON reveal and the raw-BOM viewer both use native
`<details>`/`<pre>`, not a JavaScript drawer.

**What was added:**
- **Sticky navigation** (`_render_explorer_nav()`) — anchor links to
  every major section, `position: sticky` CSS, no JS needed for this
  part.
- **Search + class filter** (`_render_filter_bar()`, `applyFilters()` in
  `_JS`) — every `.entry` div now carries `data-class` (its
  componentClass) and `data-search` (a lowercased blob of its name,
  bom-ref, type, version, and every property's own key/value, plus every
  relationship string). An independent reviewer's own examples were
  specific: "search `sha256` → find fingerprinted objects", "search
  `world-readable` → find the affected secret" — both need property
  *values* searchable, not just component names, which is why the blob
  includes them. The class-filter `<select>`'s options are generated
  from `class_counts` (already computed for the bar chart), so it can
  never offer a componentClass that isn't actually present in the
  document.
- **Clickable architecture diagram** — every non-root box in the
  Architecture section (§9) now has an `onclick="goToClass('<cls>')"`
  handler that sets the class filter, re-applies it, and scrolls to that
  class's group. Clicking the root box calls `goToClass('')`, which
  resets the filter — "harness root" isn't a real componentClass
  anything below is filterable by.
- **Per-entry raw JSON** — every `.entry` now ends with a collapsed
  `<details><summary>Raw JSON</summary><pre>...</pre></details>` of that
  exact entry's dict, `json.dumps(entry, indent=2)`, escaped through the
  same `_esc()`/`html.escape()` as every other value on the page (so raw
  JSON's own quote characters render as `&quot;` entities, never as
  literal, unescaped HTML). This is the v0.4.0-scoped version of the
  reviewer's "click a component for detail" ask — a full categorized
  Identity/Integrity/Location/Relationships/Security/Provenance drawer
  is a v0.5.0 item (once the `SecurityEvidence` object exists to
  populate the Provenance/Security parts of it with something real,
  rather than an empty placeholder).
- **A top-level Raw BOM section** — the full document, pretty-printed,
  inside one collapsed `<details>`.
- **Dedicated Metadata, External references, Vulnerabilities, and
  Compositions sections** — every native top-level CycloneDX 1.6 array
  this scanner doesn't populate yet gets its own section anyway, with an
  honest, explicit message ("External references are not collected by
  this scanner.") rather than silently omitting the section, or —worse—
  rendering a bare `0` that could look like a verified empty *result*
  (a scanner that checked and found nothing) rather than what it
  actually is (a category this scanner has never collected at all). Same
  reasoning as v0.3.0's "baseline comparison" line (§9).

**Not attempted in v0.4.0** (deferred to the persisted roadmap's later
stages, not silently dropped): a full categorized detail drawer per
component; search that also reaches into Risk observations (scoped to
Components/Services only for this release); highlighting matches inside
the raw-BOM JSON viewer; splitting `report.py` into a `report/` package
(a real refactor, worth doing once the file's size actually demands it,
not preemptively — it is a large single module by v0.4.0, but every
function in it is still independently testable and the module docstring
still accurately describes the whole file's shape).

## 11. Agent Security Graph (v0.5.0)

The persisted roadmap's next stage: capabilities, an attack-surface
classification, and blast radius, all in `security.py` (§9's module),
following the same discipline every function there already had — fixed,
explainable rules, never an opaque score, never a claim this scanner
can't actually back up.

- **`classify_capabilities(entry)`** — one tag: `read` / `write` /
  `execute` / `network` / `credential` / `inference` / `unknown`. Every
  class except `tool` gets a fixed mapping (`_CLASS_CAPABILITY`) — what
  that kind of thing inherently *is* (a `hook` executes, a
  `secrets_surface` is a credential, ...), never a guess at its actual
  runtime behavior. `tool` is the one exception: it already has a more
  specific, per-instance signal (`riskClass`, mcp.py's own name
  heuristic — §2), so its capability is a direct relabeling of that,
  never a second, independent classification that could disagree with
  it.
- **`classify_reachability(entry)`** / **`compute_attack_surface(bom)`**
  — where a component actually sits: `filesystem` / `process` /
  `filesystem+process` (a hook, which is both a script on disk and
  something that executes) / `loopback` / `network` / `credential-store`
  / `model-provider` / `unknown`. Deliberately conservative about
  "network": a non-loopback hostname could be a private LAN address or a
  real internet host, and this scanner has no DNS/routing check to tell
  which — so it's labeled `network`, never `internet-reachable`, a claim
  the string alone can't back up. `compute_attack_surface()` groups every
  entry by this tag and separately flags which ones cross a network
  trust boundary (any `network`-tier entry) — the "TRUST ZONE: LOCAL
  HOST" vs "TRUST ZONE: MODEL SERVICE" distinction an independent
  reviewer asked for, expressed as a real, checkable grouping (a table)
  rather than a second hand-drawn diagram alongside the Architecture
  section's (§9).
- **`build_dependency_children(bom)`** / **`compute_blast_radius(bom,
  bom_ref, children=None)`** — everything reachable from one component by
  following the document's own real `dependencies[]` edges (a plain
  BFS): direct children and the full transitive set. Every result is
  labeled "observed" by construction — these are edges a collector
  actually recorded (`HarnessDocument.add()`/`add_child()`), never a
  guessed or inferred path. There is deliberately no "inferred" tier
  yet: that needs something like skill-content parsing (linking a skill
  to servers/models its own `SKILL.md` prose references — §5, still not
  done), so blast radius is complete only up to what the dependency
  graph itself already contains. `build_dependency_children()` exists
  because `report.py` computes blast radius once per rendered entry
  (potentially hundreds); building the ref→dependsOn adjacency map fresh
  on every single call would make that O(components × edges) instead of
  O(components + edges) — passed in once, reused for every call.

**Rendering (`report.py`).** A new **Attack surface** section (a table
of reachability-tier counts, plus an explicit "N components cross a
network trust boundary" note, or an equally explicit "nothing reaches
beyond loopback or the local filesystem" clean state — never a silent
absence). Every entry in Components/Services now shows a
`capability: ... · reachability: ...` line. A **Blast radius** reveal
(native `<details>`, same offline idiom as the raw-JSON reveal) appears
on any entry with at least one real descendant, listing every reachable
bom-ref and labeled "observed" explicitly; a leaf component (nothing
downstream — most skills, dependencies, secrets surfaces) shows nothing,
the same "don't clutter every entry with an empty section" precedent
`_render_relationships()` already set.

**Deliberately not attempted in v0.5.0** (the persisted roadmap's
remaining v0.5.0 items, kept for a later pass): a common `SecurityEvidence`
object (source/collector/observed_at/confidence/evidence_type/location)
and a per-component Provenance section. Both need per-property
source-tracking that no collector currently records — every collector
would need touching to add it, a genuinely large, cross-cutting change
better done deliberately on its own than folded into this release. Until
then, "observed" (blast radius) versus a real "inferred" tier (v0.6.0's
skill-content analysis) is the only provenance-adjacent distinction this
scanner makes.

## 12. Six defects in v0.4.0/v0.5.0, fixed in v0.5.1

An independent reviewer's follow-up review found one real vulnerability
in the new report JavaScript, three logic errors in v0.5.0's capability/
reachability/blast-radius model, a real file-size regression, and
confirmed the entire v0.3.0 backlog (five items) was still open. All six
verified before fixing, per this project's standing discipline.

**1. High -- JavaScript injection through a crafted componentClass,
confirmed by executing it.** The architecture diagram wrote a
componentClass value into a JS string literal inside an HTML attribute:
`onclick="goToClass('{_esc(target)}')"`. `_esc()` (`html.escape`) is the
wrong escaper for that context -- the browser HTML-decodes the attribute
(`&#x27;` back to a literal `'`) *before* handing its text to the JS
parser, so a componentClass containing a quote broke out of the string
and ran arbitrary script. Reproduced by rendering a hand-crafted document
(not one this scanner's own collectors could ever produce --
`Component.__post_init__` restricts `component_class` to a fixed
vocabulary, but `report` accepts *any* JSON file) with a malicious class
and confirming, in an actual headless-Chrome click, that it executed.
Fixed by removing the nested-grammar problem entirely: architecture
nodes now carry `data-goto="<class>"` (still `_esc()`-escaped, but read
back via `getAttribute()`, which returns the exact decoded string with
no further parsing step) and a single delegated `click` listener in
`_JS`. `goToClass()` itself no longer builds a CSS selector by string
concatenation either (`findGroupForClass()` compares `data-class` values
in a loop instead) -- the same class of mistake, flagged even though the
`<select>`-sourced value reaching it couldn't itself carry a `"` past
the HTML-attribute boundary that produced it.
- Re-verified the fix the same way: the crafted payload, clicked in
  headless Chrome, no longer executes.

**2. Medium -- a `tool`'s reachability ignored its parent MCP server's
transport, in both directions.** `classify_reachability()` used to map a
`read`/`write` tool straight to `filesystem` regardless of where its
server actually runs, and a `network`-tagged tool on a local stdio
server read as `network` -- both backwards, confirmed by reproducing a
remote-HTTPS server's tools reading as `filesystem` and a stdio server's
tools reading as `network`. Capability and reachability are different
axes: capability says *what* a tool does; reachability says *how it's
reached*, which is entirely a property of the MCP server it belongs to.
Fixed: `classify_reachability()` now takes an optional `mcp_servers`
lookup (`index_mcp_servers()`, name -> entry) and a `tool` simply
inherits its parent server's own reachability, looked up by the tool's
own `server` property.

**3. Medium -- `mcp_server`'s capability was a fixed "network" even for
stdio.** `_CLASS_CAPABILITY` mapped every `mcp_server` to `"network"`
unconditionally, contradicting `classify_reachability()`'s already-
correct `"process"` for the very same stdio server on the very same row.
Fixed: `mcp_server` (like `tool`) now consults its own `transport`
property instead of the class-level default.

**4. Medium -- `compute_blast_radius()` traversed the wrong direction
for what its name promises.** The v0.5.0 implementation followed
`dependsOn` *forward* (what a component itself relies on -- its own
supply chain), so every leaf (a skill, a `secrets_surface` file, most
dependencies) reported zero reachable, the least useful possible answer
to "what's affected if this is compromised" -- confirmed by reproducing
exactly that on a poisoned skill and a world-readable credentials file.
Fixed by keeping both, labeled honestly, rather than one function
pretending to answer two different questions: `compute_supply_chain()`
(forward -- what this depends on, the original v0.5.0 behavior, renamed)
and `compute_blast_radius()` (backward -- what depends on this,
transitively, via a new `build_dependency_parents()` inverse adjacency
map). A leaf component's blast radius is (almost) never empty in
practice -- the harness root itself depends on every top-level thing via
`HarnessDocument.add()`, so it's the minimum non-trivial answer, not a
false "nothing" the way the forward traversal gave. `report.py` renders
both per entry ("Depends on" / "Blast radius"), each only when non-empty.

**5. Medium -- the report was roughly 6x the size of the same document's
v0.3.0 report** (measured: 348 KB -> 2.03 MB on a 405-package fixture).
Every entry embedded its own full `json.dumps(entry, indent=2)` copy
*and* the top-level Raw BOM section embedded a second full pretty copy
of the whole document -- for N entries, the document's own data was
present roughly N+1 times. Fixed per the reviewer's own suggested
approach: exactly one compact copy of the whole document
(`json.dumps(bom, separators=(",", ":"))`) is embedded once, in a
`<script type="application/json" id="bom-data">` blob (with `"</":
"<\\/"` replaced first -- `\/` is a valid JSON escape for `/`, so this
changes nothing about the parsed value, but stops a `</script`
substring inside the data, e.g. inside a component name, from being
read by the HTML *parser* as this script tag's own closing tag and
truncating everything after it). Both the per-entry "Raw JSON" reveal
and the top-level "Raw BOM" section now populate their `<pre>` lazily,
client-side, from that one shared blob, the first time their `<details>`
is actually opened (a `toggle` event listener registered with
`capture: true`, since `toggle` doesn't bubble) -- looked up by bom-ref,
with the whole-document view using the sentinel ref `"__bom__"`. Same
"needs JavaScript, no fallback" precedent search/filter already set in
v0.4.0. Verified in headless Chrome by actually dispatching a real
`toggle`/opening a `<details>` element and confirming the populated
`<pre>` parses back as valid JSON.

**6. The full v0.3.0 backlog, confirmed still open and fixed here --
one change (a) closes two items at once:**
- **(a) `classify_secret_confidence()` was dead code**, never called
  from anywhere in `report.py`, and **the `world_readable_secret` rule
  reported every world-readable match at "high" severity regardless of
  confidence tier** -- a `*token*`/`*.sqlite` heuristic match (secrets.py's
  own noisy tier) read exactly the same as an exact `.env`/`*.pem`/`*.key`
  match. Both fixed together: `compute_risk_observations()` now splits
  world-readable secrets by `classify_secret_confidence()` into two
  separate, honestly-labeled observations --
  `world_readable_secret_high_confidence` (severity `high`) and
  `world_readable_secret_heuristic` (severity `medium`, with the summary
  text saying to verify before acting) -- rather than one rule silently
  treating both tiers as equally certain.
- **(b) A rendered risk observation never actually showed `o["rule"]`**,
  even though the section's own intro prose says "each observation names
  the exact rule that fired" -- confirmed by grepping the rendered HTML
  for `world_readable_secret` and finding it nowhere. Fixed:
  `_render_risk_observations()` now renders the rule name (`<code>`)
  alongside the severity badge and summary.
- **(c) `unpinned_dependency` merged two different things under one false
  invariant** -- "a `dependency` component with no version is, by
  construction, an MCP launcher package", true only because a
  `deps.py`-discovered Python package is *usually* read from an
  already-installed dist-info that always names its own version, not
  because it's actually guaranteed (a METADATA file missing its own
  `Version:` header is malformed but real). Fixed with a new `origin`
  property (`"mcp-launcher"` set by `mcp.py`, `"python-package"` set by
  `deps.py`) so the two cases are distinguished by a real, recorded fact
  instead of an inferred absence: `unpinned_mcp_launcher` (a genuine
  "resolves differently every run" risk) and
  `python_package_missing_version` (a data-quality problem, not the same
  finding) are now two separate rules.
- **(d) The `idn-email` defect reproduced exactly**: `Author-email: Jane
  Doe <jane at example dot com>` (a real, deliberately-obfuscated
  non-address some packages use to dodge scrapers) produced a document
  that failed strict CycloneDX 1.6 validation (the schema's
  `contact.email` requires `idn-email` format) while `harness-aibom
  validate` reported it valid regardless -- confirmed with both
  validators directly. Fixed in `deps.py`'s `_split_name_email()`: a
  loose shape check (`_EMAIL_RE`, one `@`, non-empty local part, a domain
  with at least one `.` -- permissive on character set since `idn-email`
  allows non-ASCII, strict only on shape) rejects an obvious non-address
  before it ever reaches `supplierEmail`, and from there CycloneDX's
  native `contact.email` field. The *name* half of the same "Name
  <email>" form is still kept even when the email half is garbled, since
  the two are independent facts -- only the invalid email is dropped, not
  guessed at or silently passed through anyway.

## 13. Agent Supply Chain (v0.6.0), plus one v0.5.1 follow-up fix

The persisted roadmap's next stage: two new componentClasses closing gaps
named since v0.2.0, deterministic skill-content analysis closing the gap
named since v0.2.0's own critique, and populated `externalReferences[]`
for anything with a `purl`. Plus one small fix a reviewer found in the
same pass, in code v0.5.1 had just touched.

**`prompt_surface` (`collectors/prompt_surface.py`, `type: file`).**
Well-known, cross-project instruction filenames (`AGENTS.md`, `CLAUDE.md`)
found anywhere under the harness's own directory. Confirmed generic, not
harness-specific guessing, the same justification `deps.py`'s PEP 376/427
convention already established: `AGENTS.md` is a real, public, cross-tool
convention (agents.md), `CLAUDE.md` is Claude Code's own documented one --
neither is confirmed specifically for Hermes or OpenClaw from this
project's source material, but "if a file with this name exists in the
harness's own tree, record it" is the same "absence is not an error,
presence doesn't over-claim relevance" stance `secrets.py`'s recursive
scan already takes. Fingerprinted (sha256) like a skill or hook -- an
instruction file's content is meant to be read and reasoned about, not
kept private.

**`memory_store` (`collectors/memory_store.py`, `type: data`).**
Well-known, real artifact names/extensions from specific, widely-used
tools: `chroma.sqlite3` (Chroma's own literal default persistence
filename), `*.faiss`/`*.index` (FAISS's own index-file extensions).
Deliberately NOT a broad `*.sqlite`/`*.json` pattern -- far too broad,
and `*.sqlite` specifically already belongs to `secrets.py`'s own
pattern list for the credential-store angle. Metadata only (`path`,
`relPath`, `mode`, `worldReadable`) -- same secrets-never-leak discipline
as `secrets_surface` (§3) and for the same underlying reason: a memory
store can carry conversation history, which can itself contain anything a
user or the agent ever discussed, including credentials. Never
fingerprinted -- unlike `prompt_surface`, this content isn't meant to be
inspected at all, so this module never even opens a matched file to hash
it (hashing would still mean reading the whole file).

A new risk rule, `world_readable_memory_store` (severity `high`), mirrors
the existing `world_readable_secret_*` pair for the same reason a
world-readable `.env` matters.

**Deterministic skill-content analysis (`skills.py`'s
`analyze_skill_content()`).** Closes the gap SPEC.md has named since
v0.2.0 ("this scanner doesn't parse `SKILL.md` content to link a skill
to the servers/models it references"). Deterministic, closed-set
matching only -- never an LLM, never fuzzy inference:
- `referencedServers` -- only a real, *configured* MCP server name found
  in the harness's own config (passed in as `known_server_names`, so a
  skill mentioning an unrelated word never gets reported as "referencing
  a server").
- `urls` -- `https?://` matches, with common prose/markdown trailing
  punctuation (a sentence-ending period, a markdown code-span backtick, a
  closing paren/bracket) stripped afterward rather than excluded from the
  character class outright, so a real mid-URL "." (e.g.
  `api.example.com`) is never truncated.
- `shellIndicators` -- a fixed, closed set of common CLI tool names
  (`curl`, `wget`, `ssh`, `git`, `python`, `pip`, `npm`, `npx`, `docker`,
  `kubectl`), matched as whole words only (`curly` must never match
  `curl`).
- `envVarReferences` -- `$VAR`/`${VAR}`-shaped references.

Every match is recorded as a **text mention**, not a real graph edge --
this is the "inferred" tier the security-analysis layer's blast-radius
work (§11) deliberately left open: a skill's prose *referencing* a
server is evidence its author described some relationship, not
confirmation the skill actually invokes it at runtime (this scanner
reads static files, never traces execution). A future release could
promote a `referencedServers` match into a real, labeled-`inferred` graph
edge (distinct from the "observed" edges `add_child()` already
produces) -- not done here, since that changes what `compute_blast_radius()`
and the Architecture graph (§9) mean, and deserves its own design pass
rather than folding in as a side effect of adding the text-analysis
signal itself.

**Populated `externalReferences[]` (`cyclonedx.py`'s
`_registry_url_for_purl()`).** Any component with a `purl` (currently
only `dependency`, via `mcp.py`/`deps.py`) now also gets a native, real
`externalReferences` entry pointing at that package's actual registry
page -- `pypi.org/project/<name>/`, `npmjs.com/package/<name>` -- the
real, standardized URL shape each registry itself publishes, not a guess
or a network lookup, and deliberately version-agnostic (the registry's
current-release page outlives a version-pinned deep link that may 404
once a package is yanked). `report.py`'s External References section
(previously a permanent empty-state stub, since nothing populated the
*document-level* array it checked) now has its own renderer surfacing
these per-component entries in a table, falling back to the honest
empty-state message only when a document truly has none at either level.

**A real, if lower-severity, injection risk caught while building this,
fixed the same way v0.5.1 fixed the architecture-diagram one.** Since
`report` renders any JSON file, not just ones this scanner produced, a
hand-crafted document's `externalReferences[].url` is untrusted input --
rendering it as a plain `<a href>` after only `_esc()`-escaping would
still let a `javascript:` URI execute on click (HTML-attribute escaping
says nothing about the URL *scheme*). Fixed before it ever shipped:
`_render_external_reference_url()` only renders a clickable link for an
`http://`/`https://` URL; anything else renders as plain escaped text,
never a real link.

**`COLLECTIBLE_CLASSES`/`NOT_YET_COLLECTED` (§9's coverage checklist)
updated**: both new classes moved from "not yet collected" (empty as of
this release) to "collectible" -- AIBOM coverage now reads out of 12
categories this scanner actually looks for, not 10 plus 2 permanently
absent ones.

**Deliberately not attempted in v0.6.0** (the persisted roadmap's
remaining v0.6.0 items, kept for later): promoting a skill's text
references into real, labeled-`inferred` graph edges (needs its own
design pass, noted above); deeper MCP-tool-inventory provenance and a
common `SecurityEvidence` object (still blocked on the same per-property
source-tracking work named as deferred in v0.5.0, §11); vulnerability
integration (no real data source -- `report`'s Vulnerabilities section
stays an honest empty-state stub until one exists).

## 14. Policy gating and baseline diff (v0.7.0), plus two v0.6.0 fixes

An independent reviewer's pass over v0.6.0's two new collectors found two
real defects and named the two highest-priority items still open from the
original persisted roadmap. All four ship together here rather than
splitting the two fixes into a v0.6.1 patch, since the reviewer's own
framing treated the whole set as one piece of work: "the last two items
from the original plan, and the two that most change how the tool reads
in a lab."

**Fix: risk observations were unsorted.** `compute_risk_observations()`
(§9) built its list in rule-definition order, not severity order -- a
`report`'s Risk observations section and a `policy` run's own console
output could both put a `low` finding ahead of a `high` one, purely
because of which rule happened to run first in the source file. Fixed
with a single `_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}` sort
key applied once, at the end of `compute_risk_observations()` itself, so
every consumer (the report, `diff`, the new `policy` command below)
inherits the same order for free rather than each having to re-sort.
Regression test asserts the returned list is actually sorted, not just
that high-severity findings exist.

**Fix: symlink detection was inconsistent across the three file
collectors.** `hook`'s collector already recorded `symlink`/
`pathOutsideHome` (§2); the two new v0.6.0 collectors, `prompt_surface`
and `memory_store`, did not -- an attacker (or a misconfigured agent)
symlinking `AGENTS.md` or a `chroma.sqlite3` path to a file outside
`--home` went undetected by exactly the two collectors added most
recently. Fixed by extracting the shared logic hook's collector had
inlined into a standalone `paths.is_symlink_outside_home(file_path,
home)`, and wiring it into both new collectors the same way. The helper
only calls `.resolve()` when `file_path.is_symlink()` is actually true --
confirmed empirically (`Path(tempfile.mkdtemp())` vs. its own `.resolve()`
differ on macOS, `/var/folders/...` vs. `/private/var/folders/...`) that
unconditionally resolving both sides would produce a false
`pathOutsideHome` on the ordinary non-symlink case whenever a caller
passes an unresolved `home`. Both collectors now set `symlink` on every
matched file and `pathOutsideHome` only when it's actually a symlink
resolving outside `--home`, mirroring `hook`'s own field names and
semantics exactly (§2's taxonomy table rows updated to match).

**`report --baseline <file>` / the Baseline diff section
(`cli.py`, `report.py`).** `diff` (§4) was already this project's
strongest "what changed" output, but it only spoke JSON on a terminal --
there was no way to hand a security reviewer one document that shows both
the current state and what changed since a prior scan. `report` now
accepts an optional second document; when given, `diff_documents()` runs
the same way `diff` itself does (reused directly, not reimplemented, so
the two commands can never disagree about what counts as a change), and
the result renders in a new "Baseline diff" section (Added/Removed/
Changed, with a `fingerprint changed` column) plus updates the Security
summary's previously-permanent "not available for a single scan"
disclaimer with the real counts. With no `--baseline`, both the section
and the disclaimer render exactly as before -- fully backward compatible.
Verified end-to-end, not just at the unit level: a real before/after pair
generated from `tests/fixtures/hermes_home` with a deliberately added
skill and a deliberately modified `AGENTS.md`, rendered through the real
CLI, and inspected both in the raw HTML output and via a headless-Chrome
screenshot, confirming the nav link, the section content, and the
Security summary line all reflect the same real diff.

**`policy` (`cli.py`'s `_run_policy`).** The other of the two named
priority items: a CI-gating command that reuses `compute_risk_observations()`
directly (never a second rule engine) so `policy` and the report's own
Risk observations section can never disagree about what counts as a
finding. `--fail-on {low,medium,high}` (default `medium`) fails the
process (exit 1) if any finding at or above that severity exists.
`--baseline <file>` changes the question from "does anything qualify" to
"did this scan make things worse than the baseline" -- a finding is
counted only if its `(rule, component)` pair doesn't already appear in
the baseline's own risk observations, so a pre-existing, already-accepted
risk doesn't fail CI forever just for continuing to exist. This is a
deliberate, scoped interpretation of the roadmap's original "severity in
diff" phrasing: it stays keyed off security.py's own rule identity rather
than teaching `diff.py`'s component-level diff about severity, so the
two features (`diff`'s structural comparison, `policy`'s risk-rule
comparison) stay independent and neither has to model the other's
concerns. In `--baseline` mode, console output names the specific
new component(s) per finding (`    new: <ref>, <ref>`), not just the
rule's own aggregate summary text -- caught while writing the test for
this, not by a reviewer: printing only the summary would have told a CI
reader a rule fired again without ever saying which component was
actually new.

**Deliberately not attempted in v0.7.0**: report file size returning to
roughly 2MB at high component counts, raised in the same reviewer pass
that named the four items above -- explicitly called "not a defect" by
the reviewer and left out of their own stated priority order, so not
actioned here; still open, tracked in the roadmap memory file for a
future pass focused specifically on report payload size. Also still
deferred, unchanged from §13: promoting a skill's text references into
real `inferred` graph edges; a common `SecurityEvidence`/provenance
object; vulnerability integration (no real data source yet); SARIF/
sidecar-JSON security output, a supply-chain timeline view, compliance
mapping, and cosign signing -- all still-open original-roadmap items
`policy` and `report --baseline` were the two highest-priority picks
from, not full closure of the roadmap.

## 15. AIBOM self-integrity and the Component Inspector (v0.8.0)

An independent reviewer's 33-item wishlist framed this project's next
horizon as "an Agent AIBOM Security Explorer + evidence system", spanning
correctness checks, a richer explorer UI, capability/trust-boundary
analysis, AI-specific provenance, and enterprise supply-chain features
(VEX, SARIF, attestations, signing). Building all 33 at once would mean
shipping unverified stubs -- against this project's whole discipline (every
fix/feature gets a regression test, every JS change gets real-browser
verification, nothing ships without checking it against this actual
codebase first, not a hypothetical one). v0.8.0 instead ships the two
items from that list that are (a) concretely verifiable against this
codebase's real behavior today and (b) don't require a new data-model
concept (confidence tiers, evidence chains, trust zones -- all real,
substantial future work, not attempted here). The full wishlist is
preserved as the persisted roadmap for the stages after this one -- see
`memory/aibom-explorer-roadmap.md`.

**AIBOM self-integrity (`validate.py`).** `validate_document()` already
checked that the envelope is present and every component/service carries
a recognized `componentClass` in the right array; it now also checks the
document's own graph is internally consistent, none of which a generic
CycloneDX schema validator can check (a schema has no idea what a *valid*
bom-ref even is beyond "a string" -- it can't know `dependsOn:
["typo-ref"]` points at nothing):

- **Duplicate bom-ref** -- the same bom-ref used twice (root, a
  `components[]` entry, or a `services[]` entry), reported with every
  location it was found at.
- **Dangling `dependencies[]` edges** -- an entry's own `ref`, or any of
  its `dependsOn` targets, that doesn't match any known bom-ref.
- **Malformed `hashes[]`** -- a `SHA-256` hash entry whose `content` isn't
  actually 64 lowercase hex characters.

All three are errors (fail `validate`, exit 1) -- a document with any of
these would silently mis-render or crash a generic CycloneDX consumer
that trusts `dependsOn` or `hashes[]` to be what they claim. This is
exactly the class of bug this project's own diff-identity fix (v0.2.3)
and blast-radius-direction fix (v0.5.1) were each caught by a *reviewer*
rather than by tooling -- these checks are the ones that would catch a
bug in that same family automatically, on any document, not just this
scanner's own output.

**Orphan detection (`find_orphan_components()`), deliberately separate.**
A component/service `dependencies[]` never actually reaches by walking
from the root is still a fully *valid* CycloneDX document -- schema-valid,
and passes every check above. Most likely a scanner bug (registered but
never `add()`/`add_child()`-ed) or a hand-edit that dropped an edge
without dropping the component it pointed at, but not itself a broken
document. Kept out of `validate_document()`'s error list for exactly that
reason: `cli.py`'s `_run_validate` prints these as warnings on stderr
(`validate` still exits 0), the same "informational, not fatal" treatment
`scan`'s own `doc.warnings` already gets, never a `report --baseline`
either -- confirmed real by running `validate` against both real
examples (`examples/*.example.json`) and finding zero orphans, zero
referential-integrity errors, exactly as the graph's own construction
discipline (`HarnessDocument._register()`, `add()`/`add_child()`)
predicts.

**Component Inspector (`report.py`).** The reviewer's own "single best UI
improvement": every entry (component or service) now has an "Inspect"
button that opens a focused modal -- Identity, capability/reachability,
properties, blast radius, supply chain, relationships, and the Raw JSON
reveal, all in one place, reachable without scrolling through a long
grouped list. Deliberately implemented as *reuse*, not a second render
path: `openInspector()` (`_JS`) clones an already-rendered `.entry`
element's own DOM into the modal body rather than the server building a
second copy of the same content, or the client re-deriving
capability/reachability/blast-radius from scratch in JavaScript (which
would risk the exact "two engines disagree" problem `policy`'s own design
note in section 14 was written to avoid at the Python level -- the same
principle, applied here to the client side). The cloned raw-JSON
`<details>` needs no extra wiring either: the v0.5.1 lazy-render `toggle`
listener is already delegated on `document`, so it fires for a freshly
cloned node the same as an original one.

Two defensive patterns already established elsewhere on this page carried
straight over, deliberately, not reinvented:

- `data-inspect` (read via `getAttribute()`, compared in a loop by
  `findEntryByRef()` -- never built into a CSS selector or a JS string by
  concatenation) is the same delegated-click discipline `data-goto`
  established in v0.5.1, for the same reason: a bom-ref this scanner
  didn't itself generate (`report` accepts any JSON file) could contain a
  character that breaks a hand-built selector. Regression test mirrors
  the v0.5.1 XSS test exactly, with a quote-containing bom-ref in place
  of a quote-containing componentClass.
- The modal's own `hidden` attribute is the real visibility gate, not
  just a CSS class -- `.inspector-overlay { display: none }` as the base
  rule, `:not([hidden])` opts into `display: flex`. Setting `display:
  flex` unconditionally on the class would have silently defeated
  `panel.hidden = true`: an author stylesheet always outranks the
  browser's own `[hidden] { display: none }` UA rule at equal
  specificity, regardless of which selector looks more specific on paper.

Backdrop-click-to-close is an exact `event.target.id === 'inspector-panel'`
check, not `event.target.closest('[data-inspector-close]')` on the
overlay element itself -- `.closest()` walks up through ancestors, so a
`data-inspector-close` attribute on the overlay div would also match
every click *inside* the panel (the panel is the overlay's own
descendant), closing the modal on every interaction with its own content.
Confirmed with real dispatched browser events (headless Chrome, an
`iframe` + the iframe's own `contentWindow.Event`/`KeyboardEvent`
constructors, exactly the harness this project has used for every
JS-touching release since the v0.4.0 lesson -- see the "real bug this
caught" note in `memory/aibom-explorer-roadmap.md`): open via a real
button click, lazy raw-JSON population inside the clone, Escape-to-close
with focus restored to whatever had focus before opening, backdrop-click-
to-close, and -- the actual regression this pattern exists to prevent -- a
click *inside* the panel does NOT close it. "Copy bom-ref" itself
(`copyBomRef()`, `navigator.clipboard.writeText` with an
`execCommand('copy')` fallback for a `file://`-opened report where
`navigator.clipboard` may not exist at all) degrades to a plain "Copy
failed" button label rather than throwing when a browser blocks the
write -- confirmed real that this happens for a *synthetic* (untrusted)
click event specifically, which is expected browser security behavior for
both clipboard APIs, not a defect in this code; a real user click is a
trusted event and isn't subject to that restriction.

**Deliberately not attempted in v0.8.0**: everything else on the
reviewer's 33-item list -- confidence/observation levels per relationship
(OBSERVED/DERIVED/INFERRED/UNKNOWN), evidence chains, attack-path
analysis, blast-radius-as-a-dedicated-view (the data already exists per
v0.5.0/v0.5.1, just not yet its own top-level section), trust zones, a
capability matrix, prompt/memory BOM drift tracking beyond what `report
--baseline` already shows, model digest/provenance depth, VEX,
policy-as-code beyond the `policy` command's fixed rule set, SARIF, a
security scorecard, security assumptions/negative-evidence sections,
reproducibility metadata, CycloneDX 1.7 (this project stays on 1.6 as its
canonical output until 1.7 tooling and tests are ready -- confirmed 1.7
is real and released, per the reviewer, but a canonical-format bump is
its own migration, not a side effect of an unrelated feature),
compositions/formulation/declarations/attestations, and signing. All
staged as future work in `memory/aibom-explorer-roadmap.md`, organized
into the reviewer's own P0-P4 priority tiers, not dropped.

## 16. Ten more items from the same wishlist (v0.8.2)

The user asked for "all features" from the same Sept 2026 reviewer's
33-item wishlist §15 introduced. Attempting all 33 in one pass would still
mean shipping unverified stubs for the items with no real, checkable data
source (dataset/tokenizer provenance, vulnerability/VEX, a rushed
compliance mapping) -- those stay deliberately deferred below, same
reasoning as §15. What follows is everything from the remaining list that
*was* concretely buildable and verifiable against this actual codebase,
shipped together as v0.8.2, each with real end-to-end verification (a real
cosign binary, the real official SARIF 2.1.0 schema, real dispatched
browser events for the one JS change) -- never just "looks reasonable."

**`author` corrected (`pyproject.toml`).** A small, unrelated fix bundled
into this release at the user's request: the PyPI-facing `authors` field
read "Practical DevSecOps" (the course-material publisher this project's
early source material came from, per SPEC.md section 1's own note) rather
than the actual author. Now "Ajay Kumar Yegireddi". Not a security or
data-model change; noted here only because it shipped in the same release.

**SKILL.md YAML frontmatter (`skills.py`, P0 item 4).** A real,
documented, cross-project convention (Claude Code's own Agent Skills
format: `---`-delimited YAML with `name`/`description` as the fields
this scanner cares about, `license`/`allowed-tools` optional) -- the same
"real, confirmed convention, not harness-specific guessing" basis
`prompt_surface.py`'s AGENTS.md/CLAUDE.md filenames already stand on.
A real `description:` field is preferred over the previous first-heading
guess when present (`descriptionSource` records which one actually won);
`comp.name` itself -- the real bom-ref/diff identity -- is never
overwritten by the frontmatter's own declared `name:`, kept as
`frontmatterName` instead, purely informational. Malformed or absent
frontmatter never crashes the scan (`{}` and falls back to the heading
guess), same "record what's there, don't crash over one bad file"
discipline this module already applies to an unreadable SKILL.md.

**`scan --verify-deterministic` (P0 item 5).** Runs each active collector
*twice* and compares the two `--deterministic` documents structurally --
a real reproducibility check, not an assumption resting only on
`--deterministic` omitting `serialNumber`/`metadata.timestamp`. PASS/FAIL
per runtime, exit 1 on any FAIL. Confirmed real against the Hermes
fixture (PASS); the negative case is proven with a deliberately flaky
fake collector in the test suite, not just asserted that the happy path
prints PASS.

**`diff --security` / `security.diff_risk_observations()` (P2 item 18,
partial).** `policy --baseline`'s own ad hoc "new since baseline" set
comparison, pulled out into a shared `security.py` function -- new/
persisting/resolved buckets, keyed on `(rule, bom-ref)`. `policy
--baseline` now calls this same function instead of duplicating the
logic inline, so the two can never disagree. `diff --security` renders
the same buckets as JSON, with `--exit-code` gating on `new` only.
Deliberately NOT folded into `diff`'s default output -- the two questions
("did the inventory change" vs. "did a named risk rule newly fire") have
different consumers and different shapes.

**Trust zones (`report.py`, P2 item 13).** The same `compute_attack_surface()`
reachability data the Attack surface table already shows (§11),
regrouped into two zones -- everything in the `network` tier vs.
everything else -- rather than a flat per-tier count list. No new facts,
no second classification: this is `classify_reachability()`'s own result,
read differently.

**Capability matrix (`report.py`, P2 item 12).** `classify_capabilities()`/
`classify_reachability()` (§11), aggregated by `(componentClass,
capability, reachability)` into one table instead of read only from each
entry's own detail line -- the same componentClass-level aggregation the
Architecture diagram (§9) already applies, for the same reason (a
document with dozens of skills repeating "skill / read / filesystem"
dozens of times adds no information). Deliberately NOT a set of
independent read/write/execute/network/credential/model boolean flags
per asset, the shape the reviewer's own mockup showed --
`classify_capabilities()` assigns exactly ONE fixed capability tag per
componentClass, never several at once; a multi-checkmark row would show
data this scanner doesn't actually have.

**Model digest drift callout (`report.py`, P3 item 21, partial).** The
Baseline diff's Changed table already listed `harness-aibom:digest`
among a `model` component's changed field *names*; `diff.py`'s own
`fields[name] = {"before": ..., "after": ...}` shape already carried the
actual before/after values, just unused until now. A distinct, status-
critical-colored callout now surfaces them explicitly for exactly this
case -- a model's own tag/name staying fixed while what it resolves to
changes underneath it, the "tag same, digest different" supply-chain
signal a reviewer specifically asked for. Model-specific, not
generalized to every fingerprinted class: a model tag is a pointer that
can move; a skill's sha256 changing means the skill's own content
changed, a materially different kind of surprise.

**Raw BOM search/highlight (`report.py`, P1 item 9, partial).** A search
box above the Raw BOM's own `<pre>`, highlighting matches once it's open
-- scoped deliberately to that one block (the one place a reader
plausibly needs to text-search a large, multi-hundred-line document),
not every per-entry Raw JSON reveal (already scoped to one component).
**A real missing-`addEventListener`-wiring bug was caught here during
development** -- `highlightRawBom()` was written and worked when called
manually, but its `input` listener was never actually attached to the
search box, so typing did nothing. Every Python-level static-HTML
assertion would have passed regardless (the function text and the input
element both exist in the markup); only real dispatched browser events
(headless Chrome, `iframe` + `contentWindow.Event`) caught it, exactly
the failure mode SPEC.md has warned about since v0.4.0's own postmortem
(`memory/aibom-explorer-roadmap.md`). Fixed before shipping; the fix
itself (one `addEventListener` call) is now covered by that same
real-browser check.

**Policy-as-code (`policy_yaml.py`, P4 item 26).** `policy --policy-file
rules.yaml` -- user-authored rules, evaluated alongside (never instead
of) the built-in security.py rules. Deliberately a narrow, closed-set
condition language: an optional `componentClass` plus equality checks
against named `harness-aibom:` properties, ANDed together -- no OR, no
negation, no comparison operator beyond equality. A rule that needs more
than that is exactly the kind of opaque condition this project's whole
risk-observation design has always avoided. Each rule's own `action`
(`fail`/`warn`) decides whether it fails the command, independent of
`--fail-on`/`--baseline` (which apply only to the built-in rules' gate) --
printed in its own labeled block so the two rule systems' different
gating logic is never conflated. Malformed policy YAML (not a mapping,
an unknown severity/action, a missing condition) raises a specific,
actionable `PolicyFileError` at load time, never a raw traceback
mid-evaluation. Not yet supported together with `--format sarif` (an
explicit, checked error, not a silent gap) -- combining the two shapes
is real future work, not attempted here.

**SARIF output (`sarif.py`, P4 item 27).** `policy --format sarif
[--output results.sarif]` -- the same `compute_risk_observations()`
findings `policy`'s text mode and the report's own Risk observations
section already show, rendered as a SARIF 2.1.0 log for a GitHub/GitLab/
Azure code-scanning UI. Severity maps onto SARIF's own `level` enum
(high->error, medium->warning, low->note). A finding on a component with
a real `relPath`/`path` gets a genuine `physicalLocation` (what a
scanning UI actually annotates inline); anything else (a service with no
filesystem location, e.g. an MCP server) gets a `logicalLocation` naming
its bom-ref instead -- never a fabricated path. **Every SARIF document
this module can produce is validated against the real, official SARIF
2.1.0 JSON Schema** (vendored at `tests/fixtures/sarif-schema-2.1.0.json`,
fetched once from schemastore.org's mirror of the canonical
oasis-tcs/sarif-spec schema), the same "validate against the real spec,
not just what looks reasonable" discipline `test_cyclonedx_schema.py`
already applies to this project's own canonical output -- `jsonschema`
added as an explicit dev dependency for this, not left as an incidental
transitive one.

**AIBOM signing (`sign.py`, `cli.py`'s `sign`/`verify-signature`, plus
`report --bundle/--key`, P4 item 30).** Key-based `cosign sign-blob`/
`verify-blob`, fully offline (`--insecure-ignore-tlog=true` on verify, no
transparency-log upload on sign) -- deliberate, not a shortcut: key-based
signing has no public OIDC identity for a transparency log to attest to
in the first place, so the trust model here is "you already trust this
specific public key", the same as a GPG-signed release artifact.
Thin subprocess wrapper only -- this module never re-implements signature
verification itself (a hand-rolled verifier would be a real cryptographic
mistake to get subtly wrong); cosign's own exit code and stdout/stderr
are relayed verbatim, at both the standalone command level and inside the
report's new Artifact integrity section (`report --bundle x.bundle --key
cosign.pub` runs a real `verify-blob` against the exact input file at
render time, embedding the SHA-256 of that file, cosign's own verified/
not-verified verdict, and its raw output -- never a bare, ambiguous
checkmark this scanner can't back up).

**Confirmed against a real, locally installed `cosign v3.1.3`**, not
assumed: `sign-blob`/`verify-blob` both require `--bundle <path>` on
this version -- the older `--output-signature`/`--signature` flags are
deprecated, and combining them with this version's bundle-format default
raises "must specify --bundle with --new-bundle-format" outright,
confirmed by actually running it before settling on the shape this
module uses. Only this exact command shape was verified locally; an
older cosign install may use a different flag shape, and this module
doesn't try to detect or paper over that. `test_sign.py`/the `sign`/
`verify-signature`/`report --bundle` tests in `test_cli.py` are real,
non-mocked subprocess calls against the actual binary -- skipped
entirely (never faked) when `cosign` isn't on PATH, which is why CI now
installs it explicitly (`sigstore/cosign-installer`, `.github/workflows/ci.yml`)
so this suite runs for real there too, not just locally.

**Deliberately not attempted in v0.8.2** (the remaining items from the
same 33-item wishlist, still staged in `memory/aibom-explorer-roadmap.md`):
confidence/observation levels (OBSERVED/DERIVED/INFERRED/UNKNOWN) as a
real per-relationship data-model field -- too invasive to retrofit safely
across every collector call site in one pass, unlike the narrow, already-
justified "text mention" framing `skills.py`'s own `referencedServers`
already carries; evidence chains and attack-path analysis (both need
that same deferred confidence tagging to mean anything); a full
interactive per-instance dependency graph explorer (the per-entry
"Depends on"/"Blast radius" lists already show this data; a real
pan/zoom instance-level graph for a document with hundreds of components
is its own design-and-scalability pass, not a tacked-on addition to an
already large release); tokenizer/prompt-template metadata and dataset/
model provenance depth (no live Ollama instance available in this
environment to confirm `/api/show`'s actual field shapes against --
verified-against-a-live-box is this project's own standing bar, not
skipped lightly); vulnerability/VEX (still no real data source); CycloneDX
declarations/attestations proper (needs a real assessor-identity model,
its own design pass, same reasoning v0.5.0 deferred a `SecurityEvidence`
object for); compliance mapping (NIST AI RMF/ISO 42001/OWASP Agentic AI/
MITRE ATLAS/SLSA -- authoring a real, defensible control-to-evidence
mapping needs careful, dedicated domain work this project's "never
overclaim" discipline shouldn't rush); CycloneDX 1.7 (still a deliberate,
separate migration decision, not a side effect of this release, per §15).
