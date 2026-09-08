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
untyped "depends-on" edges, referencing bom-refs from either array — every
component or service the harness touches is listed under `dependsOn` for
the root. The *verb* (`uses`, `loads`, `invokes`, `executes`, `accesses`,
`approves`, `pulls`) is layered on top as repeated
`harness-aibom:relationship` properties (`"<verb>:<bom-ref>"`) on the
source entry (the harness root, for top-level relationships). Nothing
exotic — still valid CycloneDX, just extra properties. This does mean the
dependency graph itself is flat (root depends on everything directly,
rather than e.g. `runtime` depending on `model_endpoint` depending on
`model`) — a deliberate v1 trade-off, not an oversight; see §5.

## 2. Component taxonomy (v1)

**Components** (`bom.components[]`, each with a CycloneDX `type`):

| `componentClass` | CDX `type` | Key properties | Source |
|---|---|---|---|
| `runtime` | `application` | `version`, `installDir`, `installMethod`, `upstreamHash`, `pythonVersion`, `sdkVersion` | `hermes --version` / `openclaw --version` |
| `model` | `machine-learning-model` (native CDX ML-BOM type) | `digest`, `sizeBytes`, `modifiedAt`, `family`, `parameterSize`, `quantizationLevel`, `contextLength`, `thinking`, `ollamaNumCtx` | Ollama `GET /api/tags`, cross-referenced against the configured default model |
| `configuration` | `file` | `path`, `sha256` | `~/.hermes/config.yaml`, `~/.openclaw/openclaw.json` |
| `skill` | `library` | `path`, `category` (if nested), `sha256` (of the whole skill directory), `description` | `~/.hermes/skills/<category>/<name>/SKILL.md`, any depth |
| `hook` | `file` | `approvalStatus`, `approvedAt`, `rawLine` | `hermes hooks doctor` (best-effort text parse, see §5) |
| `secrets_surface` | `data` | `path`, `mode`, `worldReadable`, `note` | recursive filesystem scan for `.env`, `*credentials*`, `*token*`, `*.pem`, `*.key`, `*.sqlite` under the harness's own directory, skill directories included; `name` is the path relative to the scanned root (not just the basename), so two `.env` files in different directories read as two distinct entries |

**Services** (`bom.services[]`, no `type` field — see §1):

| `componentClass` | Key properties | Source |
|---|---|---|
| `model_endpoint` | `provider`, `apiMode`, `endpoints[]` (native CDX field) | `config.yaml` / `openclaw.json` |
| `mcp_server` | `endpoint`, `endpoints[]` (native CDX field), `tls` (bool), `authConfigured` (bool), `toolCount` | `mcp_servers` list inside either config file |

`model` deliberately uses CycloneDX's native `machine-learning-model` type
rather than a generic one — it's a real ML-BOM component, not just a file.

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

Both `sha256_directory` and secrets-surface discovery tolerate permission
errors rather than crashing the scan: a subdirectory that can't be listed
(root-owned skills, scanned as a non-root user — a realistic lab condition)
is skipped, not fatal, and a file that's found but can't be opened still
has its path folded into the skill's hash, just not its content.

## 4. Diffing

`harness-aibom diff before.json after.json` indexes both documents by
`(componentClass, identity)`, where `identity` is the entry's
`harness-aibom:path` property when it has one, falling back to `name`
otherwise (`model`, `runtime`, and the two service classes don't carry a
path). It reports `added` / `removed` / `changed` keys. A change to
`harness-aibom:sha256` or `harness-aibom:digest` is flagged with
`fingerprint_changed: true` — this is the mechanism for catching a
poisoned skill or a swapped model between two scans of the same harness.

Keying on `name` alone was wrong, and shipped that way in v0.1.0 through
v0.1.3: `name` isn't unique once the secrets scan recurses into skill
directories (§3) — two different `.env` files can both be named `.env`,
collide under one dict key, and the second one scanned silently
overwrites the first, hiding a real change to whichever file lost that
collision. Confirmed and fixed in v0.1.4. Deliberately not keyed on
`bom-ref` either: its numeric `-2` disambiguation suffix (model.py's
`HarnessDocument.add()`) is insertion-order-dependent, so adding one new
component earlier in a later scan can shift every following bom-ref and
make untouched files look renamed.

`hook` components still have this exposure and aren't yet fixed: the
current `hermes hooks doctor` text-parsing (§5) only extracts a script
*name*, not a full path, so there's no `path` property to key on if two
hook scripts share a basename in different directories. Fixing this needs
a real path in the hook data itself, which isn't available yet.

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

- **`openclaw --version` isn't parsed into a semantic version** — its exact
  output format wasn't in the source material, so the collector records the
  first line verbatim. Not yet checked against a live OpenClaw box.
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
- **The dependency graph is flat by design** (§1) — every component and
  service hangs directly off the harness root, rather than e.g. `runtime`
  depending on `model_endpoint` depending on `model`. A general SBOM tool
  sees relationship *existence* but not relationship *shape*; the verbs are
  only in `harness-aibom:relationship` properties. Modeling a real topology
  per componentClass is a bigger change than this release's scope covers,
  deliberately deferred rather than attempted piecemeal.
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
