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

## 1. Format: CycloneDX 1.6, extended

The root `bom.metadata.component` describes the harness itself
(`type: application`, name `<runtime>@<hostname>`). Every discovered thing
becomes a CycloneDX `component`, mapped to the closest native `type` (§2).
Fields CycloneDX has no slot for go in that component's `properties[]`
under a `harness-aibom:` namespace (e.g. `harness-aibom:componentClass`,
`harness-aibom:sha256`). A CycloneDX-aware tool that ignores unknown
property names still gets a valid, useful BOM; `harness-aibom`'s own
`diff`/`validate` commands are the only consumers that need to understand
them.

**Relationships.** CycloneDX's native `dependencies[]` only expresses
untyped "depends-on" edges — every component the harness touches is listed
under `dependsOn` for the root. The *verb* (`uses`, `loads`, `invokes`,
`executes`, `accesses`, `approves`, `pulls`) is layered on top as repeated
`harness-aibom:relationship` properties (`"<verb>:<bom-ref>"`) on the
source component (the harness root, for top-level relationships). Nothing
exotic — still valid CycloneDX, just extra properties.

## 2. Component taxonomy (v1)

| `componentClass` | CDX `type` | Key properties | Source |
|---|---|---|---|
| `runtime` | `application` | `version`, `installDir`, `installMethod`, `upstreamHash`, `pythonVersion`, `sdkVersion` | `hermes --version` / `openclaw --version` |
| `model_endpoint` | `service` | `provider`, `apiMode` | `config.yaml` / `openclaw.json` |
| `model` | `machine-learning-model` (native CDX ML-BOM type) | `digest`, `sizeBytes`, `modifiedAt`, `family`, `parameterSize`, `quantizationLevel`, `contextLength`, `thinking`, `ollamaNumCtx` | Ollama `GET /api/tags`, cross-referenced against the configured default model |
| `configuration` | `file` | `path`, `sha256` | `~/.hermes/config.yaml`, `~/.openclaw/openclaw.json` |
| `skill` | `library` | `path`, `category` (if nested), `sha256` (of the whole skill directory), `description` | `~/.hermes/skills/<category>/<name>/SKILL.md`, any depth |
| `mcp_server` | `service` | `endpoint`, `tls` (bool), `authConfigured` (bool), `toolCount` | `mcp_servers` list inside either config file |
| `hook` | `file` | `approvalStatus`, `approvedAt`, `rawLine` | `hermes hooks doctor` (best-effort text parse, see §5) |
| `secrets_surface` | `data` | `path`, `mode`, `worldReadable`, `note` | filesystem scan for `.env`, `*credentials*`, `*token*`, `*.pem`, `*.key`, `*.sqlite` near the harness's own config dir |

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
contents, never a hash derived from contents.

## 4. Diffing

`harness-aibom diff before.json after.json` indexes both documents by
`(componentClass, name)` and reports `added` / `removed` / `changed`
component keys. A change to `harness-aibom:sha256` or
`harness-aibom:digest` is flagged with `fingerprint_changed: true` — this
is the mechanism for catching a poisoned skill or a swapped model between
two scans of the same harness.

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

**Still open:**

- **`openclaw --version` isn't parsed into a semantic version** — its exact
  output format wasn't in the source material, so the collector records the
  first line verbatim. Not yet checked against a live OpenClaw box.
- **No remote/SSH scanning.** `harness-aibom scan` reads the filesystem and
  runs subprocesses on whatever machine it's invoked on. Scanning a remote
  lab VM means installing the package there (or SSHing in) — there's no
  built-in remote transport in v0.1.
- **No JSON Schema file.** `validate` is hand-rolled structural checking
  (envelope + componentClass/type consistency), not a full CycloneDX 1.6
  schema validator — reproducing that schema exactly would be its own
  maintenance burden and is better left to a dedicated CycloneDX validator
  run alongside this tool.
- **Skill/secrets-surface bom-refs can collide by name** (e.g. two `.env`
  files in different directories). `HarnessDocument.add()` disambiguates
  with a numeric suffix so the document stays valid, but the disambiguation
  is order-dependent, not content-addressed.

## 6. Explicitly out of scope for this spec

Cisco AI BOM comparison, cosign signing/provenance, and the full course lab
sequence are downstream work built *on* this package, not part of it.
