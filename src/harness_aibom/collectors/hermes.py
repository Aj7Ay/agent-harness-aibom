"""Collector for the Hermes agent harness.

Grounded in ~/pdso/Course/caasp material, not guessed:
  - `hermes --version` -> "Hermes Agent v0.19.0 (2026.7.20) [middot] upstream 6bd02ae1"
    plus "Install directory:", "Install method:", "Python:", "OpenAI SDK:" lines
    (endpoint-detection-for-hermes-agent/step1.md).
  - `~/.hermes/config.yaml` -> model.{default,provider,base_url,api_mode,
    thinking,context_length,ollama_num_ctx}.
  - `~/.hermes/skills/<category>/<name>/SKILL.md` -> one skill per
    directory containing a SKILL.md, at any depth (confirmed on a live box:
    skills are grouped into category folders such as `creative/`,
    `devops/`, `productivity/`, one level above the actual skill
    directories -- see collectors/skills.py).
  - `hermes hooks doctor` -> one allowlist line per hook, "[check] allowlisted
    (approved <date>)" / "[x] not allowlisted" (simple-lab-2-hermes-numbat.md).
  - MCP servers: audited from a `hermes.yaml`-shaped mcp_servers list in the
    CAASP MCP lab. Real Hermes versions may or may not nest this inside
    config.yaml itself, so this collector reads it from whatever config dict
    it already loaded (see collectors/mcp.py) -- absent is not an error.

Hook line parsing is intentionally best-effort text scraping, not a
confirmed stable format -- flagged via doc.warn() so it's visible in scan
output, and worth hardening against a live box once one is reachable.
"""

from __future__ import annotations

import re
import stat
import subprocess
from pathlib import Path
from typing import Callable

import yaml

from ..fingerprint import sha256_file
from ..model import Component, HarnessDocument
from ..paths import relative_to_or_none
from . import mcp as mcp_mod
from . import ollama as ollama_mod
from . import secrets as secrets_mod
from . import skills as skills_mod
from .base import Collector

RunFn = Callable[[list[str]], str]


def default_run(argv: list[str]) -> str:
    # stdin=DEVNULL: if the real binary ever falls through to an
    # interactive prompt instead of the flag we asked for, it gets an
    # immediate EOF instead of hanging until `timeout` kills the scan.
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=10, check=False, stdin=subprocess.DEVNULL
    ).stdout


class HermesCollector(Collector):
    runtime_kind = "hermes"

    def __init__(
        self,
        home: Path | None = None,
        run: RunFn = default_run,
        fetch: ollama_mod.FetchFn = ollama_mod.default_fetch,
    ):
        super().__init__(home)
        self.run = run
        self.fetch = fetch

    @property
    def hermes_dir(self) -> Path:
        return self.home / ".hermes"

    @property
    def config_path(self) -> Path:
        return self.hermes_dir / "config.yaml"

    def is_present(self) -> bool:
        return self.hermes_dir.is_dir() or self.config_path.is_file()

    def collect(self, doc: HarnessDocument) -> None:
        self._collect_runtime(doc)
        config, config_comp = self._collect_config(doc)
        if config_comp is not None:
            self._collect_model(doc, config, config_comp)
            self._collect_mcp_servers(doc, config, config_comp)
        self._collect_skills(doc)
        self._collect_hooks(doc)
        for comp in secrets_mod.find_secrets_surface(self.hermes_dir, self.home):
            doc.add(comp, "accesses")

    def _collect_mcp_servers(self, doc: HarnessDocument, config: dict, config_comp: Component) -> None:
        # A real dependency-graph edge, not another root edge: the config
        # file is what *declares* each server, and each server in turn
        # declares its own tools -- confirmed real gap: every relationship
        # used to be a root edge, making the graph a flat star with no
        # structure ("harness-root depends on all 15") a generic SBOM tool
        # could actually use for impact analysis.
        for server, tools in mcp_mod.extract_mcp_servers(config):
            doc.add_child(server, config_comp, "uses")
            for tool in tools:
                doc.add_child(tool, server, "uses")

    def _collect_runtime(self, doc: HarnessDocument) -> None:
        try:
            output = self.run(["hermes", "--version"])
        except FileNotFoundError:
            doc.warn("hermes binary not found on PATH; runtime component skipped")
            return
        except subprocess.TimeoutExpired:
            doc.warn(
                "`hermes --version` did not finish within the timeout; runtime component skipped "
                "(the binary IS on PATH -- this is a hang or a slow response, not a missing install)"
            )
            return
        except (OSError, subprocess.SubprocessError) as exc:
            doc.warn(f"`hermes --version` failed ({exc.__class__.__name__}: {exc}); runtime component skipped")
            return
        if not output.strip():
            doc.warn("`hermes --version` produced no output; runtime component skipped")
            return

        comp = Component(component_class="runtime", name="hermes")
        first_line = output.splitlines()[0]
        if m := re.search(r"v?(\d+\.\d+\.\d+)", first_line):
            comp.version = m.group(1)
        if m := re.search(r"upstream ([0-9a-f]{7,40})", first_line):
            comp.set("upstreamHash", m.group(1))

        field_map = {
            "install directory": "installDir",
            "install method": "installMethod",
            "python": "pythonVersion",
            "openai sdk": "sdkVersion",
        }
        for line in output.splitlines()[1:]:
            key, _, value = line.partition(":")
            if (prop := field_map.get(key.strip().lower())) is not None:
                comp.set(prop, value.strip())

        doc.add(comp, "uses")

    def _collect_config(self, doc: HarnessDocument) -> tuple[dict, Component | None]:
        if not self.config_path.is_file():
            doc.warn(f"{self.config_path} not found; model/configuration components skipped")
            return {}, None
        try:
            config = yaml.safe_load(self.config_path.read_text()) or {}
        except yaml.YAMLError as exc:
            doc.warn(f"could not parse {self.config_path}: {exc}")
            return {}, None

        comp = Component(component_class="configuration", name="config.yaml")
        comp.set("path", str(self.config_path))
        comp.set("relPath", relative_to_or_none(self.config_path, self.home))
        comp.set("sha256", sha256_file(self.config_path))
        doc.add(comp, "loads")
        return config, comp

    def _collect_model(self, doc: HarnessDocument, config: dict, config_comp: Component) -> None:
        model_cfg = config.get("model") or {}
        base_url = model_cfg.get("base_url")
        if not base_url:
            return

        endpoint = Component(component_class="model_endpoint", name=base_url)
        endpoint.set("provider", model_cfg.get("provider"))
        endpoint.set("apiMode", model_cfg.get("api_mode"))
        # child of configuration, not the harness root: the config file is
        # what declares this endpoint.
        doc.add_child(endpoint, config_comp, "uses")

        default_name = model_cfg.get("default")
        models = ollama_mod.discover_models(base_url, self.fetch)
        matched = False
        for m in models:
            if default_name and m.name == default_name:
                m.set("contextLength", model_cfg.get("context_length"))
                m.set("thinking", model_cfg.get("thinking"))
                m.set("ollamaNumCtx", model_cfg.get("ollama_num_ctx"))
                matched = True
            # child of the endpoint that serves it, not the harness root.
            doc.add_child(m, endpoint, "uses")

        if default_name and not matched:
            # Ollama unreachable, or the configured model hasn't been pulled
            # yet -- still record what the harness is *configured* to use.
            comp = Component(component_class="model", name=default_name)
            comp.version = default_name
            comp.set("contextLength", model_cfg.get("context_length"))
            comp.set("thinking", model_cfg.get("thinking"))
            comp.set("ollamaNumCtx", model_cfg.get("ollama_num_ctx"))
            doc.add_child(comp, endpoint, "uses")
            doc.warn(f"configured model {default_name!r} not found via Ollama /api/tags; recorded from config only")

    def _collect_skills(self, doc: HarnessDocument) -> None:
        for comp in skills_mod.discover_skills(self.hermes_dir / "skills", self.home):
            doc.add(comp, "loads")

    def _collect_hooks(self, doc: HarnessDocument) -> None:
        try:
            output = self.run(["hermes", "hooks", "doctor"])
        except (OSError, subprocess.SubprocessError):
            return
        if not output.strip():
            return

        # A box with no hooks registered says so plainly (confirmed on a
        # live box: "No shell hooks configured — nothing to check.") --
        # that's a clean, correct answer, not a parsing failure, so it gets
        # no warning at all.
        found_any = False
        marker_line_seen = False
        current: Component | None = None
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            has_marker = line.startswith("✓") or line.startswith("✗")
            name_match = re.search(r"([\w./-]+\.(?:sh|py))", line)
            if has_marker:
                marker_line_seen = True

            # A line carrying *both* a marker and a script name is always
            # a new hook entry, even if it also happens to mention "since
            # approval" in the same breath (e.g. "✓ pre-commit.sh
            # allowlisted (unchanged since approval)") -- confirmed a real
            # regression here: an earlier version treated ANY "since
            # approval" text as a status continuation unconditionally,
            # which swallowed lines shaped like that whole and silently
            # dropped every hook. A status-continuation line, by contrast,
            # is a line that mentions "since approval" but is NOT itself a
            # marker+name hook entry -- that's the actual discriminator,
            # not any one guess at whether such a line has a marker or
            # repeats the name (neither is confirmed for a real box).
            if "since approval" in line.lower() and not (has_marker and name_match):
                if current is not None:
                    current.set("contentChangedSinceApproval", "unchanged" not in line.lower())
                continue

            if not name_match or not has_marker:
                continue

            if not found_any:
                # Only warn once we know there's actually hook data to be
                # uncertain about -- this line format is confirmed from
                # course material, but per-hook script-name extraction
                # inside it is not yet checked against a live box that has
                # hooks configured.
                doc.warn(
                    "hook parsing from `hermes hooks doctor` text output is best-effort; "
                    "verify field extraction against a live box with hooks configured"
                )
                found_any = True

            approved = line.startswith("✓")
            comp = Component(component_class="hook", name=name_match.group(1))
            comp.set("approvalStatus", "allowlisted" if approved else "not_allowlisted")
            if date_match := re.search(r"approved ([0-9-]+)", line):
                comp.set("approvedAt", date_match.group(1))
            comp.set("rawLine", line)
            if "since approval" in line.lower():
                # A combined line (marker + name + status all in one)
                # carries its own content-changed signal too.
                comp.set("contentChangedSinceApproval", "unchanged" not in line.lower())
            self._attach_script_fingerprint(comp, name_match.group(1))
            doc.add(comp, "approves" if approved else "executes")
            current = comp

        if marker_line_seen and not found_any:
            # Output had ✓/✗ lines, but none of them turned into a hook
            # component -- this parser's assumptions don't match this
            # box's actual format. Silently reporting zero hooks would be
            # indistinguishable from "this box genuinely has none", which
            # is the worst failure mode a scanner has.
            doc.warn(
                "`hermes hooks doctor` output contained ✓/✗ lines but no hook components could be "
                "extracted from them -- this parser may not understand this box's format; do not "
                "treat this scan as evidence the box has no hooks"
            )

    def _attach_script_fingerprint(self, comp: Component, captured_name: str) -> None:
        """Opportunistic, not authoritative: `hermes hooks doctor`'s text
        output doesn't confirm where hook scripts actually live on disk
        (unlike skills, which have a documented `~/.hermes/skills/` home),
        so this just tries a couple of plausible locations for whatever
        name/path the doctor output printed, and sets nothing if none of
        them exist. See SPEC.md §5 -- do not treat a missing `sha256` as
        "no hook exists here", only as "this collector couldn't find the
        file at a location it guessed."

        Deliberately named `path`/`relPath`/`sha256` -- the same
        properties `configuration` and `skill` use, not `scriptPath`/
        `scriptSha256` -- so `diff.py` picks a hook's script up as its
        identity (§4) and flags a changed one as `fingerprint_changed`
        for free, with no hook-specific logic in diff.py at all. A
        `scriptXxx`-prefixed name would silently miss both.

        Confirmed real vulnerability, fixed here: a relative
        `captured_name` is never resolved against the process's current
        working directory. It used to be -- `Path("pre-commit.sh")` was
        tried as-is first -- so an unrelated file merely sitting in
        whatever directory `harness-aibom scan` happened to be run from
        could get hashed and reported as *the hook's own fingerprint*,
        wrong `path`/no `relPath` included, worse than reporting no
        fingerprint at all for a tool whose whole purpose is integrity.
        A relative name is only ever tried joined onto a known root
        (`hermes_dir/"hooks"`, `home`) -- never bare.

        `symlink` records whether the guessed location was itself a
        symlink; `path` already carries the *resolved* target (no
        separate `symlinkTarget` -- that would just repeat `path`).
        `pathOutsideHome` is set whenever the resolved target lands
        outside `--home`, symlink or not -- an allowlisted hook that
        looks like it lives inside the harness but actually points
        somewhere else entirely is exactly the case this exists to catch.
        """
        name_path = Path(captured_name)
        candidates = (
            [name_path]
            if name_path.is_absolute()
            else [self.hermes_dir / "hooks" / captured_name, self.home / captured_name]
        )

        for candidate in candidates:
            is_symlink = candidate.is_symlink()
            candidate = candidate.resolve()
            if not candidate.is_file():
                continue
            comp.set("path", str(candidate))
            comp.set("symlink", is_symlink)
            rel_path = relative_to_or_none(candidate, self.home)
            comp.set("relPath", rel_path)
            if rel_path is None:
                # A hook script living entirely outside --home is itself
                # worth flagging, not just silently missing a relPath.
                # Driven off the *resolved* candidate, not off whether
                # the captured name itself was absolute: a relative name
                # under a known root can still be a symlink that resolves
                # somewhere else entirely (~/.hermes/hooks/audit.sh ->
                # /tmp/evil/payload.sh) -- confirmed the previous
                # is_absolute()-gated version missed exactly that case,
                # the one this flag exists to catch.
                comp.set("pathOutsideHome", True)
            comp.set("sha256", sha256_file(candidate))
            try:
                comp.set("mode", oct(stat.S_IMODE(candidate.stat().st_mode)))
            except OSError:
                pass
            return
