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
import subprocess
from pathlib import Path
from typing import Callable

import yaml

from ..fingerprint import sha256_file
from ..model import Component, HarnessDocument
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
        config = self._collect_config(doc)
        self._collect_model(doc, config)
        self._collect_skills(doc)
        self._collect_hooks(doc)
        for comp in mcp_mod.extract_mcp_servers(config):
            doc.add(comp, "uses")
        for comp in secrets_mod.find_secrets_surface(self.hermes_dir):
            doc.add(comp, "accesses")

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

    def _collect_config(self, doc: HarnessDocument) -> dict:
        if not self.config_path.is_file():
            doc.warn(f"{self.config_path} not found; model/configuration components skipped")
            return {}
        try:
            config = yaml.safe_load(self.config_path.read_text()) or {}
        except yaml.YAMLError as exc:
            doc.warn(f"could not parse {self.config_path}: {exc}")
            return {}

        comp = Component(component_class="configuration", name="config.yaml")
        comp.set("path", str(self.config_path))
        comp.set("sha256", sha256_file(self.config_path))
        doc.add(comp, "loads")
        return config

    def _collect_model(self, doc: HarnessDocument, config: dict) -> None:
        model_cfg = config.get("model") or {}
        base_url = model_cfg.get("base_url")
        if not base_url:
            return

        endpoint = Component(component_class="model_endpoint", name=base_url)
        endpoint.set("provider", model_cfg.get("provider"))
        endpoint.set("apiMode", model_cfg.get("api_mode"))
        doc.add(endpoint, "uses")

        default_name = model_cfg.get("default")
        models = ollama_mod.discover_models(base_url, self.fetch)
        matched = False
        for m in models:
            if default_name and m.name == default_name:
                m.set("contextLength", model_cfg.get("context_length"))
                m.set("thinking", model_cfg.get("thinking"))
                m.set("ollamaNumCtx", model_cfg.get("ollama_num_ctx"))
                matched = True
            doc.add(m, "uses")

        if default_name and not matched:
            # Ollama unreachable, or the configured model hasn't been pulled
            # yet -- still record what the harness is *configured* to use.
            comp = Component(component_class="model", name=default_name)
            comp.version = default_name
            comp.set("contextLength", model_cfg.get("context_length"))
            comp.set("thinking", model_cfg.get("thinking"))
            comp.set("ollamaNumCtx", model_cfg.get("ollama_num_ctx"))
            doc.add(comp, "uses")
            doc.warn(f"configured model {default_name!r} not found via Ollama /api/tags; recorded from config only")

    def _collect_skills(self, doc: HarnessDocument) -> None:
        for comp in skills_mod.discover_skills(self.hermes_dir / "skills"):
            doc.add(comp, "loads")

    def _collect_hooks(self, doc: HarnessDocument) -> None:
        try:
            output = self.run(["hermes", "hooks", "doctor"])
        except (OSError, subprocess.SubprocessError):
            return
        if not output.strip():
            return

        doc.warn(
            "hook parsing from `hermes hooks doctor` text output is best-effort; "
            "verify field extraction against a live box before relying on it"
        )
        for line in output.splitlines():
            line = line.strip()
            if not (line.startswith("✓") or line.startswith("✗")):
                continue
            name_match = re.search(r"([\w./-]+\.(?:sh|py))", line)
            if not name_match:
                # Status lines with no script name of their own (e.g. "script
                # unchanged since approval") describe the previous hook, not
                # a new one -- skip rather than inventing a phantom component.
                continue
            approved = line.startswith("✓")

            comp = Component(component_class="hook", name=name_match.group(1))
            comp.set("approvalStatus", "allowlisted" if approved else "not_allowlisted")
            if date_match := re.search(r"approved ([0-9-]+)", line):
                comp.set("approvedAt", date_match.group(1))
            comp.set("rawLine", line)
            doc.add(comp, "approves" if approved else "executes")
