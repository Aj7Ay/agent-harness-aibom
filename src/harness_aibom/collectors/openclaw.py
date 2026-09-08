"""Collector for the OpenClaw agent gateway.

Grounded in ~/pdso/docker/devsecops-box-gpu-oc/README.md, not guessed:
  - Config lives at ~/.openclaw/openclaw.json, written by
    `openclaw config set --batch-json` -- gateway bind/port/token, and
    models.providers.ollama.baseUrl plus a default model like
    "ollama/qwen3:8b" under models.default.
  - The gateway auth token is also mirrored into /opt/openclaw/.env
    (OPENCLAW_GATEWAY_TOKEN) -- a secrets surface; this collector never
    reads the value, only records that the file exists and its permissions.
  - Provider credentials for Ollama actually live in a per-agent SQLite
    store, ~/.openclaw/agents/<agent>/agent/openclaw-agent.sqlite -- also a
    secrets surface, path/mode only.
  - `openclaw --version` output format is not confirmed from source
    material (unlike Hermes's more structured, documented version string),
    so this collector records the first line verbatim without parsing it
    into a semantic version.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Callable

from ..fingerprint import sha256_file
from ..model import Component, HarnessDocument
from . import mcp as mcp_mod
from . import ollama as ollama_mod
from . import secrets as secrets_mod
from .base import Collector

RunFn = Callable[[list[str]], str]


def default_run(argv: list[str]) -> str:
    return subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False).stdout


class OpenClawCollector(Collector):
    runtime_kind = "openclaw"

    def __init__(
        self,
        home: Path | None = None,
        run: RunFn = default_run,
        fetch: ollama_mod.FetchFn = ollama_mod.default_fetch,
        env_dir: Path | None = None,
    ):
        super().__init__(home)
        self.run = run
        self.fetch = fetch
        # /opt/openclaw/.env on the real box; overridable since a non-root
        # scan can't read /opt/openclaw there anyway, and tests need a
        # fixture-local path.
        self.env_dir = env_dir or Path("/opt/openclaw")

    @property
    def openclaw_dir(self) -> Path:
        return self.home / ".openclaw"

    @property
    def config_path(self) -> Path:
        return self.openclaw_dir / "openclaw.json"

    def is_present(self) -> bool:
        return self.openclaw_dir.is_dir() or self.config_path.is_file()

    def collect(self, doc: HarnessDocument) -> None:
        self._collect_runtime(doc)
        config = self._collect_config(doc)
        self._collect_model(doc, config)
        for comp in mcp_mod.extract_mcp_servers(config):
            doc.add(comp, "uses")
        self._collect_secrets(doc)

    def _collect_runtime(self, doc: HarnessDocument) -> None:
        try:
            output = self.run(["openclaw", "--version"])
        except (OSError, subprocess.SubprocessError):
            doc.warn("openclaw binary not found on PATH; runtime component skipped")
            return
        if not output.strip():
            doc.warn("`openclaw --version` produced no output; runtime component skipped")
            return

        comp = Component(component_class="runtime", name="openclaw")
        comp.version = output.splitlines()[0].strip()
        doc.add(comp, "uses")

    def _collect_config(self, doc: HarnessDocument) -> dict:
        if not self.config_path.is_file():
            doc.warn(f"{self.config_path} not found; model/configuration components skipped")
            return {}
        try:
            config = json.loads(self.config_path.read_text())
        except json.JSONDecodeError as exc:
            doc.warn(f"could not parse {self.config_path}: {exc}")
            return {}

        comp = Component(component_class="configuration", name="openclaw.json")
        comp.set("path", str(self.config_path))
        comp.set("sha256", sha256_file(self.config_path))
        doc.add(comp, "loads")
        return config

    def _collect_model(self, doc: HarnessDocument, config: dict) -> None:
        providers = ((config.get("models") or {}).get("providers")) or {}
        ollama_cfg = providers.get("ollama") or {}
        base_url = ollama_cfg.get("baseUrl") or ollama_cfg.get("base_url")
        if not base_url:
            return

        endpoint = Component(component_class="model_endpoint", name=base_url)
        endpoint.set("provider", "ollama")
        doc.add(endpoint, "uses")

        # OpenClaw addresses models as "<provider>/<name>", e.g. "ollama/qwen3:8b".
        default_model = (config.get("models") or {}).get("default")
        default_name = default_model.split("/", 1)[1] if default_model and "/" in default_model else default_model

        models = ollama_mod.discover_models(base_url, self.fetch)
        matched = False
        for m in models:
            if default_name and m.name == default_name:
                matched = True
            doc.add(m, "uses")

        if default_name and not matched:
            comp = Component(component_class="model", name=default_name)
            comp.version = default_name
            doc.add(comp, "uses")
            doc.warn(f"configured model {default_name!r} not found via Ollama /api/tags; recorded from config only")

    def _collect_secrets(self, doc: HarnessDocument) -> None:
        for comp in secrets_mod.find_secrets_surface(self.env_dir):
            doc.add(comp, "accesses")
        for comp in secrets_mod.find_secrets_surface(self.openclaw_dir):
            doc.add(comp, "accesses")

        agents_dir = self.openclaw_dir / "agents"
        if agents_dir.is_dir():
            for sqlite_path in sorted(agents_dir.glob("*/agent/*.sqlite")):
                comp = Component(component_class="secrets_surface", name=sqlite_path.name)
                comp.set("path", str(sqlite_path))
                comp.set("note", "per-agent provider credential store (SQLite); contents never read")
                doc.add(comp, "accesses")
