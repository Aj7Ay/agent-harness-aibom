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
from ..paths import relative_to_or_none
from . import deps as deps_mod
from . import mcp as mcp_mod
from . import memory_store as memory_store_mod
from . import ollama as ollama_mod
from . import prompt_surface as prompt_surface_mod
from . import secrets as secrets_mod
from . import skills as skills_mod
from .base import Collector

RunFn = Callable[[list[str]], str]


def default_run(argv: list[str]) -> str:
    # stdin=DEVNULL: if the real binary ever falls through to an
    # interactive prompt instead of the flag we asked for, it gets an
    # immediate EOF instead of hanging until `timeout` kills the scan --
    # confirmed necessary against a live Hermes box (see hermes.py).
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=10, check=False, stdin=subprocess.DEVNULL
    ).stdout


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
        runtime_comp = self._collect_runtime(doc)
        if runtime_comp is not None:
            self._collect_dependencies(doc, runtime_comp)
        config, config_comp = self._collect_config(doc)
        if config_comp is not None:
            self._collect_model(doc, config, config_comp)
            self._collect_mcp_servers(doc, config, config_comp)
        self._collect_skills(doc, config)
        self._collect_secrets(doc)
        for comp in prompt_surface_mod.find_prompt_surface(self.openclaw_dir, self.home):
            doc.add(comp, "loads")
        for comp in memory_store_mod.find_memory_store(self.openclaw_dir, self.home):
            doc.add(comp, "accesses")

    def _collect_mcp_servers(self, doc: HarnessDocument, config: dict, config_comp: Component) -> None:
        # Real dependency-graph edges, not root edges -- see hermes.py's
        # identical method for why.
        for server, tools, package in mcp_mod.extract_mcp_servers(config):
            doc.add_child(server, config_comp, "uses")
            for tool in tools:
                doc.add_child(tool, server, "uses")
            if package is not None:
                doc.add_child(package, server, "uses")

    def _collect_dependencies(self, doc: HarnessDocument, runtime_comp: Component) -> None:
        # No-op today: unlike Hermes's structured `--version` output,
        # OpenClaw's isn't confirmed from source material (see module
        # docstring), so `_collect_runtime` below never sets an
        # `installDir` property to look under. Wired up anyway so this
        # starts working the moment that output format is confirmed and
        # `installDir` gets captured, with no further change needed here.
        install_dir = runtime_comp.properties.get("installDir")
        if not install_dir:
            return
        for dep in deps_mod.discover_python_dependencies(Path(install_dir)):
            doc.add_child(dep, runtime_comp, "uses")

    def _collect_runtime(self, doc: HarnessDocument) -> Component | None:
        try:
            output = self.run(["openclaw", "--version"])
        except FileNotFoundError:
            doc.warn("openclaw binary not found on PATH; runtime component skipped")
            return None
        except subprocess.TimeoutExpired:
            doc.warn(
                "`openclaw --version` did not finish within the timeout; runtime component skipped "
                "(the binary IS on PATH -- this is a hang or a slow response, not a missing install)"
            )
            return None
        except (OSError, subprocess.SubprocessError) as exc:
            doc.warn(f"`openclaw --version` failed ({exc.__class__.__name__}: {exc}); runtime component skipped")
            return None
        if not output.strip():
            doc.warn("`openclaw --version` produced no output; runtime component skipped")
            return None

        comp = Component(component_class="runtime", name="openclaw")
        comp.version = output.splitlines()[0].strip()
        return doc.add(comp, "uses")

    def _collect_config(self, doc: HarnessDocument) -> tuple[dict, Component | None]:
        if not self.config_path.is_file():
            doc.warn(f"{self.config_path} not found; model/configuration components skipped")
            return {}, None
        try:
            config = json.loads(self.config_path.read_text())
        except json.JSONDecodeError as exc:
            doc.warn(f"could not parse {self.config_path}: {exc}")
            return {}, None

        comp = Component(component_class="configuration", name="openclaw.json")
        comp.set("path", str(self.config_path))
        comp.set("relPath", relative_to_or_none(self.config_path, self.home))
        comp.set("sha256", sha256_file(self.config_path))
        doc.add(comp, "loads")
        return config, comp

    def _collect_model(self, doc: HarnessDocument, config: dict, config_comp: Component) -> None:
        providers = ((config.get("models") or {}).get("providers")) or {}
        ollama_cfg = providers.get("ollama") or {}
        base_url = ollama_cfg.get("baseUrl") or ollama_cfg.get("base_url")
        if not base_url:
            return

        endpoint = Component(component_class="model_endpoint", name=base_url)
        endpoint.set("provider", "ollama")
        doc.add_child(endpoint, config_comp, "uses")

        # OpenClaw addresses models as "<provider>/<name>", e.g. "ollama/qwen3:8b".
        default_model = (config.get("models") or {}).get("default")
        default_name = default_model.split("/", 1)[1] if default_model and "/" in default_model else default_model

        models = ollama_mod.discover_models(base_url, self.fetch)
        matched = False
        for m in models:
            if default_name and m.name == default_name:
                matched = True
            doc.add_child(m, endpoint, "uses")

        if default_name and not matched:
            comp = Component(component_class="model", name=default_name)
            comp.version = default_name
            doc.add_child(comp, endpoint, "uses")
            doc.warn(f"configured model {default_name!r} not found via Ollama /api/tags; recorded from config only")

    def _collect_skills(self, doc: HarnessDocument, config: dict) -> None:
        # Not confirmed from source material that OpenClaw has a skills
        # directory at all -- discover_skills() returns [] harmlessly if
        # ~/.openclaw/skills/ doesn't exist, same as any other optional
        # piece this collector looks for.
        known_servers = frozenset(server.name for server, _tools, _pkg in mcp_mod.extract_mcp_servers(config))
        for comp in skills_mod.discover_skills(self.openclaw_dir / "skills", self.home, known_servers):
            doc.add(comp, "loads")

    def _collect_secrets(self, doc: HarnessDocument) -> None:
        # env_dir defaults to /opt/openclaw, entirely outside self.home --
        # relative_to_or_none() inside find_secrets_surface() just leaves
        # relPath unset for these, `path` still identifies them uniquely.
        for comp in secrets_mod.find_secrets_surface(self.env_dir, self.home):
            doc.add(comp, "accesses")
        # exclude_dirnames={"agents"}: that subtree is scanned explicitly
        # below with richer, OpenClaw-specific metadata (which agent, that
        # it's a credential store) -- scanning it here too via the generic
        # *.sqlite pattern would report the same file as two components.
        for comp in secrets_mod.find_secrets_surface(
            self.openclaw_dir, self.home, exclude_dirnames=frozenset({"agents"})
        ):
            doc.add(comp, "accesses")

        agents_dir = self.openclaw_dir / "agents"
        if agents_dir.is_dir():
            for sqlite_path in sorted(agents_dir.glob("*/agent/*.sqlite")):
                comp = Component(component_class="secrets_surface", name=sqlite_path.name)
                comp.set("path", str(sqlite_path))
                comp.set("relPath", relative_to_or_none(sqlite_path, self.home))
                comp.set("note", "per-agent provider credential store (SQLite); contents never read")
                doc.add(comp, "accesses")
