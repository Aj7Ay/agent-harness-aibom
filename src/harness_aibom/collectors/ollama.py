"""Discover Ollama models via the local Ollama HTTP API (`GET /api/tags`).

Shared by the Hermes and OpenClaw collectors, since both just point their
own provider config at an Ollama base_url. `fetch` is injectable for tests;
the real one is a plain stdlib urllib GET with a short timeout, so a
harness scan never hangs just because Ollama happens to be down.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Callable

from ..model import Component

FetchFn = Callable[[str], dict]


def default_fetch(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310 - trusted local endpoint
        return json.loads(resp.read().decode("utf-8"))


def discover_models(base_url: str, fetch: FetchFn = default_fetch) -> list[Component]:
    """base_url looks like 'http://127.0.0.1:11434' or '.../v1' -- the /v1
    suffix (OpenAI-compatible API) is stripped since /api/tags is Ollama's
    own native endpoint, not the OpenAI-compatible one."""
    root = base_url.rstrip("/")
    if root.endswith("/v1"):
        root = root[: -len("/v1")]

    try:
        data = fetch(f"{root}/api/tags")
    except Exception:
        return []

    models = []
    for m in data.get("models", []):
        comp = Component(component_class="model", name=m.get("name", "unknown"))
        comp.version = m.get("name")
        details = m.get("details") or {}
        comp.set("digest", m.get("digest"))
        comp.set("sizeBytes", m.get("size"))
        comp.set("modifiedAt", m.get("modified_at"))
        comp.set("family", details.get("family"))
        comp.set("parameterSize", details.get("parameter_size"))
        comp.set("quantizationLevel", details.get("quantization_level"))
        models.append(comp)
    return models
