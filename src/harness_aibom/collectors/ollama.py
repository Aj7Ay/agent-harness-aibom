"""Discover Ollama models via the local Ollama HTTP API (`GET /api/tags`,
and -- v0.9.0 -- an optional per-model `POST /api/show` enrichment).

Shared by the Hermes and OpenClaw collectors, since both just point their
own provider config at an Ollama base_url. `fetch`/`show_fetch` are
injectable for tests; the real ones are plain stdlib urllib calls with a
short timeout, so a harness scan never hangs just because Ollama happens
to be down.

**`/api/show` verification note (v0.9.0)**: the exact response field
names below (`template`, `parameters`, `capabilities`, `details.
parent_model`, `details.format`, `model_info["general.architecture"]`)
were confirmed by fetching Ollama's own real, current, published API doc
(github.com/ollama/ollama/blob/main/docs/api.md) -- not recalled from
memory. **This was NOT additionally verified against a live Ollama
server** -- no Ollama instance was available in the sandbox this was
built in. Implemented strictly against the real, fetched, current API
doc (including its own example response, reproduced in tests), with
graceful degradation (never a crash, never a scan warning that blocks
anything) if a real server's actual behavior ever differs from that
doc. See SPEC.md for the exact reasoning and what would need to change
if this is later verified against a live box.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Callable

from ..model import Component

FetchFn = Callable[[str], dict]
ShowFetchFn = Callable[[str, str], dict]


def default_fetch(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310 - trusted local endpoint
        return json.loads(resp.read().decode("utf-8"))


def default_show_fetch(base_url: str, model_name: str) -> dict:
    """`POST {base_url}/api/show` with `{"model": model_name}` -- the
    real, documented request shape (Ollama's own api.md). Raises on any
    failure (connection refused, timeout, non-JSON body); callers treat
    that as "not available for this model", never a crash.
    """
    body = json.dumps({"model": model_name}).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/show", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 - trusted local endpoint
        return json.loads(resp.read().decode("utf-8"))


#: The one `model_info` key this module reads -- confirmed in Ollama's
#: own documented example response and architecture-agnostic (every
#: other example key there, e.g. `llama.attention.head_count`, is
#: namespaced to one specific model family and would be a guess to
#: generalize to an arbitrary model).
_MODEL_INFO_ARCHITECTURE_KEY = "general.architecture"


def enrich_model_with_show_info(
    comp: Component, base_url: str, model_name: str, show_fetch: ShowFetchFn = default_show_fetch,
) -> bool:
    """Best-effort `/api/show` enrichment for one already-discovered
    model component. Every property this can set comes from a field
    verified in Ollama's own real, published API doc (this module's own
    docstring) -- never a guessed field name or shape. Returns True if
    anything was actually added, False on any failure (network error,
    malformed/unexpected response shape, an older Ollama without this
    endpoint) -- never raises, the same graceful-degradation discipline
    `discover_models()` itself already follows for `/api/tags`.

    Deliberately narrow about `model_info`: it's a large, architecture-
    dependent dict in real Ollama responses (`llama.attention.head_count`,
    `qwen3.embedding_length`, ...) -- reading every key would mean
    inventing a schema Ollama itself doesn't fix across model families.
    Only `general.architecture` is read, the one key confirmed stable in
    Ollama's own documented example.
    """
    try:
        data = show_fetch(base_url, model_name)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False

    added = False

    template = data.get("template")
    if isinstance(template, str) and template.strip():
        comp.set("promptTemplate", template)
        added = True

    parameters = data.get("parameters")
    if isinstance(parameters, str) and parameters.strip():
        comp.set("declaredParameters", parameters)
        added = True

    capabilities = data.get("capabilities")
    if isinstance(capabilities, list) and capabilities:
        comp.set("capabilities", ",".join(str(c) for c in capabilities))
        added = True

    details = data.get("details")
    if isinstance(details, dict):
        # family/parameter_size/quantization_level are already captured
        # from /api/tags's own `details` (discover_models below) -- only
        # the two fields NOT already collected are read here.
        if details.get("parent_model"):
            comp.set("parentModel", details["parent_model"])
            added = True
        if details.get("format"):
            comp.set("modelfileFormat", details["format"])
            added = True

    model_info = data.get("model_info")
    if isinstance(model_info, dict) and model_info.get(_MODEL_INFO_ARCHITECTURE_KEY):
        comp.set("architecture", model_info[_MODEL_INFO_ARCHITECTURE_KEY])
        added = True

    return added


def discover_models(
    base_url: str,
    fetch: FetchFn = default_fetch,
    show_fetch: ShowFetchFn | None = default_show_fetch,
) -> list[Component]:
    """base_url looks like 'http://127.0.0.1:11434' or '.../v1' -- the /v1
    suffix (OpenAI-compatible API) is stripped since /api/tags is Ollama's
    own native endpoint, not the OpenAI-compatible one.

    `show_fetch` (v0.9.0) drives the optional per-model `/api/show`
    enrichment above -- pass `None` to skip it entirely (e.g. a caller
    that only wants the cheap `/api/tags` list). Defaults to the real
    fetcher, matching `fetch`'s own default-on behavior for `/api/tags`;
    a failure enriching any one model never drops that model from the
    result, it just keeps the fields `/api/tags` already provided.
    """
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
        digest = m.get("digest")
        comp.set("digest", digest)
        # v0.9.0: a real, directly *observed* fact -- taken verbatim from
        # Ollama's own manifest digest, never recomputed or guessed
        # (SPEC.md section 3) -- tagged explicitly so it can be read back
        # and contrasted with a genuinely *inferred* fact elsewhere in
        # the document (skills.py's own content-analysis properties).
        if digest:
            comp.set("digestConfidence", "observed")
        comp.set("sizeBytes", m.get("size"))
        comp.set("modifiedAt", m.get("modified_at"))
        comp.set("family", details.get("family"))
        comp.set("parameterSize", details.get("parameter_size"))
        comp.set("quantizationLevel", details.get("quantization_level"))
        if show_fetch is not None:
            enrich_model_with_show_info(comp, root, comp.name, show_fetch)
        models.append(comp)
    return models
