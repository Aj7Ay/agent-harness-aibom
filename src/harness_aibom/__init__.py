"""agent-harness-aibom: an AIBOM generator for AI agent harnesses.

This package answers a narrower question than a general-purpose AI BOM
scanner: what exactly constitutes a *deployed agent harness* -- its runtime
binary, the model endpoint(s) it talks to, the configuration and skills it
loads, the MCP servers and hooks it can reach, and the secrets surface
around all of that. See SPEC.md at the repo root for the full data model.
"""

__version__ = "0.1.3"
