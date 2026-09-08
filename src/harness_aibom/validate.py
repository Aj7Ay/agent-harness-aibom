"""Lightweight structural check for a harness-aibom document.

This is *not* a full CycloneDX 1.6 schema validator -- reproducing that
schema exactly here would be its own maintenance burden, and general
CycloneDX validity is better checked with a dedicated tool. What this
checks is specific to harness-aibom: the CycloneDX envelope is present, and
every component carries a recognized harness-aibom:componentClass whose
declared `type` matches what SPEC.md says that class should use.
"""

from __future__ import annotations

from .model import CDX_TYPE_FOR_CLASS

REQUIRED_TOP_LEVEL = ("bomFormat", "specVersion", "components")


def validate_document(data: dict) -> list[str]:
    errors: list[str] = []

    for key in REQUIRED_TOP_LEVEL:
        if key not in data:
            errors.append(f"missing top-level field {key!r}")

    if "bomFormat" in data and data["bomFormat"] != "CycloneDX":
        errors.append(f"bomFormat must be 'CycloneDX', got {data['bomFormat']!r}")

    for i, comp in enumerate(data.get("components", [])):
        label = f"components[{i}] ({comp.get('name')!r})"
        props = {p.get("name"): p.get("value") for p in comp.get("properties", [])}
        cls = props.get("harness-aibom:componentClass")

        if cls is None:
            errors.append(f"{label} missing harness-aibom:componentClass")
            continue
        if cls not in CDX_TYPE_FOR_CLASS:
            errors.append(f"{label} has unknown componentClass {cls!r}")
            continue

        expected_type = CDX_TYPE_FOR_CLASS[cls]
        if comp.get("type") != expected_type:
            errors.append(f"{label} type={comp.get('type')!r}, expected {expected_type!r} for componentClass {cls!r}")

    return errors
