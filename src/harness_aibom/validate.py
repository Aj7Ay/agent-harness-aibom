"""Lightweight structural check for a harness-aibom document.

This is *not* a full CycloneDX 1.6 schema validator -- reproducing that
schema exactly here would be its own maintenance burden, and general
CycloneDX validity is better checked with a dedicated tool (this package's
own test suite validates its example output against `cyclonedx-python-lib`
for exactly that reason -- see tests/test_cyclonedx_schema.py). What this
checks is specific to harness-aibom: the envelope is present, and every
component/service carries a recognized harness-aibom:componentClass in the
array it actually belongs in.
"""

from __future__ import annotations

from .model import CDX_TYPE_FOR_CLASS, SERVICE_CLASSES

REQUIRED_TOP_LEVEL = ("bomFormat", "specVersion", "components")


def _properties_of(entry: dict) -> dict[str, str]:
    return {p.get("name"): p.get("value") for p in entry.get("properties", [])}


def validate_document(data: dict) -> list[str]:
    errors: list[str] = []

    for key in REQUIRED_TOP_LEVEL:
        if key not in data:
            errors.append(f"missing top-level field {key!r}")

    if "bomFormat" in data and data["bomFormat"] != "CycloneDX":
        errors.append(f"bomFormat must be 'CycloneDX', got {data['bomFormat']!r}")

    for i, comp in enumerate(data.get("components", [])):
        label = f"components[{i}] ({comp.get('name')!r})"
        cls = _properties_of(comp).get("harness-aibom:componentClass")

        if cls is None:
            errors.append(f"{label} missing harness-aibom:componentClass")
            continue
        if cls in SERVICE_CLASSES:
            errors.append(f"{label} has componentClass {cls!r}, which belongs in 'services', not 'components'")
            continue
        if cls not in CDX_TYPE_FOR_CLASS:
            errors.append(f"{label} has unknown componentClass {cls!r}")
            continue

        expected_type = CDX_TYPE_FOR_CLASS[cls]
        if comp.get("type") != expected_type:
            errors.append(f"{label} type={comp.get('type')!r}, expected {expected_type!r} for componentClass {cls!r}")

    for i, svc in enumerate(data.get("services", [])):
        label = f"services[{i}] ({svc.get('name')!r})"
        cls = _properties_of(svc).get("harness-aibom:componentClass")

        if cls is None:
            errors.append(f"{label} missing harness-aibom:componentClass")
        elif cls not in SERVICE_CLASSES:
            errors.append(f"{label} has componentClass {cls!r}, which belongs in 'components', not 'services'")

    return errors
