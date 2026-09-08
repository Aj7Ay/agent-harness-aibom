"""`harness-aibom` command-line entrypoint: scan / validate / diff."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .collectors.hermes import HermesCollector
from .collectors.openclaw import OpenClawCollector
from .cyclonedx import current_hostname, to_cyclonedx
from .diff import diff_documents
from .model import HarnessDocument
from .validate import validate_document

COLLECTORS = {
    "hermes": HermesCollector,
    "openclaw": OpenClawCollector,
}


def _run_scan(args: argparse.Namespace) -> int:
    home = Path(args.home).expanduser() if args.home else Path.home()

    if args.runtime == "auto":
        candidates = [cls(home=home) for cls in COLLECTORS.values()]
        active = [c for c in candidates if c.is_present()]
        if not active:
            print(f"no supported runtime found under {home}", file=sys.stderr)
            return 1
    else:
        active = [COLLECTORS[args.runtime](home=home)]

    for collector in active:
        doc = HarnessDocument(
            harness_name=f"{collector.runtime_kind}@{current_hostname()}",
            runtime_kind=collector.runtime_kind,
            hostname=current_hostname(),
        )
        collector.collect(doc)
        for w in doc.warnings:
            print(f"warning[{collector.runtime_kind}]: {w}", file=sys.stderr)

        bom = to_cyclonedx(doc)
        text = json.dumps(bom, indent=2 if args.pretty else None)

        if args.output:
            out_path = Path(args.output)
            if len(active) > 1:
                out_path = out_path.with_name(f"{collector.runtime_kind}-{out_path.name}")
            out_path.write_text(text + "\n")
            print(f"wrote {out_path}")
        else:
            print(text)

    return 0


def _run_validate(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.file).read_text())
    errors = validate_document(data)
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"{args.file}: valid")
    return 0


def _run_diff(args: argparse.Namespace) -> int:
    before = json.loads(Path(args.before).read_text())
    after = json.loads(Path(args.after).read_text())
    print(json.dumps(diff_documents(before, after), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="harness-aibom")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a running harness and emit a CycloneDX AIBOM")
    scan.add_argument("--runtime", choices=["auto", *COLLECTORS], default="auto")
    scan.add_argument("--home", help="home directory to scan under (default: current user's)")
    scan.add_argument("--output", "-o", help="write to this file instead of stdout")
    scan.add_argument("--pretty", action="store_true", default=True, help="pretty-print JSON (default: on)")
    scan.set_defaults(func=_run_scan)

    validate = sub.add_parser("validate", help="check a harness-aibom JSON document's shape")
    validate.add_argument("file")
    validate.set_defaults(func=_run_validate)

    diff = sub.add_parser("diff", help="compare two harness-aibom documents, e.g. before/after a suspected compromise")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.set_defaults(func=_run_diff)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
