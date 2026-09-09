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
from .report import render_html
from .validate import validate_document

COLLECTORS = {
    "hermes": HermesCollector,
    "openclaw": OpenClawCollector,
}


def _make_collector(cls, home: Path, args: argparse.Namespace):
    if cls is OpenClawCollector and getattr(args, "openclaw_env_dir", None):
        return cls(home=home, env_dir=Path(args.openclaw_env_dir))
    return cls(home=home)


def _run_scan(args: argparse.Namespace) -> int:
    # .resolve(): two --home values that name the same directory (one
    # relative, one absolute) must produce identical `path` properties, or
    # `diff` reports false changes on every path-bearing component just
    # from how the flag was spelled -- confirmed with a real before/after
    # scan using a relative vs. an absolute --home.
    home = (Path(args.home).expanduser() if args.home else Path.home()).resolve()

    if args.runtime == "auto":
        candidates = [_make_collector(cls, home, args) for cls in COLLECTORS.values()]
        active = [c for c in candidates if c.is_present()]
        if not active:
            print(f"no supported runtime found under {home}", file=sys.stderr)
            return 1
        if len(active) > 1 and args.output:
            names = ", ".join(c.runtime_kind for c in active)
            print(f"multiple runtimes found ({names}); writing one file per runtime instead of {args.output}")
    else:
        active = [_make_collector(COLLECTORS[args.runtime], home, args)]

    for collector in active:
        doc = HarnessDocument(
            harness_name=f"{collector.runtime_kind}@{current_hostname()}",
            runtime_kind=collector.runtime_kind,
            hostname=current_hostname(),
        )
        collector.collect(doc)
        for w in doc.warnings:
            print(f"warning[{collector.runtime_kind}]: {w}", file=sys.stderr)

        bom = to_cyclonedx(doc, deterministic=args.deterministic)
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


def _load_json_file(path: str) -> dict | None:
    """None on any read/parse failure, after printing a clean one-line
    `error: ...` -- callers return exit code 1 rather than letting a
    traceback reach the user for an everyday mistake like a missing or
    malformed file."""
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        print(f"error: {path}: no such file", file=sys.stderr)
    except IsADirectoryError:
        print(f"error: {path}: is a directory, not a file", file=sys.stderr)
    except OSError as exc:
        print(f"error: {path}: {exc.strerror or exc}", file=sys.stderr)
    except json.JSONDecodeError as exc:
        print(f"error: {path}: not valid JSON ({exc})", file=sys.stderr)
    return None


def _run_validate(args: argparse.Namespace) -> int:
    data = _load_json_file(args.file)
    if data is None:
        return 1
    errors = validate_document(data)
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"{args.file}: valid")
    return 0


def _run_report(args: argparse.Namespace) -> int:
    data = _load_json_file(args.file)
    if data is None:
        return 1
    if not isinstance(data, dict):
        print(f"error: {args.file}: not a CycloneDX document (expected a JSON object)", file=sys.stderr)
        return 1

    in_path = Path(args.file)
    out_path = Path(args.output) if args.output else in_path.with_suffix(".html")
    # Confirmed real: with no --output, a .html input's own default output
    # path is itself -- report x.html silently overwrote its own input,
    # destroying it. Compare resolved paths, not raw strings, so a
    # relative and an absolute spelling of the same file are still caught.
    if out_path.resolve() == in_path.resolve():
        print(f"error: refusing to overwrite {args.file} -- pass --output to write somewhere else", file=sys.stderr)
        return 1

    try:
        # encoding="utf-8" explicitly: without it, write_text() uses the
        # platform's locale-preferred encoding -- a C/POSIX locale (normal
        # in Docker/CI) raises UnicodeEncodeError on the em dash in the
        # page <title> and leaves a truncated file behind; some Windows
        # locales would instead mangle it silently while the page still
        # declares charset=utf-8.
        out_path.write_text(render_html(data), encoding="utf-8")
    except OSError as exc:
        print(f"error: {out_path}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    print(f"wrote {out_path}")
    return 0


def _run_diff(args: argparse.Namespace) -> int:
    before = _load_json_file(args.before)
    after = _load_json_file(args.after)
    if before is None or after is None:
        return 1

    result = diff_documents(before, after)
    print(json.dumps(result, indent=2))

    if args.exit_code and (result["added"] or result["removed"] or result["changed"]):
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="harness-aibom")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a running harness and emit a CycloneDX AIBOM")
    scan.add_argument("--runtime", choices=["auto", *COLLECTORS], default="auto")
    scan.add_argument("--home", help="home directory to scan under (default: current user's)")
    scan.add_argument("--output", "-o", help="write to this file instead of stdout")
    scan.add_argument(
        "--pretty",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="pretty-print JSON (default: on; pass --no-pretty for compact single-line output)",
    )
    scan.add_argument(
        "--openclaw-env-dir",
        help="override the OpenClaw gateway .env directory (default: /opt/openclaw)",
    )
    scan.add_argument(
        "--deterministic",
        action="store_true",
        help=(
            "omit serialNumber and metadata.timestamp so two scans of an unchanged box "
            "produce byte-identical output -- for hashing/signing the AIBOM as a baseline"
        ),
    )
    scan.set_defaults(func=_run_scan)

    validate = sub.add_parser("validate", help="check a harness-aibom JSON document's shape")
    validate.add_argument("file")
    validate.set_defaults(func=_run_validate)

    report = sub.add_parser("report", help="render a harness-aibom document as a single static HTML file")
    report.add_argument("file")
    report.add_argument("--output", "-o", help="output HTML file (default: <file> with a .html extension)")
    report.set_defaults(func=_run_report)

    diff = sub.add_parser("diff", help="compare two harness-aibom documents, e.g. before/after a suspected compromise")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument(
        "--exit-code",
        action="store_true",
        help="exit 1 if the documents differ, like `git diff --exit-code` -- for use as a CI gate",
    )
    diff.set_defaults(func=_run_diff)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
