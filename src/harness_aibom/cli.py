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
from .security import compute_risk_observations
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

    # --baseline (v0.7.0): diff's own output, rendered -- `diff` is
    # already this project's strongest output for "what changed", but
    # had no HTML view. Reuses diff_documents() directly rather than a
    # second implementation, so the two commands can never disagree
    # about what counts as a change.
    diff_result = None
    if args.baseline:
        baseline_data = _load_json_file(args.baseline)
        if baseline_data is None:
            return 1
        if not isinstance(baseline_data, dict):
            print(f"error: {args.baseline}: not a CycloneDX document (expected a JSON object)", file=sys.stderr)
            return 1
        diff_result = diff_documents(baseline_data, data)

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
        out_path.write_text(render_html(data, diff_result=diff_result), encoding="utf-8")
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


#: Same rank every severity-sorted view in this project already uses
#: (security.py's own _SEVERITY_RANK) -- kept here too since cli.py
#: doesn't import security.py's private constant.
_POLICY_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def _run_policy(args: argparse.Namespace) -> int:
    """Gate on security.py's own named risk rules -- reuses
    compute_risk_observations() directly rather than a second rule
    engine, so `policy` and the report's own Risk observations section
    (§9) can never disagree about what counts as a finding.

    Without --baseline: fails if any finding at or above --fail-on
    exists in `file` at all. With --baseline: fails only on a finding
    that's genuinely NEW since the baseline (same rule, same component,
    present in `file` but not in `baseline`) -- a pre-existing, already-
    accepted risk shouldn't fail CI forever just for existing; the real
    CI-gating question is usually "did THIS change make things worse."
    """
    data = _load_json_file(args.file)
    if data is None:
        return 1
    if not isinstance(data, dict):
        print(f"error: {args.file}: not a CycloneDX document (expected a JSON object)", file=sys.stderr)
        return 1

    observations = compute_risk_observations(data)
    baseline_keys: set[tuple[str, str]] = set()
    if args.baseline:
        baseline_data = _load_json_file(args.baseline)
        if baseline_data is None:
            return 1
        if not isinstance(baseline_data, dict):
            print(f"error: {args.baseline}: not a CycloneDX document (expected a JSON object)", file=sys.stderr)
            return 1
        baseline_keys = {
            (o["rule"], ref) for o in compute_risk_observations(baseline_data) for ref in o["components"]
        }

    threshold = _POLICY_SEVERITY_RANK[args.fail_on]
    violations = []
    for o in observations:
        if _POLICY_SEVERITY_RANK.get(o["severity"], 99) > threshold:
            continue
        new_refs = [ref for ref in o["components"] if (o["rule"], ref) not in baseline_keys]
        if args.baseline and not new_refs:
            continue  # every match already existed in the baseline -- not new
        violations.append((o, new_refs if args.baseline else o["components"]))

    violating_refs = {id(o): refs for o, refs in violations}
    for o in observations:
        refs = violating_refs.get(id(o))
        marker = "x" if refs is not None else "."
        print(f"{marker} [{o['severity']}] {o['rule']}: {o['summary']}")
        # In --baseline mode `o['summary']`'s own count still covers
        # every match (old and new alike) -- print exactly which ones
        # are the new ones a CI reader actually needs to act on,
        # otherwise "1 finding new since baseline" names a rule but
        # never the specific component that changed.
        if args.baseline and refs:
            print(f"    new: {', '.join(refs)}")

    scope = "new since baseline" if args.baseline else f"at or above '{args.fail_on}'"
    if violations:
        print(f"\npolicy: FAILED -- {len(violations)} finding(s) {scope}", file=sys.stderr)
        return 1
    print(f"\npolicy: passed -- no findings {scope}")
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
    report.add_argument(
        "--baseline",
        help="a second harness-aibom JSON document to diff against -- renders the changes inline "
        "(a Baseline diff section) instead of the report's usual 'not available for a single scan' note",
    )
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

    policy = sub.add_parser(
        "policy", help="gate on security.py's named risk rules -- exit 1 on a qualifying finding, for CI"
    )
    policy.add_argument("file")
    policy.add_argument(
        "--fail-on",
        choices=["low", "medium", "high"],
        default="medium",
        help="fail if any finding at or above this severity exists (default: medium)",
    )
    policy.add_argument(
        "--baseline",
        help="only fail on a finding that's genuinely new since this baseline document -- a pre-existing, "
        "already-accepted risk doesn't fail CI forever just for still existing",
    )
    policy.set_defaults(func=_run_policy)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
