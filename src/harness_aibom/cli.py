"""`harness-aibom` command-line entrypoint: scan / validate / diff."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from . import __version__
from .collectors.hermes import HermesCollector
from .collectors.openclaw import OpenClawCollector
from .cyclonedx import current_hostname, to_cyclonedx
from .diff import diff_documents
from .model import HarnessDocument
from .policy_yaml import PolicyFileError, evaluate_policy_rules, load_policy_rules
from .report import render_html
from .security import compute_risk_observations, diff_risk_observations
from .sign import CosignNotFound, sign_blob, verify_blob
from .validate import find_orphan_components, validate_document

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

    if args.verify_deterministic:
        return _run_verify_deterministic(active)

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


def _run_verify_deterministic(active: list) -> int:
    """Scan each active collector *twice* and confirm the `--deterministic`
    JSON output is byte-for-byte identical both times -- v0.8.2, a real
    reproducibility check, not an assumption resting only on
    `--deterministic` omitting `serialNumber`/`metadata.timestamp` (the
    two wall-clock-derived fields it's documented to strip). Everything
    else in a scan is already meant to reflect only what's actually on
    disk right now, so two scans of the *same, unchanged* filesystem
    state should produce the exact same document -- if they don't,
    `--deterministic`'s whole promise (a stable baseline worth hashing or
    signing, see the `sign`/`verify-signature` commands) is broken for a
    reason worth finding, not just declared true because nothing happened
    to print an error.

    Compares the parsed dicts directly (`==`), not the serialized JSON
    text -- structural equality is the actual claim being verified; a
    text comparison would also count as a difference something JSON
    itself doesn't consider meaningful (which it never should be, since
    both scans go through the same `json.dumps()` call path either way,
    but a structural comparison doesn't have to rely on that staying true).
    """
    ok = True
    for collector in active:
        outputs = []
        for _ in range(2):
            doc = HarnessDocument(
                harness_name=f"{collector.runtime_kind}@{current_hostname()}",
                runtime_kind=collector.runtime_kind,
                hostname=current_hostname(),
            )
            collector.collect(doc)
            outputs.append(to_cyclonedx(doc, deterministic=True))
        if outputs[0] == outputs[1]:
            print(f"PASS [{collector.runtime_kind}]: two scans of the same state are byte-identical")
        else:
            print(
                f"FAIL [{collector.runtime_kind}]: two scans of the same state differ -- "
                "--deterministic output is not actually reproducible right now",
                file=sys.stderr,
            )
            ok = False
    return 0 if ok else 1


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
    # v0.8.0: orphan components are printed but never fail the command --
    # a document with one is still fully valid (validate_document() above
    # already passed), just possibly worth a human's attention. Same
    # "informational, not fatal" treatment `scan`'s own warnings get.
    orphans = find_orphan_components(data)
    for ref in orphans:
        print(f"warning: {ref}: not reachable from the harness root via dependencies[] (orphan)", file=sys.stderr)
    suffix = f" ({len(orphans)} orphan warning{'s' if len(orphans) != 1 else ''})" if orphans else ""
    print(f"{args.file}: valid{suffix}")
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

    # --bundle/--key (v0.8.2): a real cosign verify-blob run against this
    # exact input file, embedded as the Artifact integrity section --
    # never a second verifier, shells out through the same sign.py
    # wrapper `verify-signature` itself uses.
    signature_info = None
    if args.bundle or args.key:
        if not (args.bundle and args.key):
            print("error: --bundle and --key must be given together", file=sys.stderr)
            return 1
        in_path_for_hash = Path(args.file)
        try:
            digest = hashlib.sha256(in_path_for_hash.read_bytes()).hexdigest()
        except OSError as exc:
            print(f"error: {args.file}: {exc.strerror or exc}", file=sys.stderr)
            return 1
        try:
            result = verify_blob(in_path_for_hash, Path(args.key), Path(args.bundle))
        except CosignNotFound as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        signature_info = {
            "sha256": digest,
            "bundle": args.bundle,
            "key": args.key,
            "verified": result.returncode == 0,
            "output": (result.stdout or "") + (result.stderr or ""),
        }

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
        out_path.write_text(render_html(data, diff_result=diff_result, signature_info=signature_info), encoding="utf-8")
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

    if args.security:
        # v0.8.2: the same "what changed" question `diff` already answers
        # structurally (added/removed/changed components), reframed as
        # "what got worse" -- named risk-rule findings, grouped by
        # new/persisting/resolved, via security.py's diff_risk_observations()
        # (the same identity `policy --baseline` uses). Deliberately a
        # separate mode, not folded into the default JSON output: the two
        # questions ("did the inventory change" vs. "did a specific named
        # risk rule newly fire") have different consumers and different
        # shapes -- a generic diff tool wants the former, a security
        # reviewer or a CI gate wants the latter.
        result = diff_risk_observations(before, after)
        print(json.dumps(result, indent=2))
        if args.exit_code and result["new"]:
            return 1
        return 0

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
    v0.8.3: a rule that fired but was suppressed for exactly that reason
    (every one of its matches already in the baseline) prints with a
    distinct `~ [accepted]` marker instead of the plain `.` a rule that
    never fired at all gets -- visibility only, never a change to
    PASS/FAIL or the exit code in baseline mode.

    --format sarif (v0.8.2) renders the SAME findings as a SARIF 2.1.0
    log (sarif.py) instead of the human-readable checklist below, for a
    GitHub/GitLab/Azure code-scanning UI to consume directly -- ignores
    --baseline (a security tab wants the full current picture, not a
    delta) but still honors --fail-on for the exit code, so `policy
    --format sarif` can still gate CI the same way the default text mode
    does, while also producing an artifact a scanning UI can upload.
    """
    data = _load_json_file(args.file)
    if data is None:
        return 1
    if not isinstance(data, dict):
        print(f"error: {args.file}: not a CycloneDX document (expected a JSON object)", file=sys.stderr)
        return 1

    observations = compute_risk_observations(data)

    policy_rules = None
    if args.policy_file:
        if args.format == "sarif":
            print("error: --policy-file is not supported together with --format sarif yet", file=sys.stderr)
            return 1
        try:
            policy_rules = load_policy_rules(Path(args.policy_file).read_text())
        except OSError as exc:
            print(f"error: {args.policy_file}: {exc.strerror or exc}", file=sys.stderr)
            return 1
        except PolicyFileError as exc:
            print(f"error: {args.policy_file}: {exc}", file=sys.stderr)
            return 1

    if args.format == "sarif":
        from .sarif import render_sarif

        text = json.dumps(render_sarif(data), indent=2)
        if args.output:
            Path(args.output).write_text(text + "\n")
            print(f"wrote {args.output}")
        else:
            print(text)
        threshold = _POLICY_SEVERITY_RANK[args.fail_on]
        has_qualifying = any(_POLICY_SEVERITY_RANK.get(o["severity"], 99) <= threshold for o in observations)
        return 1 if has_qualifying else 0
    # rule -> its NEW (not-in-baseline) component refs only -- at most one
    # observation per rule name (compute_risk_observations() never emits
    # two for the same rule), so this dict can't collide. v0.8.2:
    # diff_risk_observations() (security.py) is the same "new since
    # baseline" identity `diff --security` below now shares -- this used
    # to be an ad hoc set comparison duplicated inline here.
    #
    # v0.8.3: `persisting_by_rule` alongside it -- same shape, but the
    # OLD (already-in-baseline) refs a rule matched. A reviewer found that
    # in --baseline mode, a rule that fired only against pre-existing
    # matches (every ref already in the baseline, so `new_by_rule` has
    # nothing for it) printed with the exact same "." marker as a rule
    # that never fired at all -- an accepted, still-present finding was
    # indistinguishable from a clean one, even though `diff_risk_
    # observations()` already knew the difference (that's what its own
    # "persisting" bucket is for). This never changes PASS/FAIL or the
    # exit code -- baseline mode's whole point is that a pre-existing
    # finding shouldn't gate CI -- it only adds visibility.
    new_by_rule: dict[str, list[str]] = {}
    persisting_by_rule: dict[str, list[str]] = {}
    if args.baseline:
        baseline_data = _load_json_file(args.baseline)
        if baseline_data is None:
            return 1
        if not isinstance(baseline_data, dict):
            print(f"error: {args.baseline}: not a CycloneDX document (expected a JSON object)", file=sys.stderr)
            return 1
        diffed = diff_risk_observations(baseline_data, data)
        new_by_rule = {o["rule"]: o["components"] for o in diffed["new"]}
        persisting_by_rule = {o["rule"]: o["components"] for o in diffed["persisting"]}

    threshold = _POLICY_SEVERITY_RANK[args.fail_on]
    violations = []
    for o in observations:
        if _POLICY_SEVERITY_RANK.get(o["severity"], 99) > threshold:
            continue
        new_refs = new_by_rule.get(o["rule"], [])
        if args.baseline and not new_refs:
            continue  # every match already existed in the baseline -- not new
        violations.append((o, new_refs if args.baseline else o["components"]))

    violating_refs = {id(o): refs for o, refs in violations}
    for o in observations:
        refs = violating_refs.get(id(o))
        accepted_refs = persisting_by_rule.get(o["rule"], []) if args.baseline and refs is None else []
        marker = "x" if refs is not None else ("~" if accepted_refs else ".")
        suffix = " [accepted]" if marker == "~" else ""
        print(f"{marker} [{o['severity']}] {o['rule']}: {o['summary']}{suffix}")
        # In --baseline mode `o['summary']`'s own count still covers
        # every match (old and new alike) -- print exactly which ones
        # are the new ones a CI reader actually needs to act on,
        # otherwise "1 finding new since baseline" names a rule but
        # never the specific component that changed. `~ [accepted]`'s own
        # refs get the same treatment, so a reader can see exactly which
        # pre-existing components are still being let through.
        if args.baseline and refs:
            print(f"    new: {', '.join(refs)}")
        elif accepted_refs:
            print(f"    accepted: {', '.join(accepted_refs)}")

    # v0.8.2: user-authored policy-as-code rules (policy_yaml.py), run
    # ALONGSIDE the built-in security.py rules above, never instead of
    # them -- printed in their own clearly labeled block since they carry
    # their own severity/action, independent of --fail-on/--baseline
    # (which apply only to the built-in rules' gating logic above). A
    # rule's own `action: fail` always fails the command regardless of
    # --fail-on; `action: warn` never does, regardless of severity.
    policy_file_failures = 0
    if policy_rules is not None:
        policy_observations = evaluate_policy_rules(data, policy_rules)
        print(f"\npolicy file: {args.policy_file}")
        for o in policy_observations:
            marker = "x" if o["action"] == "fail" else "!"
            print(f"{marker} [{o['severity']}/{o['action']}] {o['rule']}: {o['summary']}")
            if o["action"] == "fail":
                policy_file_failures += 1

    scope = "new since baseline" if args.baseline else f"at or above '{args.fail_on}'"
    if violations or policy_file_failures:
        parts = []
        if violations:
            parts.append(f"{len(violations)} built-in finding(s) {scope}")
        if policy_file_failures:
            parts.append(f"{policy_file_failures} policy-file rule(s) with action: fail")
        print(f"\npolicy: FAILED -- {'; '.join(parts)}", file=sys.stderr)
        return 1
    print(f"\npolicy: passed -- no findings {scope}")
    return 0


def _run_sign(args: argparse.Namespace) -> int:
    """Sign `file` (typically a `--deterministic` scan output -- see
    `scan --verify-deterministic`'s own reasoning for why that matters
    here too: a signature over a non-reproducible document is a
    signature over "whatever happened to be in it that moment", not a
    stable baseline) with `cosign`, writing a sigstore bundle. A thin
    wrapper -- sign.py does the real work; this just turns a missing
    `cosign` binary or a non-zero exit into a clean CLI result instead of
    a raw traceback, and relays cosign's own stdout/stderr verbatim.

    `--signing-config` (v0.8.3) is optional -- `sign_blob()` already
    defaults to the vendored, offline-safe signing config (see sign.py's
    own docstring for why that default exists at all), so this flag only
    matters to a caller who wants a different one.
    """
    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"error: {args.file}: no such file", file=sys.stderr)
        return 1
    bundle_path = Path(args.bundle) if args.bundle else file_path.with_suffix(file_path.suffix + ".bundle")
    signing_config = Path(args.signing_config) if args.signing_config else None
    try:
        result = sign_blob(file_path, Path(args.key), bundle_path, signing_config=signing_config)
    except CosignNotFound as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode == 0:
        print(f"wrote {bundle_path}")
    return result.returncode


def _run_verify_signature(args: argparse.Namespace) -> int:
    """Verify `file` against a sigstore bundle using cosign -- same thin-
    wrapper reasoning as `_run_sign` above: cosign itself decides
    verified/not-verified, this only relays its result cleanly.
    """
    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"error: {args.file}: no such file", file=sys.stderr)
        return 1
    bundle_path = Path(args.bundle) if args.bundle else file_path.with_suffix(file_path.suffix + ".bundle")
    if not bundle_path.is_file():
        print(f"error: {bundle_path}: no such file (pass --bundle if it's somewhere else)", file=sys.stderr)
        return 1
    try:
        result = verify_blob(file_path, Path(args.key), bundle_path)
    except CosignNotFound as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result.returncode


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
    scan.add_argument(
        "--verify-deterministic",
        action="store_true",
        help="run the scan twice and confirm --deterministic output is actually byte-identical both times "
        "-- prints PASS/FAIL instead of writing output, exit 1 on FAIL",
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
    report.add_argument("--bundle", help="a cosign signature bundle for `file` -- verified via cosign at render "
                         "time and shown in the Artifact integrity section; requires --key")
    report.add_argument("--key", help="the cosign public key matching --bundle")
    report.set_defaults(func=_run_report)

    diff = sub.add_parser("diff", help="compare two harness-aibom documents, e.g. before/after a suspected compromise")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument(
        "--exit-code",
        action="store_true",
        help="exit 1 if the documents differ, like `git diff --exit-code` -- for use as a CI gate "
        "(with --security: exit 1 only if a named risk rule newly fired)",
    )
    diff.add_argument(
        "--security",
        action="store_true",
        help="diff security.py's own named risk-rule findings (new/persisting/resolved) instead of "
        "raw component/field changes -- 'what got worse', not just 'what changed'",
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
        "already-accepted risk doesn't fail CI forever just for still existing (shown with a '~ [accepted]' "
        "marker instead of '.', for visibility only -- never changes PASS/FAIL)",
    )
    policy.add_argument(
        "--format",
        choices=["text", "sarif"],
        default="text",
        help="text (default): the human-readable checklist below. sarif: a SARIF 2.1.0 log of the same "
        "findings, for a code-scanning UI -- ignores --baseline, still honors --fail-on for the exit code",
    )
    policy.add_argument("--output", "-o", help="with --format sarif: write to this file instead of stdout")
    policy.add_argument(
        "--policy-file",
        help="YAML file of user-authored rules (componentClass + property equality conditions), evaluated "
        "alongside the built-in rules above -- see SPEC.md for the file shape",
    )
    policy.set_defaults(func=_run_policy)

    sign = sub.add_parser(
        "sign", help="sign a file (typically a --deterministic scan output) with cosign, key-based, offline"
    )
    sign.add_argument("file")
    sign.add_argument("--key", required=True, help="cosign private key file (cosign.key)")
    sign.add_argument("--bundle", help="output bundle path (default: <file>.bundle)")
    sign.add_argument(
        "--signing-config",
        help="a cosign signing-config JSON file to pass as --signing-config (default: this package's own "
        "vendored, offline-safe config -- override only if you need a different one; see SPEC.md)",
    )
    sign.set_defaults(func=_run_sign)

    verify_signature = sub.add_parser(
        "verify-signature", help="verify a file against a cosign signature bundle, key-based, offline"
    )
    verify_signature.add_argument("file")
    verify_signature.add_argument("--key", required=True, help="cosign public key file (cosign.pub)")
    verify_signature.add_argument("--bundle", help="bundle path (default: <file>.bundle)")
    verify_signature.set_defaults(func=_run_verify_signature)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
