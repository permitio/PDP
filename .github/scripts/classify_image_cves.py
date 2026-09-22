#!/usr/bin/env python3
"""Turn a Trivy JSON report on a published image into an actionable verdict.

Triaging a CVE report on a shipped container image always comes down to one question:
can a rebuild fix this, or does someone have to change source? The 0.9.14 customer
report (PER-15358) took a full manual investigation to answer it - twelve CVEs that
looked like a code emergency turned out to be an image that had not been rebuilt since
2026-08-04, with every fix already sitting in Alpine's repos.

Trivy already carries the signal needed to answer that automatically: a finding with a
FixedVersion means upstream shipped a patch, so `apk upgrade` / `pip install` in the
existing Dockerfile would absorb it on the next build. A finding WITHOUT one cannot be
rebuilt away and needs a pin, a base-image move, a dependency drop, or a waiver.

One wrinkle: "has a fix" is not the same as "a rebuild of THIS repo picks it up". The
OPA binary at /app/bin/opa is compiled from permit-opa's source, so a CVE in one of its
Go modules (google.golang.org/grpc, golang.org/x/crypto, ...) is fixed by bumping
permit-opa's go.mod - a change in a DIFFERENT repository, which no release cut here will
absorb. The Go *stdlib* is the exception: it comes from the floating `golang:1.25-bookworm`
build stage, so a rebuild does upgrade it. The classifier splits these, because calling a
permit-opa dependency "just rebuild" would send someone to cut a release that cannot fix it.

Verdicts:
  CLEAN   - nothing at CRITICAL/HIGH after waivers.
  REBUILD - findings exist and EVERY one is absorbed by rebuilding this repo's image.
            Cut a release; no code change needed.
  SOURCE  - at least one finding needs a change somewhere: no upstream fix exists at all,
            or the fix lives in permit-opa's go.mod.

SOURCE outranks REBUILD: a report can contain both kinds, and the one that needs a human
is the one that should set the verdict.

A report that cannot be read is NOT clean. `--report` pointing at a missing, empty or
truncated file means the scan step failed, and the only safe answer is a loud one: the
script writes `parse_ok=false`, prints a workflow error annotation and exits non-zero.
Reading a zero-byte file as `{}` once turned a broken scan into a green CLEAN run.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

# Exit code for "the report itself is unusable", distinct from a verdict.
EXIT_UNREADABLE_REPORT = 2


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True, type=Path, help="Trivy JSON report")
    ap.add_argument("--tag", required=True, help="Image tag that was scanned")
    ap.add_argument("--summary", type=Path, help="Append Markdown here ($GITHUB_STEP_SUMMARY)")
    ap.add_argument("--github-output", type=Path, help="Write outputs here ($GITHUB_OUTPUT)")
    ap.add_argument(
        "--slack-output",
        type=Path,
        help="Write a short plain-text summary here, ready to drop into a Slack message",
    )
    return ap.parse_args()


class ReportUnreadableError(Exception):
    """The Trivy report cannot be read, so no verdict can be honestly reported."""


def classify(finding: dict) -> str:
    """Who has to act on this finding: 'rebuild', 'permit-opa', or 'no-fix'."""
    if not finding["fixed"]:
        return "no-fix"
    # Go modules linked into /app/bin/opa are permit-opa's dependencies, not ours.
    # "stdlib" is Trivy's name for the Go runtime itself, which DOES come from this
    # repo's golang build stage and so is rebuildable here.
    if finding["type"] == "gobinary" and finding["pkg"] != "stdlib":
        return "permit-opa"
    return "rebuild"


def load_report(report: Path) -> dict:
    """Read the Trivy JSON report, refusing to invent an empty one.

    Args:
        report: Path passed to ``--report``.

    Returns:
        The parsed report.

    Raises:
        ReportUnreadableError: The file is missing, empty, not JSON, or not a JSON object.
            Every message names the file and what to do about it.
    """
    if not report.is_file():
        raise ReportUnreadableError(
            f"{report} does not exist. The Trivy step did not write a report - check whether "
            f"it ran, and that its `output:` matches the --report path."
        )
    raw = report.read_text(encoding="utf-8", errors="replace")
    if not raw.strip():
        raise ReportUnreadableError(
            f"{report} is empty (0 usable bytes). Trivy exited before writing results - "
            f"check the scan step's log for a DB download or image-pull failure."
        )
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReportUnreadableError(
            f"{report} is not valid JSON ({exc}). The scan was interrupted or the file was "
            f"truncated; re-run the scan step."
        ) from exc
    if not isinstance(data, dict):
        raise ReportUnreadableError(
            f"{report} is a JSON {type(data).__name__}, expected an object with `Results`. "
            f"Check that the Trivy step used `format: json`."
        )
    return data


def collect(report: Path) -> list[dict]:
    """Flatten Trivy's per-target results, de-duplicating on (package, CVE).

    Trivy reports one row per affected package, so a single OpenSSL CVE shows up twice
    (libcrypto3 + libssl3). Keying on the pair keeps both - they are genuinely separate
    packages to upgrade - while dropping the repeats Trivy emits when the same package
    is discovered through more than one target.
    """
    data = load_report(report)
    findings: dict[tuple[str, str], dict] = {}
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            pkg = vuln.get("PkgName", "?")
            cve = vuln.get("VulnerabilityID", "?")
            findings.setdefault(
                (pkg, cve),
                {
                    "pkg": pkg,
                    "cve": cve,
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "installed": vuln.get("InstalledVersion") or "?",
                    "fixed": vuln.get("FixedVersion") or "",
                    "title": (vuln.get("Title") or "").strip(),
                    "type": result.get("Type", "?"),
                },
            )
    for f in findings.values():
        f["action"] = classify(f)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    action_order = {"no-fix": 0, "permit-opa": 1, "rebuild": 2}
    return sorted(
        findings.values(),
        key=lambda f: (
            order.get(f["severity"], 9),
            action_order.get(f["action"], 9),
            f["pkg"],
            f["cve"],
        ),
    )


def severity_counts(findings: list[dict]) -> Counter[str]:
    """Count findings by their actual Trivy severity.

    The scan asks Trivy for CRITICAL,HIGH only, but the severity filter is a workflow
    input and `.trivyignore.yaml` does not change it, so a report can legitimately
    arrive carrying MEDIUM rows. Counting "everything that is not CRITICAL" as HIGH
    mislabels them.

    Args:
        findings: Rows from :func:`collect`.

    Returns:
        A Counter keyed by severity name.
    """
    return Counter(f["severity"] for f in findings)


def severity_breakdown(findings: list[dict]) -> str:
    """Render the severity counts as `3 CRITICAL, 9 HIGH`, worst first."""
    counts = severity_counts(findings)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    names = sorted(counts, key=lambda s: (order.get(s, 9), s))
    return ", ".join(f"{counts[name]} {name}" for name in names)


def render(tag: str, findings: list[dict], verdict: str) -> str:
    if verdict == "CLEAN":
        return f"## `permitio/pdp-v2:{tag}` - CLEAN\n\nNo CRITICAL/HIGH findings after applying `.trivyignore.yaml`.\n"

    rebuildable = [f for f in findings if f["action"] == "rebuild"]
    opa = [f for f in findings if f["action"] == "permit-opa"]
    nofix = [f for f in findings if f["action"] == "no-fix"]

    if verdict == "REBUILD":
        headline = (
            "**Every finding is already patched upstream, so this image is stale rather "
            "than broken.** No source change is needed: cutting a release rebuilds it and "
            "`apk upgrade` / `pip install` absorb the patches. This is exactly the "
            "situation behind the 0.9.14 customer report (PER-15358)."
        )
    else:
        parts = []
        if nofix:
            parts.append(
                f"{len(nofix)} finding(s) have **no upstream fix at all** - each needs a "
                "decision: pin or bump the dependency, move the base image, drop the "
                "package, or, if the code path is genuinely unreachable, waive it in BOTH "
                "`.trivyignore.yaml` and `.docker/scout/pdp-v2.vex.json`"
            )
        if opa:
            parts.append(
                f"{len(opa)} finding(s) are in Go modules linked into `/app/bin/opa`, "
                "which is built from **permit-opa** - the fix is a `go.mod` bump in that "
                "repo, so cutting a release here will not clear them"
            )
        headline = "**A rebuild alone will NOT clear this image.** " + "; ".join(parts) + "."

    lines = [
        f"## `permitio/pdp-v2:{tag}` - {verdict}",
        "",
        headline,
        "",
        f"- Findings: **{len(findings)}** ({severity_breakdown(findings)})",
        f"- Cleared by rebuilding this repo: **{len(rebuildable)}**",
        f"- Need a permit-opa `go.mod` bump: **{len(opa)}**",
        f"- No upstream fix available: **{len(nofix)}**",
        "",
        "| Severity | Package | Installed | CVE | Fixed in | Owner |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    owner = {
        "rebuild": "rebuild (this repo)",
        "permit-opa": "**permit-opa go.mod**",
        "no-fix": "**no fix - needs a decision**",
    }
    for f in findings:
        fixed = f"`{f['fixed']}`" if f["fixed"] else "_none available_"
        lines.append(
            f"| {f['severity']} | `{f['pkg']}` | `{f['installed']}` | "
            f"[{f['cve']}](https://avd.aquasec.com/nvd/{f['cve'].lower()}) | {fixed} "
            f"| {owner[f['action']]} |"
        )

    lines += ["", "### Next step", ""]
    if rebuildable:
        lines.append(
            f"- Cut a release to clear {len(rebuildable)} finding(s). `release.yml` passes "
            "`no-cache-filters: main`, so the build cannot replay stale `apk` / `pip` "
            "layers from the GHA cache."
        )
    if opa:
        lines.append(
            f"- Bump {', '.join(sorted({f['pkg'] for f in opa}))} in permit-opa's `go.mod`, "
            "then rebuild here to pick up the new OPA binary."
        )
    if nofix:
        lines.append(
            f"- Triage {', '.join(sorted({f['cve'] for f in nofix}))} by hand - no released version fixes them yet."
        )
    return "\n".join(lines) + "\n"


def slack_escape(text: str) -> str:
    """Escape text for a Slack message body.

    Slack's mrkdwn needs `&`, `<` and `>` escaped - `&` FIRST, or `&lt;` becomes
    `&amp;lt;` and renders literally. `|` has no entity at all, because it separates
    url from label inside `<url|label>`, so it is swapped for U+2502 BOX DRAWINGS
    LIGHT VERTICAL instead.

    Args:
        text: Untrusted text, e.g. a CVE title or a package name.

    Returns:
        Text that renders as written in Slack.
    """
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return escaped.replace("|", "│")


def slack_summary(tag: str, findings: list[dict], verdict: str, limit: int = 600) -> str:
    """Render the one-shot Slack line for this tag.

    Args:
        tag: Image tag that was scanned.
        findings: Rows from :func:`collect`.
        verdict: CLEAN, REBUILD or SOURCE.
        limit: Hard cap on the returned length, so the message stays readable.

    Returns:
        Plain text, already Slack-escaped, at most `limit` characters.
    """
    # Only the untrusted parts are escaped: escaping the assembled line would turn the
    # `->` separator into `-&gt;`.
    image = slack_escape(f"permitio/pdp-v2:{tag}")
    if verdict == "CLEAN":
        return f"{image} -> CLEAN (no CRITICAL/HIGH findings after waivers)"
    head = f"{image} -> {verdict} ({len(findings)} findings: {severity_breakdown(findings)})"
    top = ", ".join(f"{slack_escape(f['cve'])} in {slack_escape(f['pkg'])}" for f in findings[:5])
    if len(findings) > 5:
        top += f", +{len(findings) - 5} more"
    return f"{head}\nTop: {top}"[:limit]


def write_outputs(args: argparse.Namespace, verdict: str, findings: list[dict]) -> None:
    """Write the step outputs every consumer of this script reads.

    `verdict` and `findings` are consumed by scheduled-security-scan.yml; renaming either
    breaks the daily scan. `critical`, `high` and `parse_ok` are additive.
    """
    if not args.github_output:
        return
    counts = severity_counts(findings)
    with args.github_output.open("a", encoding="utf-8") as fh:
        fh.write(f"verdict={verdict}\n")
        fh.write(f"findings={len(findings)}\n")
        fh.write(f"critical={counts['CRITICAL']}\n")
        fh.write(f"high={counts['HIGH']}\n")
        fh.write(f"parse_ok={'false' if verdict == 'ERROR' else 'true'}\n")


def fail_unreadable(args: argparse.Namespace, reason: str) -> int:
    """Report an unusable report as a failure, never as CLEAN.

    Every artifact this script produces still gets written - a workflow annotation, the
    job summary and the Slack line - so the failure is visible everywhere a verdict
    would have been, and the exit code turns the job red.

    Args:
        args: Parsed CLI arguments.
        reason: What is wrong with the report and what to do about it.

    Returns:
        :data:`EXIT_UNREADABLE_REPORT`.
    """
    message = f"Cannot classify permitio/pdp-v2:{args.tag}: {reason}"
    print(f"::error::{message}")
    print(message, file=sys.stderr)
    body = (
        f"## `permitio/pdp-v2:{args.tag}` - SCAN FAILED\n\n"
        f"**The scan report could not be read, so this image has NOT been cleared.**\n\n"
        f"{reason}\n"
    )
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as fh:
            fh.write(body + "\n")
    if args.slack_output:
        args.slack_output.write_text(slack_escape(message), encoding="utf-8")
    write_outputs(args, "ERROR", [])
    return EXIT_UNREADABLE_REPORT


def main() -> int:
    args = parse_args()
    try:
        findings = collect(args.report)
    except ReportUnreadableError as exc:
        return fail_unreadable(args, str(exc))

    if not findings:
        verdict = "CLEAN"
    elif any(f["action"] != "rebuild" for f in findings):
        verdict = "SOURCE"
    else:
        verdict = "REBUILD"

    body = render(args.tag, findings, verdict)
    print(body)

    if args.summary:
        with args.summary.open("a", encoding="utf-8") as fh:
            fh.write(body + "\n")
    if args.slack_output:
        args.slack_output.write_text(slack_summary(args.tag, findings, verdict), encoding="utf-8")
    write_outputs(args, verdict, findings)

    # Exit 0 for every verdict the report supports: the workflow decides pass/fail from
    # the verdict output so that the SARIF upload and artifact steps still run. An
    # unreadable report is the one exception - it is not a verdict.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
