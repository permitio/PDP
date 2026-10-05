#!/usr/bin/env python3
"""Turn a Trivy JSON report on a published image into an actionable verdict.

Triaging a CVE report on a shipped container image always comes down to one question:
can a rebuild fix this, or does someone have to change source? Answered by hand, that
takes a full investigation - and a batch of CVEs that looks like a code emergency is
often an image that has simply not been rebuilt, with every fix already sitting in
Alpine's repos.

Trivy already carries the signal needed to answer that automatically: a finding with a
FixedVersion means upstream shipped a patch. For an Alpine package, `apk upgrade` in the
existing Dockerfile absorbs it on the next build. A finding WITHOUT one cannot be rebuilt
away and needs a pin, a base-image move, a dependency drop, or a waiver.

One wrinkle: "has a fix" is not the same as "a rebuild of THIS repo picks it up". The
OPA binary at /app/bin/opa is compiled from permit-opa's source, so a CVE in one of its
Go modules (google.golang.org/grpc, golang.org/x/crypto, ...) is fixed by bumping
permit-opa's go.mod - a change in a DIFFERENT repository, which no release cut here will
absorb. Two more cases a plain rebuild cannot fix, because the Dockerfile pins them:

  - The Go *stdlib* comes from the `golang:1.27-bookworm@sha256:...` build stage, which is
    digest-pinned. A rebuild reuses the same toolchain; the fix arrives when Dependabot's
    `docker` PR moves the digest and that PR is merged.
  - Python packages are locked in uv.lock, so a rebuild reinstalls the same versions: a
    fixed Python package needs a lock update (Dependabot's `uv` PR, or
    `uv lock --upgrade-package NAME`), and one pinned with `==` in pyproject.toml (e.g.
    starlette, ddtrace, websockets) needs that pin moved first.

Calling any of these "just rebuild" would send someone to cut a release that cannot fix it.

Verdicts:
  CLEAN   - nothing at CRITICAL/HIGH after waivers.
  REBUILD - findings exist and EVERY one is absorbed by rebuilding this repo's image.
            Cut a release; no code change needed.
  SOURCE  - at least one finding needs a change somewhere: no upstream fix exists at all,
            the fix lives in permit-opa's go.mod, the golang base digest has to move, or
            a uv.lock update or an exact pin in pyproject.toml has to move.

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
import re
import sys
from collections import Counter
from pathlib import Path

import tomllib

# Exit code for "the report itself is unusable", distinct from a verdict.
EXIT_UNREADABLE_REPORT = 2


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True, type=Path, help="Trivy JSON report")
    ap.add_argument("--tag", required=True, help="Image tag that was scanned")
    ap.add_argument("--summary", type=Path, help="Append Markdown here ($GITHUB_STEP_SUMMARY)")
    ap.add_argument("--github-output", type=Path, help="Write outputs here ($GITHUB_OUTPUT)")
    return ap.parse_args()


class ReportUnreadableError(Exception):
    """The Trivy report cannot be read, so no verdict can be honestly reported."""


_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==")


def exact_pins(pyproject: Path | None = None) -> set[str]:
    """Names of Python packages pinned with `==` in pyproject.toml.

    Reads `[project].dependencies` and `[tool.uv].override-dependencies` - an override is a pin
    too. Names are normalised the PEP 503 way (lower case, runs of `-_.` folded to `-`), which is
    also how Trivy reports them closely enough to compare.

    Args:
        pyproject: File to read. Defaults to pyproject.toml in the working directory, which is
            the repo root in every workflow that runs this script.

    Returns:
        The set of normalised package names.
    """
    path = pyproject or Path("pyproject.toml")
    if pyproject is None and not path.is_file():
        # Run outside the repo: no pins are known, so a fixed Python package reads as a lock
        # update rather than a pin. Both are SOURCE verdicts; only the owner label differs.
        return set()
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    requirements = list(data.get("project", {}).get("dependencies", []))
    requirements += data.get("tool", {}).get("uv", {}).get("override-dependencies", [])
    pins: set[str] = set()
    for requirement in requirements:
        m = _PIN.match(requirement)
        if m:
            pins.add(_normalise(m.group(1)))
    return pins


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def classify(finding: dict, pins: set[str] | frozenset[str] = frozenset()) -> str:
    """Who has to act on this finding.

    Returns one of 'rebuild', 'permit-opa', 'base-digest', 'lock', 'pinned' or 'no-fix'.
    """
    if not finding["fixed"]:
        return "no-fix"
    if finding["type"] == "gobinary":
        # "stdlib" is Trivy's name for the Go runtime, which comes from the digest-pinned
        # golang build stage: a rebuild reuses it, so the digest has to move first.
        if finding["pkg"] == "stdlib":
            return "base-digest"
        # Every other Go module linked into /app/bin/opa is a permit-opa dependency.
        return "permit-opa"
    if finding["type"] == "python-pkg":
        # uv.lock fixes every Python version, so a rebuild reinstalls the vulnerable one.
        return "pinned" if _normalise(finding["pkg"]) in pins else "lock"
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


def collect(report: Path, pins: set[str] | None = None) -> list[dict]:
    """Flatten Trivy's per-target results, de-duplicating on (package, CVE).

    Trivy reports one row per affected package, so a single OpenSSL CVE shows up twice
    (libcrypto3 + libssl3). Keying on the pair keeps both - they are genuinely separate
    packages to upgrade - while dropping the repeats Trivy emits when the same package
    is discovered through more than one target.
    """
    data = load_report(report)
    if pins is None:
        pins = exact_pins()
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
        f["action"] = classify(f, pins)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    action_order = {"no-fix": 0, "permit-opa": 1, "base-digest": 2, "pinned": 3, "lock": 4, "rebuild": 5}
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


_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _cell(text: str) -> str:
    """Make scanner-supplied text safe inside a Markdown table cell.

    Package names, versions and ids come from the image under scan. A `|`, backtick or
    newline in one would add columns, break the code span or end the row.
    """
    return " ".join(str(text).split()).replace("|", "\\|").replace("`", "'")


def _next_steps(by_action: dict[str, list[dict]]) -> list[str]:
    """One line per kind of action the findings need, in the order a human acts on them."""
    rebuildable = by_action["rebuild"]
    opa = by_action["permit-opa"]
    base = by_action["base-digest"]
    lock = by_action["lock"]
    pinned = by_action["pinned"]
    nofix = by_action["no-fix"]
    steps: list[str] = []
    if rebuildable:
        steps.append(
            f"- Cut a release to clear {len(rebuildable)} finding(s). `release.yml` passes "
            "`no-cache-filters: main`, so the build cannot replay a stale `apk` layer from "
            "the GHA cache."
        )
    if lock:
        steps.append(
            f"- Update {', '.join(sorted({_cell(f['pkg']) for f in lock}))} in uv.lock (merge "
            "Dependabot's `uv` PR, or `uv lock --upgrade-package NAME`), then cut a release."
        )
    if opa:
        steps.append(
            f"- Bump {', '.join(sorted({f['pkg'] for f in opa}))} in permit-opa's `go.mod`, "
            "then rebuild here to pick up the new OPA binary."
        )
    if base:
        steps.append(
            "- Merge the open Dependabot `docker` PR that moves the golang digest "
            "(Dockerfile `opa_build`), then cut a release."
        )
    if pinned:
        steps.append(
            f"- Raise the `==` pin for {', '.join(sorted({_cell(f['pkg']) for f in pinned}))} "
            "in pyproject.toml and run `uv lock` (or waive it with a reachability argument)."
        )
    if nofix:
        steps.append(
            f"- Triage {', '.join(sorted({_cell(f['cve']) for f in nofix}))} by hand - "
            "no released version fixes them yet."
        )
    return steps


def render(tag: str, findings: list[dict], verdict: str) -> str:
    if verdict == "CLEAN":
        return f"## `permitio/pdp-v2:{tag}` - CLEAN\n\nNo CRITICAL/HIGH findings after applying `.trivyignore.yaml`.\n"

    by_action: dict[str, list[dict]] = {
        a: [f for f in findings if f["action"] == a]
        for a in ("rebuild", "permit-opa", "base-digest", "lock", "pinned", "no-fix")
    }
    rebuildable = by_action["rebuild"]
    opa = by_action["permit-opa"]
    base = by_action["base-digest"]
    lock = by_action["lock"]
    pinned = by_action["pinned"]
    nofix = by_action["no-fix"]

    if verdict == "REBUILD":
        headline = (
            "**Every finding is already patched upstream, so this image is stale rather "
            "than broken.** No source change is needed: cutting a release rebuilds it and "
            "`apk upgrade` absorbs the patches."
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
        if base:
            parts.append(
                f"{len(base)} finding(s) are in the Go stdlib, which comes from the "
                "digest-pinned golang build stage - merge Dependabot's `docker` digest PR "
                "for it first, then rebuild"
            )
        if lock:
            parts.append(
                f"{len(lock)} finding(s) are in Python packages locked in uv.lock - a rebuild "
                "reinstalls the same versions, so the lock has to be updated"
            )
        if pinned:
            parts.append(
                f"{len(pinned)} finding(s) are in Python packages pinned with `==` in "
                "pyproject.toml - the pin has to move, then the lock"
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
        f"- Need the golang base digest to move: **{len(base)}**",
        f"- Need a uv.lock update: **{len(lock)}**",
        f"- Need an exact pin in pyproject.toml moved: **{len(pinned)}**",
        f"- No upstream fix available: **{len(nofix)}**",
        "",
        "| Severity | Package | Installed | CVE | Fixed in | Owner |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    owner = {
        "rebuild": "rebuild (this repo)",
        "permit-opa": "**permit-opa go.mod**",
        "base-digest": "**golang base digest**",
        "lock": "**uv.lock**",
        "pinned": "**pyproject.toml pin**",
        "no-fix": "**no fix - needs a decision**",
    }
    for f in findings:
        fixed = f"`{_cell(f['fixed'])}`" if f["fixed"] else "_none available_"
        cve = _cell(f["cve"])
        cve_cell = f"[{cve}](https://avd.aquasec.com/nvd/{cve.lower()})" if _CVE_ID.match(f["cve"]) else cve
        lines.append(
            f"| {_cell(f['severity'])} | `{_cell(f['pkg'])}` | `{_cell(f['installed'])}` | "
            f"{cve_cell} | {fixed} | {owner[f['action']]} |"
        )

    lines += ["", "### Next step", ""]
    lines += _next_steps(by_action)
    return "\n".join(lines) + "\n"


def write_outputs(args: argparse.Namespace, verdict: str, findings: list[dict]) -> None:
    """Write the step outputs every consumer of this script reads.

    `verdict` and `findings` are consumed by scheduled-security-scan.yml; renaming either
    breaks the scheduled scan. `critical`, `high` and `parse_ok` are additive.
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
    job summary and the step outputs - so the failure is visible everywhere a verdict
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
    write_outputs(args, verdict, findings)

    # Exit 0 for every verdict the report supports: the workflow decides pass/fail from
    # the verdict output so that the SARIF upload and artifact steps still run. An
    # unreadable report is the one exception - it is not a verdict.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
