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
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True, type=Path, help="Trivy JSON report")
    ap.add_argument("--tag", required=True, help="Image tag that was scanned")
    ap.add_argument("--summary", type=Path, help="Append Markdown here ($GITHUB_STEP_SUMMARY)")
    ap.add_argument("--github-output", type=Path, help="Write outputs here ($GITHUB_OUTPUT)")
    ap.add_argument(
        "--issue-body",
        type=Path,
        default=Path("cve-issue-body.md"),
        help="Where to write the tracking-issue body",
    )
    return ap.parse_args()


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


def collect(report: Path) -> list[dict]:
    """Flatten Trivy's per-target results, de-duplicating on (package, CVE).

    Trivy reports one row per affected package, so a single OpenSSL CVE shows up twice
    (libcrypto3 + libssl3). Keying on the pair keeps both - they are genuinely separate
    packages to upgrade - while dropping the repeats Trivy emits when the same package
    is discovered through more than one target.
    """
    data = json.loads(report.read_text() or "{}")
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


def render(tag: str, findings: list[dict], verdict: str) -> str:
    if verdict == "CLEAN":
        return f"## `permitio/pdp-v2:{tag}` - CLEAN\n\nNo CRITICAL/HIGH findings after applying `.trivyignore.yaml`.\n"

    rebuildable = [f for f in findings if f["action"] == "rebuild"]
    opa = [f for f in findings if f["action"] == "permit-opa"]
    nofix = [f for f in findings if f["action"] == "no-fix"]
    crit = [f for f in findings if f["severity"] == "CRITICAL"]

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
        f"- Findings: **{len(findings)}** ({len(crit)} CRITICAL, {len(findings) - len(crit)} HIGH)",
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
            "`no-cache-filter: main,opa_build`, so the build cannot replay stale `apk` / "
            "`pip` layers from the GHA cache."
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


def main() -> int:
    args = parse_args()
    findings = collect(args.report)

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
    if verdict != "CLEAN":
        args.issue_body.write_text(body, encoding="utf-8")
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as fh:
            fh.write(f"verdict={verdict}\n")
            fh.write(f"findings={len(findings)}\n")

    # Always exit 0: the workflow decides pass/fail from the verdict output so that the
    # SARIF upload and issue steps still run.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
