#!/usr/bin/env python3
"""Render the unified image-scan report that CI posts as a sticky PR comment.

Two scanners look at the same image and answer slightly different questions: Trivy
enumerates OS and language packages against its own advisory DB, Docker Scout matches
the image's SBOM against Docker's. A PR only gets one comment, so this script merges
both into one body, keyed by the marker below.

The body ALWAYS starts with ``MARKER`` and nothing else - the upsert step matches
existing comments with ``startsWith(marker)``, so a leading blank line silently breaks
dedup and every push adds another comment.

Fail-closed and always-exit-0 are both required here and they do not conflict: an
unparseable report writes ``parse_ok=false`` and renders a loud red body, then exits 0.
Exiting non-zero would skip the comment step and leave the PR silent, which is the one
outcome worse than a red comment. The blocking decision belongs to the workflow's
separate fail step, which fails on ``parse_ok != 'true'``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

MARKER = "<!-- pdp-image-scan -->"
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
BLOCKING_SEVERITIES = ("CRITICAL", "HIGH")
NVD_URL = "https://avd.aquasec.com/nvd/"
_WHITESPACE = re.compile(r"\s+")
# Only an id of exactly this shape is ever put inside a Markdown link target. Anything
# else is printed as plain text - see :func:`cve_link`.
_CVE_ID = re.compile(r"^CVE-\d{4}-\d+$")

# GitHub rejects an issue-comment body over 65536 characters with a 422, which would turn
# the comment step red on a report that is merely large. The body is rendered with
# progressively smaller per-table row caps until it fits; ``None`` means "no cap".
MAX_BODY_CHARS = 65000
ROW_CAPS: tuple[int | None, ...] = (None, 200, 50, 10, 0)


def escape_cell(text: object) -> str:
    """Make untrusted scanner text safe to drop into a Markdown table cell.

    CVE titles come from advisory feeds, not from this repo. A literal ``|`` ends the
    cell and shears the rest of the row off the table; a newline ends the row entirely;
    raw HTML renders as HTML in a GitHub comment; and ``[`` / ``]`` let advisory text
    build its own ``[Looks safe](https://evil.example)`` link inside a comment that
    carries this repo's bot identity. All four are neutralised here.

    This makes scanner text inert, but it does NOT make it safe to interpolate into a
    Markdown link TARGET - ``\\|`` is not an escape inside ``(...)`` and a bare ``)``
    still closes the link. Targets go through :func:`cve_link` instead.

    Args:
        text: Any scanner-supplied value.

    Returns:
        A single-line, table-safe rendering, or ``-`` when the value is empty.
    """
    flat = _WHITESPACE.sub(" ", str(text)).strip()
    # `&` first: escaping it after `<` would turn `&lt;` into `&amp;lt;`.
    flat = flat.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    flat = flat.replace("[", "\\[").replace("]", "\\]")
    return flat.replace("|", "\\|") or "-"


def cve_link(cve: str) -> str:
    """Render an advisory id as a Markdown link, but only when it is safe to link.

    ``escape_cell`` protects the link TEXT and nothing else. A hostile advisory id such
    as ``CVE-9999-1|EXTRA) [x](http://evil`` would still shear the table cell and close
    the link early through the *target*, because a Markdown target is not escaped the
    same way a cell is: ``\\|`` is not an escape inside ``(...)``, and the first ``)``
    ends the target whatever precedes it. Rather than invent an escaping scheme for a
    field that has exactly one legitimate shape, this allows the shape and prints
    everything else as inert text.

    Args:
        cve: Advisory id exactly as the scanner reported it.

    Returns:
        ``[CVE-x-y](https://avd.aquasec.com/nvd/cve-x-y)`` for a well-formed CVE id, and
        the escaped bare id - no link at all - for anything else.
    """
    text = escape_cell(cve)
    if not _CVE_ID.match(cve):
        return text
    return f"[{text}]({NVD_URL}{cve.lower()})"


def _cap_rows(findings: list[dict], cap: int | None) -> tuple[list[dict], int]:
    """Split findings into the ones to render and a count of the ones dropped."""
    if cap is None or len(findings) <= cap:
        return findings, 0
    return findings[:cap], len(findings) - cap


def _omitted_note(dropped: int) -> list[str]:
    """The line that replaces the rows a size cap removed.

    Deliberately NOT "see the job summary": the workflow appends this very same rendered
    body to ``$GITHUB_STEP_SUMMARY``, so pointing there would send a reader to an
    identically truncated table.
    """
    if not dropped:
        return []
    return [
        "",
        f"_... and {dropped} more finding(s), omitted to fit GitHub's 65,536-character "
        f"comment limit. The full set is in this run's scan step logs and in the SARIF "
        f"report uploaded to code scanning._",
    ]


def read_json(path: Path | None) -> tuple[dict | None, str]:
    """Load a scanner report, reporting *why* it is unusable instead of guessing.

    Args:
        path: Report path, or None when the scanner was not asked to run.

    Returns:
        ``(data, "")`` on success, or ``(None, reason)`` where ``reason`` is a message
        naming the file and the problem.
    """
    if path is None:
        return None, "no report path was provided"
    if not path.is_file():
        return None, f"`{path}` does not exist - the scan step did not produce a report"
    raw = path.read_text(encoding="utf-8", errors="replace")
    if not raw.strip():
        return None, f"`{path}` is empty - the scan step wrote 0 usable bytes"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"`{path}` is not valid JSON: {exc}"
    if not isinstance(data, dict):
        return None, f"`{path}` is a JSON {type(data).__name__}, expected an object"
    return data, ""


def collect_trivy(data: dict) -> list[dict]:
    """Flatten ``Results[].Vulnerabilities[]``, de-duplicating on (package, CVE).

    The traversal is shape-anchored on purpose. A recursive walk over the document
    double-counts, because Trivy nests a second ``Severity`` inside each advisory's
    per-source ``CVSS`` block.

    Args:
        data: A parsed Trivy JSON report.

    Returns:
        Findings sorted by severity, then package, then CVE id.
    """
    findings: dict[tuple[str, str], dict] = {}
    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            pkg = vuln.get("PkgName") or "?"
            cve = vuln.get("VulnerabilityID") or "?"
            findings.setdefault(
                (pkg, cve),
                {
                    "pkg": pkg,
                    "cve": cve,
                    "severity": (vuln.get("Severity") or "UNKNOWN").upper(),
                    "installed": vuln.get("InstalledVersion") or "?",
                    "fixed": vuln.get("FixedVersion") or "",
                    "title": (vuln.get("Title") or "").strip(),
                    "type": result.get("Type") or "?",
                },
            )
    return sorted(
        findings.values(),
        key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), f["pkg"], f["cve"]),
    )


def _scout_rules(run: dict) -> dict[str, dict]:
    driver = (run.get("tool") or {}).get("driver") or {}
    return {r["id"]: r for r in driver.get("rules") or [] if isinstance(r, dict) and r.get("id")}


def _scout_severity(rule: dict, result: dict) -> str:
    """Recover a severity name from a SARIF rule, falling back to the result level.

    ``security-severity`` is an OPTIONAL SARIF rule property, so absent is a normal case
    and not an error: Scout omits it on rules it has no CVSS score for. It is handled
    with an explicit ``is None`` test rather than by letting ``float(None)`` raise,
    because the two failure modes deserve the same fallback but only one of them is
    exceptional - and because ``float()`` is typed to reject ``None`` outright, so the
    old ``try`` was a static-analysis error that happened to work at runtime.

    Args:
        rule: The SARIF ``reportingDescriptor`` for this result, or ``{}`` when the run
            declared no matching rule.
        result: The SARIF result itself, used for its ``level`` fallback.

    Returns:
        One of CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN.
    """
    raw = (rule.get("properties") or {}).get("security-severity")
    score: float | None = None
    if raw is not None:
        try:
            score = float(raw)
        except (TypeError, ValueError):
            score = None
    if score is not None:
        for floor, name in ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW")):
            if score >= floor:
                return name
        return "UNKNOWN"
    levels = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}
    return levels.get(result.get("level") or "", "UNKNOWN")


def collect_scout(data: dict) -> list[dict]:
    """Flatten a Docker Scout SARIF document into one row per rule id (CVE).

    Args:
        data: A parsed SARIF document.

    Returns:
        Findings sorted by severity, then CVE id.
    """
    findings: dict[str, dict] = {}
    for run in data.get("runs") or []:
        if not isinstance(run, dict):
            continue
        rules = _scout_rules(run)
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            cve = result.get("ruleId") or "?"
            rule = rules.get(cve, {})
            detail = (result.get("message") or {}).get("text") or ""
            if not detail:
                detail = (rule.get("shortDescription") or {}).get("text") or ""
            findings.setdefault(
                cve,
                {"cve": cve, "severity": _scout_severity(rule, result), "detail": detail[:200]},
            )
    return sorted(findings.values(), key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), f["cve"]))


def tally(trivy_findings: list[dict], scout_findings: list[dict]) -> dict[str, int]:
    """Count findings across both scanners, de-duplicated on CVE id.

    The same CVE reported by Trivy and Scout is one problem, not two, and the worse of
    the two severities wins.

    Args:
        trivy_findings: Rows from :func:`collect_trivy`.
        scout_findings: Rows from :func:`collect_scout`.

    Returns:
        ``{"critical": int, "high": int, "total": int}``.
    """
    worst: dict[str, str] = {}
    for finding in [*trivy_findings, *scout_findings]:
        current = worst.get(finding["cve"])
        rank = SEVERITY_RANK.get(finding["severity"], 9)
        if current is None or rank < SEVERITY_RANK.get(current, 9):
            worst[finding["cve"]] = finding["severity"]
    severities = list(worst.values())
    return {
        "critical": severities.count("CRITICAL"),
        "high": severities.count("HIGH"),
        "total": len(severities),
    }


def _trivy_rows(findings: list[dict], cap: int | None = None) -> list[str]:
    rows = [
        "| Severity | Package | Installed | CVE | Fixed in | Type |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    shown, dropped = _cap_rows(findings, cap)
    for f in shown:
        fixed = f"`{escape_cell(f['fixed'])}`" if f["fixed"] else "_none available_"
        rows.append(
            f"| {escape_cell(f['severity'])} | `{escape_cell(f['pkg'])}` "
            f"| `{escape_cell(f['installed'])}` | {cve_link(f['cve'])} "
            f"| {fixed} | {escape_cell(f['type'])} |"
        )
    return rows + _omitted_note(dropped)


def _scout_rows(findings: list[dict], cap: int | None = None) -> list[str]:
    rows = ["| Severity | CVE | Detail |", "| --- | --- | --- |"]
    shown, dropped = _cap_rows(findings, cap)
    for f in shown:
        rows.append(f"| {escape_cell(f['severity'])} | {cve_link(f['cve'])} | {escape_cell(f['detail'])} |")
    return rows + _omitted_note(dropped)


def _fold(title: str, rows: list[str]) -> list[str]:
    return ["<details>", f"<summary>{title}</summary>", "", *rows, "", "</details>"]


def _split(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    top = [f for f in findings if f["severity"] in BLOCKING_SEVERITIES]
    return top, [f for f in findings if f["severity"] not in BLOCKING_SEVERITIES]


def _trivy_section(findings: list[dict], error: str, cap: int | None = None) -> list[str]:
    lines = ["### Trivy", ""]
    if error:
        return [*lines, f":x: **Trivy report unavailable.** {error}", ""]
    top, rest = _split(findings)
    lines += _trivy_rows(top, cap) if top else ["No CRITICAL or HIGH findings."]
    if rest:
        lines += ["", *_fold(f"{len(rest)} finding(s) below HIGH", _trivy_rows(rest, cap))]
    return [*lines, ""]


def _scout_section(findings: list[dict], error: str, *, requested: bool, cap: int | None = None) -> list[str]:
    lines = ["### Docker Scout", ""]
    if not requested:
        return [*lines, "_Docker Scout did not run for this image._", ""]
    if error:
        return [*lines, f":x: **Docker Scout results unavailable.** {error}", ""]
    top, rest = _split(findings)
    lines += _scout_rows(top, cap) if top else ["No CRITICAL or HIGH findings."]
    if rest:
        lines += ["", *_fold(f"{len(rest)} finding(s) below HIGH", _scout_rows(rest, cap))]
    return [*lines, ""]


def _headline(counts: dict[str, int], trivy_error: str, scout_error: str) -> str:
    if trivy_error:
        return ":x: **Scan report could not be parsed - treat this as a FAILURE, not as clean.**"
    if scout_error:
        return ":x: **Docker Scout results could not be parsed - treat this as a FAILURE, not as clean.**"
    if counts["critical"] or counts["high"]:
        return f":x: **{counts['critical']} CRITICAL / {counts['high']} HIGH** finding(s) after waivers."
    return ":white_check_mark: **No CRITICAL or HIGH findings** after waivers."


def _footer(scanners: list[str]) -> list[str]:
    ran = ", ".join(scanners) if scanners else "no scanner"
    line = f"_Scanned by {ran}. Waivers: `.trivyignore.yaml` + `.docker/scout/pdp-v2.vex.json`._"
    server = os.environ.get("GITHUB_SERVER_URL")
    repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server and repo and run_id:
        line += f" [View run]({server}/{repo}/actions/runs/{run_id})"
    return ["---", "", line]


def format_report(
    trivy: dict | None,
    scout: dict | None,
    image: str,
    *,
    trivy_error: str = "",
    scout_error: str = "",
) -> tuple[str, dict]:
    """Render the sticky-comment body and the counts the workflow gates on.

    Args:
        trivy: Parsed Trivy JSON, or None when it could not be read.
        scout: Parsed Docker Scout SARIF, or None when Scout did not run or failed.
        image: Image reference the scan targeted, e.g. ``permitio/pdp-v2:next``.
        trivy_error: Why the Trivy report is unusable; empty when it parsed.
        scout_error: Why the Scout SARIF is unusable; empty when it parsed or was
            never requested.

    Returns:
        ``(markdown, counts)``. ``counts`` carries ``critical``, ``high``, ``total``
        and ``parse_ok``. ``parse_ok`` is False whenever a requested report could not
        be parsed, and the counts are then meaningless by design. The markdown is kept
        under :data:`MAX_BODY_CHARS` by capping table ROWS only; the counts it reports
        always cover every finding.
    """
    trivy_findings = collect_trivy(trivy) if trivy is not None else []
    scout_requested = scout is not None or bool(scout_error)
    scout_findings = collect_scout(scout) if scout is not None else []
    counts = tally(trivy_findings, scout_findings)
    counts["parse_ok"] = not trivy_error and not scout_error

    scanners = [] if trivy_error else ["Trivy"]
    if scout is not None:
        scanners.append("Docker Scout")

    head = [
        MARKER,
        "## PDP image vulnerability report",
        "",
        f"**Image:** `{escape_cell(image)}`",
        "",
        _headline(counts, trivy_error, scout_error),
        "",
    ]
    # Try the full table first and only shrink if it does not fit. The counts in the
    # headline and in `counts` are NEVER capped - only the per-row detail is - so a
    # truncated body still gates on, and still announces, every finding.
    body = ""
    for cap in ROW_CAPS:
        lines = [
            *head,
            *_trivy_section(trivy_findings, trivy_error, cap),
            *_scout_section(scout_findings, scout_error, requested=scout_requested, cap=cap),
            *_footer(scanners),
        ]
        body = "\n".join(lines) + "\n"
        if len(body) <= MAX_BODY_CHARS:
            break
    return body, counts


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Render the unified image-scan PR comment.")
    ap.add_argument("--trivy", required=True, type=Path, help="Trivy JSON report")
    ap.add_argument("--scout-sarif", type=Path, help="Docker Scout SARIF report (optional)")
    ap.add_argument("--image", required=True, help="Image reference that was scanned")
    ap.add_argument("--out", type=Path, help="Write the Markdown body here as well as stdout")
    ap.add_argument("--github-output", type=Path, help="Append counts here ($GITHUB_OUTPUT)")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    trivy, trivy_error = read_json(args.trivy)
    scout, scout_error = (None, "")
    if args.scout_sarif is not None:
        scout, scout_error = read_json(args.scout_sarif)

    body, counts = format_report(
        trivy,
        scout,
        args.image,
        trivy_error=trivy_error,
        scout_error=scout_error,
    )
    print(body)
    if args.out:
        args.out.write_text(body, encoding="utf-8")
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as fh:
            fh.write(f"critical={counts['critical']}\n")
            fh.write(f"high={counts['high']}\n")
            fh.write(f"total={counts['total']}\n")
            fh.write(f"parse_ok={str(counts['parse_ok']).lower()}\n")
    # Always 0: a non-zero exit here would skip the comment step and leave the PR
    # silent. The workflow's fail step gates on parse_ok / critical / high.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
