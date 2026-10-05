#!/usr/bin/env python3
"""Build the scheduled security scan's single Slack report.

Four sources feed it: Trivy over each published tag, Docker Scout over `latest`, and the
repository's open Dependabot alerts - each reporting CRITICAL/HIGH findings that the
waiver list (.trivyignore.yaml / the OpenVEX doc) does not already answer - plus cargo
audit over Cargo.lock, which reports every RustSec advisory. The same advisory seen by
several sources or tags is ONE line, naming every source that saw it, so agreeing
scanners never read as several problems.

The layout follows permitio/agent-security's report: a headline count, one line per
source, then the high/critical findings with package, advisory link and remediation, and
an "Unscored" list for advisories with no CVSS v3 score.

A source whose report is missing or unreadable is shown as "did not complete" and the
report never claims a clean result while one is missing. Findings are not failures:
this script always exits 0 once it has written a report, and the workflow keeps the run
green when the scans ran. Only a usage error exits non-zero.

Every scanner-supplied string (package names, titles, ids, URLs) is untrusted and is
escaped exactly once, here. The notifier sends the result verbatim.
"""

import argparse
import importlib.util
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unscored": 4}
SEVERE = ("critical", "high")
MAX_LISTED = 15
MAX_TITLE = 120
WAIVER_FILE = ".trivyignore.yaml"

_HTTPS_URL = re.compile(r"^https://[^\s<>|]+$")
_WHITESPACE = re.compile(r"\s+")
_SCOUT_FIELD = re.compile(r"^\s*([A-Za-z][A-Za-z ]*?)\s*:(.*)$")
_PURL = re.compile(r"^pkg:[^/]+/(?P<name>[^@?#]+)(?:@(?P<version>[^?#]+))?")
_MARKDOWN_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")

# What has to happen for a Trivy finding to go away, keyed by classify_image_cves.classify().
# A 'lock' or 'pinned' finding whose package main's uv.lock holds gets
# classify_image_cves.lock_note() instead, which names main's locked version.
_ACTION_HINT = {
    "rebuild": "a release rebuild picks it up",
    "permit-opa": "bump it in permit-opa",
    "base-digest": "needs the golang base-image digest bump",
    "lock": "update it in uv.lock",
    "pinned": "bump the exact pin in pyproject.toml",
}


def _sibling(name: str):
    """Load another script from .github/scripts by path; the directory is not a package."""
    path = SCRIPTS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"{path} is missing or cannot be loaded; format_security_report.py needs it.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


scan_report = _sibling("format_scan_report")
classifier = _sibling("classify_image_cves")
dependabot = _sibling("check_dependabot_alerts")
cargo_audit = _sibling("format_cargo_audit")


@dataclass
class Finding:
    """One advisory affecting one or more packages, as seen by one or more sources."""

    id: str
    severity: str
    score: float | None
    title: str
    url: str
    remediation: str
    packages: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    aliases: set[str] = field(default_factory=set)
    # Who has to act on a Trivy finding (classify_image_cves.classify); '' for any other source.
    action: str = ""
    # A Trivy finding whose image holds the version main's uv.lock still has: its remediation
    # says a release cannot clear it (classify_image_cves.lock_still_flagged).
    lock_still_flagged: bool = False


@dataclass
class Source:
    """One scanner run: its findings, or why it has none to give."""

    name: str
    scope: str
    findings: list[Finding] = field(default_factory=list)
    complete: bool = True
    note: str = ""


def escape_slack(text: str) -> str:
    """Escape text for Slack mrkdwn: `&` first, then `<` and `>`."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def truncate(text: str, limit: int = MAX_TITLE) -> str:
    """Collapse whitespace and cut to `limit` characters, marking the cut."""
    flat = _WHITESPACE.sub(" ", text).strip()
    return flat if len(flat) <= limit else f"{flat[: limit - 1]}…"


def link(url: str, label: str) -> str:
    """A Slack link for an https URL, or the escaped label alone for anything else."""
    safe_label = escape_slack(label).replace("|", "¦")
    return f"<{url}|{safe_label}>" if _HTTPS_URL.match(url) else safe_label


def normalise_severity(value: object, score: float | None = None) -> str:
    """Map any scanner's severity word to critical/high/medium/low/unscored."""
    word = str(value or "").strip().lower()
    if word == "moderate":
        word = "medium"
    if word in SEVERITY_ORDER and word != "unscored":
        return word
    if score is None or score <= 0:
        return "unscored"
    for floor, name in ((9.0, "critical"), (7.0, "high"), (4.0, "medium")):
        if score >= floor:
            return name
    return "low"


def _float(value: object) -> float | None:
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _remediation(fixed: str, hint: str = "") -> str:
    if not fixed:
        return "no fix released"
    return f"fix: {fixed}, {hint}" if hint else f"fix: {fixed}"


# --- Trivy -------------------------------------------------------------------------


def _trivy_score(vuln: dict) -> float | None:
    """The CVSS base score Trivy carries, preferring the source its severity came from."""
    cvss = vuln.get("CVSS") or {}
    if not isinstance(cvss, dict):
        return None
    preferred = [vuln.get("SeveritySource"), "nvd", "ghsa", *cvss.keys()]
    for source in preferred:
        entry = cvss.get(source) if isinstance(source, str) else None
        if isinstance(entry, dict):
            score = _float(entry.get("V3Score")) or _float(entry.get("V40Score"))
            if score is not None:
                return score
    return None


def trivy_source(tag: str, report: Path, pins: set[str], locked: dict[str, set[str]]) -> Source:
    """Findings from one Trivy JSON report on `permitio/pdp-v2:<tag>`.

    The report is walked with classify_image_cves.vulnerabilities(), so a layout the classifier
    refuses - no `SchemaVersion` 2, or an entry that is not an object - makes the source
    incomplete rather than a clean one. Skipping what does not fit would report a broken scan
    as "no high/critical vulnerabilities found" and keep Slack quiet.
    """
    source = Source(name="Trivy", scope=f"pdp-v2:{tag}")
    data, error = scan_report.read_json(report)
    if data is None:
        source.complete, source.note = False, _unreadable(report, error)
        return source
    try:
        rows = list(classifier.vulnerabilities(data, report))
    except classifier.ReportUnreadableError as exc:
        source.complete, source.note = False, _unreadable(report, str(exc))
        return source
    seen: set[tuple[str, str]] = set()
    for result, vuln in rows:
        pkg = str(vuln.get("PkgName") or "?")
        cve = str(vuln.get("VulnerabilityID") or "?")
        if (pkg, cve) in seen:
            continue
        seen.add((pkg, cve))
        fixed = str(vuln.get("FixedVersion") or "")
        installed = str(vuln.get("InstalledVersion") or "?")
        action = classifier.classify({"pkg": pkg, "fixed": fixed, "type": str(result.get("Type") or "?")}, pins)
        hint = classifier.lock_note(pkg, action, locked, installed=installed) or _ACTION_HINT.get(action, "")
        score = _trivy_score(vuln)
        source.findings.append(
            Finding(
                id=cve,
                severity=normalise_severity(vuln.get("Severity"), score),
                score=score,
                title=str(vuln.get("Title") or ""),
                url=str(vuln.get("PrimaryURL") or ""),
                remediation=_remediation(fixed, hint),
                packages=[f"{pkg}@{installed}"],
                sources=[f"Trivy {tag}"],
                action=action,
                lock_still_flagged=classifier.lock_still_flagged(pkg, action, locked, installed=installed),
            )
        )
    return source


# --- Docker Scout --------------------------------------------------------------------


def _scout_fields(message: str) -> dict[str, str]:
    """Parse Scout's `Key : Value` result message into a dict with lower-case keys."""
    fields: dict[str, str] = {}
    for line in message.splitlines():
        match = _SCOUT_FIELD.match(line)
        if match:
            fields[match.group(1).strip().lower()] = match.group(2).strip()
    return fields


def _purl_display(purl: str) -> str:
    match = _PURL.match(purl)
    if not match:
        return purl or "?"
    version = match.group("version")
    return f"{match.group('name')}@{version}" if version else match.group("name")


def _scout_title(rule: dict) -> str:
    """First prose line of the rule's help text; Scout's shortDescription is just the id."""
    help_text = (rule.get("help") or {}).get("text") or ""
    for line in help_text.splitlines():
        text = line.strip().lstrip(">").strip()
        if text and not text.startswith(("#", "|", "```")):
            return _MARKDOWN_LINK.sub(r"\1", text).replace("`", "")
    return ""


def _unreadable(path: Path, reason: str) -> str:
    """Why a report is unusable, naming the file without its path, which only adds noise in Slack.

    read_json's reasons quote the path in backticks; the classifier's name it bare.
    """
    return reason.replace(f"`{path}`", path.name).replace(str(path), path.name)


def scout_source(tag: str, sarif: Path) -> Source:
    """Findings from Docker Scout's VEX-filtered gate SARIF on `permitio/pdp-v2:<tag>`."""
    source = Source(name="Docker Scout", scope=f"pdp-v2:{tag}")
    data, error = scan_report.read_json(sarif)
    if data is None:
        source.complete, source.note = False, _unreadable(sarif, error)
        return source
    for run in data.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = (run.get("tool") or {}).get("driver") or {}
        rules = {r["id"]: r for r in driver.get("rules") or [] if isinstance(r, dict) and r.get("id")}
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            advisory = str(result.get("ruleId") or "?")
            rule = rules.get(advisory, {})
            fields = _scout_fields((result.get("message") or {}).get("text") or "")
            score = _float(fields.get("cvss score")) or _float((rule.get("properties") or {}).get("security-severity"))
            fixed = fields.get("fixed version", "")
            source.findings.append(
                Finding(
                    id=advisory,
                    severity=normalise_severity(fields.get("severity"), score),
                    score=score,
                    title=_scout_title(rule),
                    url=str(rule.get("helpUri") or ""),
                    remediation=_remediation("" if fixed.lower() in ("", "not fixed") else fixed),
                    packages=[_purl_display(fields.get("package", ""))],
                    sources=[f"Docker Scout {tag}"],
                )
            )
    return source


# --- Dependabot ------------------------------------------------------------------------


def _alert_score(advisory: dict) -> float | None:
    severities = advisory.get("cvss_severities") or {}
    for key in ("cvss_v4", "cvss_v3"):
        score = _float((severities.get(key) or {}).get("score"))
        if score is not None:
            return score
    return _float((advisory.get("cvss") or {}).get("score"))


def dependabot_source(alerts: Path | None, waived: set[str]) -> tuple[Source, int]:
    """Unwaived open critical/high Dependabot alerts, and how many the waivers answered."""
    source = Source(name="Dependabot alerts", scope="all ecosystems")
    if alerts is None:
        source.complete, source.note = False, "the alert feed was not fetched"
        return source, 0
    try:
        entries = dependabot.parse_feed(dependabot.read_feed(alerts), str(alerts))
        normalised = [(dependabot.normalize(entry), entry) for entry in entries]
    except dependabot.AlertFeedError as exc:
        source.complete, source.note = False, str(exc)
        return source, 0
    waived_count = 0
    for alert, entry in normalised:
        if alert.state != "open" or alert.severity not in dependabot.REPORTABLE_SEVERITIES:
            continue
        if alert.is_waived(waived):
            waived_count += 1
            continue
        advisory = entry.get("security_advisory") or {}
        package = (entry.get("dependency") or {}).get("package") or {}
        patched = ((entry.get("security_vulnerability") or {}).get("first_patched_version") or {}).get("identifier")
        score = _alert_score(advisory)
        source.findings.append(
            Finding(
                id=alert.identifier,
                severity=normalise_severity(alert.severity, score),
                score=score,
                title=str(advisory.get("summary") or ""),
                url=str(entry.get("html_url") or ""),
                remediation=_remediation(str(patched or "")),
                packages=[f"{package.get('name') or '?'} ({package.get('ecosystem') or '?'})"],
                sources=["Dependabot"],
                aliases={i for i in (alert.cve_id, alert.ghsa_id) if i},
            )
        )
    return source, waived_count


# --- cargo audit ---------------------------------------------------------------------


def cargo_source(report: Path | None) -> tuple[Source, int]:
    """Vulnerable crates from `cargo audit --json`, and how many warnings (unmaintained, yanked) it gave."""
    source = Source(name="cargo audit", scope="Cargo.lock")
    if report is None:
        source.complete, source.note = False, "no report"
        return source, 0
    data, error = scan_report.read_json(report)
    if data is None:
        source.complete, source.note = False, _unreadable(report, error)
        return source, 0
    vulnerabilities = (data.get("vulnerabilities") or {}).get("list")
    if not isinstance(vulnerabilities, list):
        source.complete, source.note = False, "the report has no vulnerability list"
        return source, 0
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            continue
        advisory = entry.get("advisory") or {}
        package = entry.get("package") or {}
        advisory_id = str(advisory.get("id") or "?")
        score = cargo_audit.cvss3_base_score(str(advisory.get("cvss") or ""))
        source.findings.append(
            Finding(
                id=advisory_id,
                severity=normalise_severity(None, score),
                score=score or None,
                title=str(advisory.get("title") or ""),
                url=cargo_audit.advisory_url(advisory),
                remediation=_remediation(", ".join((entry.get("versions") or {}).get("patched") or [])),
                packages=[f"{package.get('name') or '?'}@{package.get('version') or '?'}"],
                sources=["cargo audit"],
                aliases={str(alias) for alias in advisory.get("aliases") or [] if alias},
            )
        )
    warnings = data.get("warnings") or {}
    return source, sum(len(items) for items in warnings.values() if isinstance(items, list))


# --- Merge and render ----------------------------------------------------------------


def _work_rank(finding: Finding) -> tuple[int, int]:
    """How much work a finding's owner needs before the advisory goes away; lower is more.

    classify_image_cves.ACTION_ORDER, except that a 'lock' or 'pinned' finding whose flagged
    version main's uv.lock still holds comes right after 'base-digest', ahead of every other
    'pinned' or 'lock' one: a release certainly cannot clear it, while the others may already be
    fixed in main's lock. The classifier's verdict headline lists them in that order too. A
    finding from another source carries no action and ranks after 'rebuild'.
    """
    if finding.lock_still_flagged:
        return classifier.ACTION_ORDER["pinned"], 0
    return classifier.ACTION_ORDER.get(finding.action, len(classifier.ACTION_ORDER)), 1


def merge(sources: list[Source]) -> list[Finding]:
    """One finding per advisory across every source, keeping the worst severity seen.

    The remediation is that of the owner with the most work left (:func:`_work_rank`), the
    first one seen among equals. One advisory can hit packages with different owners - an
    Alpine package a release rebuild clears and a Python package it cannot - and the line
    must not tell a reader that a release clears it. Likewise a Trivy tag whose image main's
    uv.lock still matches outranks another tag's "cutting a release clears each finding whose
    fix that version carries", which would leave the call open.
    """
    by_id: dict[str, Finding] = {}
    merged: list[Finding] = []
    for finding in (f for s in sources for f in s.findings):
        keys = {finding.id, *finding.aliases} - {"", "?"}
        existing = next((by_id[k] for k in keys if k in by_id), None)
        if existing is None:
            existing = Finding(**{**finding.__dict__, "packages": [], "sources": [], "aliases": set()})
            merged.append(existing)
        elif SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[existing.severity]:
            existing.severity, existing.score = finding.severity, finding.score
        if _work_rank(finding) < _work_rank(existing):
            existing.remediation, existing.action = finding.remediation, finding.action
            existing.lock_still_flagged = finding.lock_still_flagged
        existing.title = existing.title or finding.title
        existing.aliases |= keys
        existing.packages += [p for p in finding.packages if p not in existing.packages]
        existing.sources += [s for s in finding.sources if s not in existing.sources]
        for key in keys:
            by_id[key] = existing
    return sorted(merged, key=lambda f: (SEVERITY_ORDER[f.severity], -(f.score or 0), f.id))


def _count_line(findings: list[Finding]) -> str:
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    parts = [f"{n} {s}" for s, n in counts.items() if n]
    return ", ".join(parts) if parts else "clean"


def source_line(source: Source, extra: str = "") -> str:
    label = f"*{escape_slack(source.name)}* (`{escape_slack(source.scope)}`)"
    if not source.complete:
        note = f": {escape_slack(truncate(source.note))}" if source.note else ""
        return f"• {label}: :warning: did not complete{note}"
    return f"• {label}: {_count_line(source.findings)}{extra}"


def finding_line(finding: Finding) -> str:
    label = finding.severity if finding.score is None else f"{finding.severity} {finding.score:.1f}"
    packages = escape_slack(", ".join(finding.packages) or "?").replace("`", "'")
    pieces = [f"*{label}*", f"`{packages}`"]
    if finding.title:
        pieces.append(escape_slack(truncate(finding.title)))
    pieces.append(link(finding.url, finding.id))
    pieces.append(escape_slack(finding.remediation))
    sources = escape_slack(", ".join(finding.sources))
    return f"• {' — '.join(pieces)} _({sources})_"


def headline(severe: int, unscored: int, *, incomplete: bool) -> str:
    """Plain-text one-liner for the weekly digest; never carries scanner text."""
    if severe:
        noun = "vulnerability" if severe == 1 else "vulnerabilities"
        suffix = " (some scans did not complete)" if incomplete else ""
        return f"{severe} high/critical {noun} found{suffix}"
    if incomplete:
        return "security scan incomplete"
    if unscored:
        return f"no high/critical vulnerabilities; {unscored} unscored to triage"
    return "no high/critical vulnerabilities found"


def _list_section(title: str, findings: list[Finding]) -> list[str]:
    if not findings:
        return []
    lines = ["", title, *(finding_line(f) for f in findings[:MAX_LISTED])]
    if len(findings) > MAX_LISTED:
        lines.append(f"• …and {len(findings) - MAX_LISTED} more (see the run)")
    return lines


def render(repo: str, run_url: str, lines: list[str], findings: list[Finding], *, incomplete: bool) -> str:
    severe = [f for f in findings if f.severity in SEVERE]
    unscored = [f for f in findings if f.severity == "unscored"]
    name = escape_slack(repo)
    if severe:
        top = f":rotating_light: *{name}: {headline(len(severe), 0, incomplete=False)}*"
    elif incomplete:
        top = f":warning: *{name}: security scan incomplete*"
    elif unscored:
        top = f":large_yellow_circle: *{name}: {headline(0, len(unscored), incomplete=False)}*"
    else:
        top = f":white_check_mark: *{name}: no high/critical vulnerabilities found*"
    body = [top]
    if incomplete:
        body.append(":warning: Some scans did not complete, so the results are partial.")
    note = (
        "_Image scanners and Dependabot: critical/high only, after the waivers in `.trivyignore.yaml` "
        "and the OpenVEX doc. cargo audit: every RustSec advisory._"
    )
    body += ["", note, *lines]
    body += _list_section("*High / critical*", severe)
    body += _list_section("*Unscored* (the advisory has no CVSS v3 score; triage manually)", unscored)
    body += ["", link(run_url, "Workflow run")]
    return "\n".join(body)


# --- CLI -----------------------------------------------------------------------------


def _tag_path(value: str) -> tuple[str, Path]:
    tag, sep, path = value.partition("=")
    if not sep or not tag or not path:
        raise argparse.ArgumentTypeError(f"expected TAG=PATH, got {value!r}")
    return tag, Path(path)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Build the scheduled security scan's single Slack report.")
    ap.add_argument("--repo", required=True, help="owner/name, shown in the headline.")
    ap.add_argument("--run-url", required=True, help="Link to the workflow run.")
    ap.add_argument(
        "--trivy",
        action="append",
        type=_tag_path,
        default=[],
        help="TAG=trivy.json, once per tag that was meant to be scanned; a missing file reads as incomplete.",
    )
    ap.add_argument("--scout", type=_tag_path, help="TAG=gate.sarif from the VEX-filtered Scout gate.")
    ap.add_argument("--cargo", type=Path, help="`cargo audit --json` report for Cargo.lock.")
    ap.add_argument("--dependabot", type=Path, help="Open Dependabot alerts JSON (gh api --paginate).")
    ap.add_argument("--out", type=Path, required=True, help="Write the Slack mrkdwn message here.")
    ap.add_argument("--headline-out", type=Path, help="Write the plain one-line headline here.")
    ap.add_argument("--github-output", type=Path, help="Append notify/status/severe/unscored here.")
    return ap.parse_args(argv)


@dataclass
class Report:
    """The rendered message and the counts the workflow branches on."""

    message: str
    headline: str
    severe: int
    unscored: int
    incomplete: bool


def build(args: argparse.Namespace) -> Report:
    pins = classifier.exact_pins()
    locked = classifier.locked_versions()
    sources = [trivy_source(tag, path, pins, locked) for tag, path in args.trivy]
    if not sources:
        sources.append(Source(name="Trivy", scope="published tags", complete=False, note="no tag was scanned"))
    if args.scout:
        sources.append(scout_source(*args.scout))
    else:
        sources.append(Source(name="Docker Scout", scope="pdp-v2:latest", complete=False, note="no report"))
    cargo, warnings = cargo_source(args.cargo)
    alerts, waived = dependabot_source(args.dependabot, dependabot.waived_cve_ids())

    lines = [source_line(s) for s in sources]
    lines.append(source_line(cargo, f" · {warnings} warning(s): unmaintained or yanked crates" if warnings else ""))
    lines.append(source_line(alerts, f" · {waived} waived in {WAIVER_FILE}" if waived else ""))
    sources += [cargo, alerts]
    findings = merge(sources)
    incomplete = any(not s.complete for s in sources)
    severe = sum(1 for f in findings if f.severity in SEVERE)
    unscored = sum(1 for f in findings if f.severity == "unscored")
    return Report(
        message=render(args.repo, args.run_url, lines, findings, incomplete=incomplete),
        headline=headline(severe, unscored, incomplete=incomplete),
        severe=severe,
        unscored=unscored,
        incomplete=incomplete,
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = build(args)
    args.out.write_text(report.message + "\n", encoding="utf-8")
    if args.headline_out:
        args.headline_out.write_text(report.headline + "\n", encoding="utf-8")
    if args.github_output:
        attention = report.severe or report.unscored
        status = "fail" if report.incomplete else ("warn" if attention else "ok")
        notify = "true" if attention or report.incomplete else "false"
        with args.github_output.open("a", encoding="utf-8") as fh:
            fh.write(f"notify={notify}\nstatus={status}\nsevere={report.severe}\nunscored={report.unscored}\n")
    print(report.message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
