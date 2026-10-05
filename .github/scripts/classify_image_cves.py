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
  - Python packages are installed from uv.lock exactly, so a rebuild installs whatever
    main's lock holds - and this script never decides that version is fixed. Trivy's
    FixedVersion lists only the versions that end each vulnerable range, not the ranges
    themselves, so a version at or above it can still be vulnerable: a range left open with
    no fix, or a regression on a later line. A fixed Python package is therefore owner
    'lock' (Dependabot's `uv` PR, or `uv lock --upgrade-package NAME`), or 'pinned' when
    pyproject.toml pins it with `==` (e.g. starlette, ddtrace, websockets) and the pin has
    to move first - never 'rebuild'. The one call it does make compares the lock with the
    image, not with FixedVersion: when main's lock still holds the very version Trivy
    flagged, a release reinstalls it, so the finding certainly needs the lock (or the pin)
    to move. Otherwise the report's Next step names the version main's uv.lock holds, once
    per package, for a human to judge against each advisory.

Calling any of these "just rebuild" would send someone to cut a release that cannot fix it.

Verdicts:
  CLEAN   - nothing at CRITICAL/HIGH after waivers.
  REBUILD - findings exist and EVERY one has an upstream fix that rebuilding this repo's
            image from main absorbs, such as an Alpine package through `apk upgrade`. Cut
            a release; no code change needed.
  SOURCE  - at least one finding is not known to clear on a rebuild: no upstream fix exists
            at all, the fix lives in permit-opa's go.mod, the golang base digest has to
            move, or it is in a Python package, which needs a uv.lock update or an exact pin
            in pyproject.toml moved unless main's locked version already carries the fix.

SOURCE outranks REBUILD: a report can contain both kinds, and the one that needs a human
is the one that should set the verdict.

pyproject.toml and uv.lock are read from the checkout this script sits in, whatever the
working directory - main, on a scheduled run.

A report that cannot be read is NOT clean. `--report` pointing at a missing, empty or
truncated file, or at JSON not laid out as a Trivy report - no `"SchemaVersion": 2`, which
Trivy's JSON format always writes, as with `{}` or a SARIF file - means the scan step failed,
and the only safe answer is a loud one: the script prints a workflow error annotation, writes
SCAN FAILED to the job summary and exits non-zero. Reading a zero-byte file as `{}` once
turned a broken scan into a green CLEAN run.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections import Counter
from collections.abc import Iterator, Mapping, Set
from pathlib import Path

# Exit code for "the report itself is unusable", distinct from a verdict.
EXIT_UNREADABLE_REPORT = 2

# The `SchemaVersion` Trivy's JSON format writes (`report.SchemaVersion` in Trivy's pkg/report),
# and the only layout this script reads.
TRIVY_SCHEMA_VERSION = 2


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True, type=Path, help="Trivy JSON report")
    ap.add_argument("--tag", required=True, help="Image tag that was scanned")
    ap.add_argument("--summary", type=Path, help="Append Markdown here ($GITHUB_STEP_SUMMARY)")
    return ap.parse_args()


class ReportUnreadableError(Exception):
    """The Trivy report cannot be read, so no verdict can be honestly reported."""


# PEP 508 allows whitespace between the name, the extras and the operator: `foo [x] == 1`.
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==")


def repo_root() -> Path:
    """Return the repository root, derived from this script's location."""
    return Path(__file__).resolve().parents[2]


def exact_pins(pyproject: Path | None = None) -> set[str]:
    """Names of Python packages pinned with `==` in pyproject.toml.

    Reads `[project].dependencies` and `[tool.uv].override-dependencies` - an override is a pin
    too. Names are normalised the PEP 503 way (lower case, runs of `-_.` folded to `-`), which is
    also how Trivy reports them closely enough to compare.

    Args:
        pyproject: File to read. Defaults to the repository's own pyproject.toml, whatever the
            working directory.

    Returns:
        The set of normalised package names.
    """
    path = pyproject or repo_root() / "pyproject.toml"
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    requirements = list(data.get("project", {}).get("dependencies", []))
    requirements += data.get("tool", {}).get("uv", {}).get("override-dependencies", [])
    pins: set[str] = set()
    for requirement in requirements:
        m = _PIN.match(requirement)
        if m:
            pins.add(_normalise(m.group(1)))
    return pins


def locked_versions(lock: Path | None = None) -> dict[str, set[str]]:
    """The versions uv.lock holds for each package.

    A name maps to a set because uv writes one `[[package]]` entry per version when the
    resolution forks on environment markers.

    Args:
        lock: File to read. Defaults to the repository's own uv.lock, whatever the working
            directory.

    Returns:
        Locked versions keyed by normalised package name.
    """
    path = lock or repo_root() / "uv.lock"
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    versions: dict[str, set[str]] = {}
    for package in data.get("package", []):
        if "version" in package:
            versions.setdefault(_normalise(package["name"]), set()).add(package["version"])
    return versions


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# Every action classify() returns, most work first: the order the verdict's table lists them in.
# format_security_report.py ranks the owners of an advisory several packages share by it.
ACTION_ORDER = {"no-fix": 0, "permit-opa": 1, "base-digest": 2, "pinned": 3, "lock": 4, "rebuild": 5}


def classify(finding: dict, pins: Set[str] = frozenset()) -> str:
    """Who has to act on this finding.

    A Python package with a fix is 'lock' or 'pinned', never 'rebuild', whatever main's uv.lock
    holds: see the module docstring for why its version is not compared to Trivy's FixedVersion.

    Args:
        finding: A row with `pkg`, `fixed` and `type` (Trivy's result type).
        pins: Normalised names pinned with `==` in pyproject.toml, from :func:`exact_pins`.

    Returns:
        One of 'rebuild', 'permit-opa', 'base-digest', 'lock', 'pinned' or 'no-fix'.
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
        return "pinned" if _normalise(finding["pkg"]) in pins else "lock"
    return "rebuild"


_RELEASE_ONLY = re.compile(r"^\d+(?:\.\d+)*$")


def _same_version(a: str, b: str) -> bool:
    """Whether two version strings certainly name the same version.

    Equal ignoring case and surrounding space, or plain release numbers whose parts are equal
    as integers once trailing zero parts are dropped, which is how PEP 440 compares release
    numbers: `1.0` and `1.0.0`, and also `1.01` and `1.1`. Anything else - a pre-release, a
    local label, an epoch - has to match exactly, so an unsure answer is "no".
    """
    a, b = a.strip().lower(), b.strip().lower()
    if a == b:
        return True
    if not (_RELEASE_ONLY.match(a) and _RELEASE_ONLY.match(b)):
        return False
    return _release(a) == _release(b)


def _release(version: str) -> list[int]:
    parts = [int(part) for part in version.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return parts


def lock_still_flagged(pkg: str, action: str, locked: Mapping[str, Set[str]], *, installed: str) -> bool:
    """Whether main's uv.lock still holds the version Trivy flagged for a 'lock' or 'pinned' finding.

    True when every version main's lock holds for the package is the scanned image's own
    version: a release reinstalls that very version, so it cannot clear the finding. This
    compares the image's version with the lock's, never with Trivy's FixedVersion.

    Args:
        pkg: The package name as Trivy reports it.
        action: The finding's owner, from :func:`classify`.
        locked: main's uv.lock, from :func:`locked_versions`.
        installed: The version Trivy found in the image (its InstalledVersion).

    Returns:
        False for any other owner and for a package main's uv.lock does not hold.
    """
    versions = locked.get(_normalise(pkg), ())
    if action not in ("lock", "pinned") or not versions:
        return False
    return all(_same_version(version, installed) for version in versions)


def lock_note(pkg: str, action: str, locked: Mapping[str, Set[str]], *, installed: str) -> str:
    """What main's uv.lock holds for a 'lock' or 'pinned' finding, and what to do about it.

    When the lock still holds the version Trivy flagged (:func:`lock_still_flagged`), the note
    says the lock has to move. Otherwise it is context for a human, not a verdict: whether the
    locked version carries the fix is theirs to judge against the advisory. The note covers
    every CVE of the package, each with its own fix, so it never speaks of a single fix.

    Args:
        pkg: The package name as Trivy reports it.
        action: The finding's owner, from :func:`classify`.
        locked: main's uv.lock, from :func:`locked_versions`.
        installed: The version Trivy found in the image (its InstalledVersion).

    Returns:
        One sentence without a final full stop, or '' for any other owner and for a package
        main's uv.lock does not hold.
    """
    name = _normalise(pkg)
    versions = sorted(locked.get(name, ()))
    if action not in ("lock", "pinned") or not versions:
        return ""
    # Only `name` and the versions, both read from main's uv.lock, go into the sentence, so it
    # holds no scanner text.
    held = f"{name} {', '.join(versions)}"
    if action == "lock":
        update = f"run `uv lock --upgrade-package {name}`"
    else:
        update = f"raise the `==` pin for {name} in pyproject.toml and run `uv lock`"
    if lock_still_flagged(pkg, action, locked, installed=installed):
        return f"main's uv.lock still holds {held}, the version Trivy flagged - {update}, then cut a release"
    judged = "that version carries" if len(versions) == 1 else "every one of those versions carries"
    return (
        f"main's uv.lock has {held} - cutting a release clears each finding whose fix {judged}; "
        f"for the rest, {update}, then cut a release"
    )


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


def _require_trivy_schema(data: dict, report: Path | str) -> None:
    """Raise :class:`ReportUnreadableError` unless `SchemaVersion` is the one Trivy's JSON format writes."""
    version = data.get("SchemaVersion")
    if version is None:
        raise ReportUnreadableError(
            f"{report} is not a Trivy JSON report: it has no `SchemaVersion`, which Trivy's JSON format "
            f"always writes. Check that the Trivy step used `format: json` (not `sarif` or a template) and "
            f"that nothing rewrote the file."
        )
    if version != TRIVY_SCHEMA_VERSION:
        found = (
            f"`SchemaVersion` {version}"
            if isinstance(version, int)
            else f"a `SchemaVersion` that is a JSON {type(version).__name__}"
        )
        raise ReportUnreadableError(
            f"{report} has {found}, and these scripts read Trivy's schema {TRIVY_SCHEMA_VERSION}. If Trivy "
            f"changed its JSON layout, update vulnerabilities() in .github/scripts/classify_image_cves.py."
        )


def vulnerabilities(data: dict, report: Path | str) -> Iterator[tuple[dict, dict]]:
    """Walk `Results[].Vulnerabilities[]`, refusing any other layout.

    Trivy's JSON format always writes `"SchemaVersion": 2`, so a report without it - `{}`, a
    SARIF file, anything else that merely parses as JSON - is not one, and reading it as an
    empty report would turn a broken scan into CLEAN. A missing or null `Results` or
    `Vulnerabilities` is an empty list - Trivy leaves them out when there is nothing to list.
    Anything else that is not a list of objects means the file is not a Trivy report either.

    The PR and release scan gate (format_scan_report.py) and the scheduled Slack report
    (format_security_report.py) walk Trivy reports with this too, so all three refuse the
    same files.

    Args:
        data: The report, from :func:`load_report`.
        report: The report's path, or what to call it, named in the error.

    Yields:
        Each (result, vulnerability) pair, in report order.

    Raises:
        ReportUnreadableError: The report has no `SchemaVersion` 2, or some level of the
            layout is not a list of objects.
    """

    def unreadable(what: str, value: object) -> ReportUnreadableError:
        return ReportUnreadableError(
            f"{report} is not laid out as a Trivy JSON report: {what} is a JSON {type(value).__name__}. "
            f"Check that the Trivy step used `format: json` and that nothing rewrote the file."
        )

    _require_trivy_schema(data, report)
    results = data.get("Results")
    if results is None:
        return
    if not isinstance(results, list):
        raise unreadable("`Results`", results)
    for result in results:
        if not isinstance(result, dict):
            raise unreadable("a `Results` entry", result)
        vulns = result.get("Vulnerabilities")
        if vulns is None:
            continue
        if not isinstance(vulns, list):
            raise unreadable("`Vulnerabilities`", vulns)
        for vuln in vulns:
            if not isinstance(vuln, dict):
                raise unreadable("a `Vulnerabilities` entry", vuln)
            yield result, vuln


def collect(
    report: Path,
    pins: Set[str] | None = None,
    locked: Mapping[str, Set[str]] | None = None,
) -> list[dict]:
    """Flatten Trivy's per-target results, de-duplicating on (package, CVE).

    Trivy reports one row per affected package, so a single OpenSSL CVE shows up twice
    (libcrypto3 + libssl3). Keying on the pair keeps both - they are genuinely separate
    packages to upgrade - while dropping the repeats Trivy emits when the same package
    is discovered through more than one target.

    Every field is read as text, so a number or other non-string value in a field cannot crash
    the triage. A layout that is not Trivy's - no `SchemaVersion` 2, `Results` or
    `Vulnerabilities` not a list, or an entry in one that is not an object - raises
    :class:`ReportUnreadableError`, so it is reported as SCAN FAILED rather than as a traceback
    or a CLEAN verdict.

    Args:
        report: Trivy JSON report.
        pins: Exact pins, as :func:`exact_pins` returns. Defaults to the repository's own.
        locked: Locked versions, as :func:`locked_versions` returns. Defaults to the
            repository's own uv.lock.

    Returns:
        One row per (package, CVE), each with its `action`, its `lock_note` and whether
        main's uv.lock still holds the flagged version (`lock_still_flagged`; see
        :func:`lock_note` and :func:`lock_still_flagged`), worst severity first.

    Raises:
        ReportUnreadableError: The report cannot be read, or is not laid out as Trivy's.
    """
    data = load_report(report)
    if pins is None:
        pins = exact_pins()
    if locked is None:
        locked = locked_versions()
    findings: dict[tuple[str, str], dict] = {}
    for result, vuln in vulnerabilities(data, report):
        pkg = str(vuln.get("PkgName") or "?")
        cve = str(vuln.get("VulnerabilityID") or "?")
        findings.setdefault(
            (pkg, cve),
            {
                "pkg": pkg,
                "cve": cve,
                "severity": str(vuln.get("Severity") or "UNKNOWN"),
                "installed": str(vuln.get("InstalledVersion") or "?"),
                "fixed": str(vuln.get("FixedVersion") or ""),
                "title": str(vuln.get("Title") or "").strip(),
                "type": str(result.get("Type") or "?"),
            },
        )
    for f in findings.values():
        f["action"] = classify(f, pins)
        f["lock_note"] = lock_note(f["pkg"], f["action"], locked, installed=f["installed"])
        f["lock_still_flagged"] = lock_still_flagged(f["pkg"], f["action"], locked, installed=f["installed"])
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(
        findings.values(),
        key=lambda f: (
            order.get(f["severity"], 9),
            ACTION_ORDER.get(f["action"], 9),
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
    steps += _lock_notes(lock)
    if unlocked := _without_lock_note(lock):
        steps.append(
            f"- Update {unlocked} in uv.lock (merge Dependabot's `uv` PR, or "
            "`uv lock --upgrade-package NAME`), then cut a release."
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
    steps += _lock_notes(pinned)
    if unlocked := _without_lock_note(pinned):
        steps.append(
            f"- Raise the `==` pin for {unlocked} in pyproject.toml and run `uv lock` (or waive it "
            "with a reachability argument)."
        )
    if nofix:
        steps.append(
            f"- Triage {', '.join(sorted({_cell(f['cve']) for f in nofix}))} by hand - "
            "no released version fixes them yet."
        )
    return steps


def _lock_notes(findings: list[dict]) -> list[str]:
    """One step per package main's uv.lock holds, naming its locked version."""
    return [f"- {note}." for note in sorted({f["lock_note"] for f in findings if f["lock_note"]})]


def _without_lock_note(findings: list[dict]) -> str:
    """The packages main's uv.lock does not hold, comma-separated; '' when there are none."""
    return ", ".join(sorted({_cell(f["pkg"]) for f in findings if not f["lock_note"]}))


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
            "than broken.** No source change is needed: cutting a release rebuilds it from main, "
            "and `apk upgrade` absorbs the patches."
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
        held = [f for f in lock + pinned if f["lock_still_flagged"]]
        lock_open = [f for f in lock if not f["lock_still_flagged"]]
        pinned_open = [f for f in pinned if not f["lock_still_flagged"]]
        if held:
            parts.append(
                f"{len(held)} finding(s) are in Python packages whose flagged version main's uv.lock "
                "still holds, so a release reinstalls it - the lock, or the `==` pin in pyproject.toml, "
                "has to move first"
            )
        if lock_open:
            parts.append(
                f"{len(lock_open)} finding(s) are in Python packages, which a rebuild installs from main's "
                "uv.lock as it is - unless main's locked version carries the fix, the lock has to be "
                "updated (Next step names each locked version)"
            )
        if pinned_open:
            parts.append(
                f"{len(pinned_open)} finding(s) are in Python packages pinned with `==` in "
                "pyproject.toml - unless main's pinned version carries the fix, the pin has to "
                "move, then the lock"
            )
        # Any other Python finding may already be fixed in main's uv.lock; these certainly are not.
        certainly = "will NOT" if nofix or opa or base or held else "might not"
        headline = f"**A rebuild alone {certainly} clear this image.** " + "; ".join(parts) + "."

    lines = [
        f"## `permitio/pdp-v2:{tag}` - {verdict}",
        "",
        headline,
        "",
        f"- Findings: **{len(findings)}** ({severity_breakdown(findings)})",
        f"- Cleared by rebuilding this repo: **{len(rebuildable)}**",
        f"- Need a permit-opa `go.mod` bump: **{len(opa)}**",
        f"- Need the golang base digest to move: **{len(base)}**",
        f"- Need a uv.lock update, unless main's lock already has the fix: **{len(lock)}**",
        f"- Need an exact pin in pyproject.toml moved, unless main's pin has the fix: **{len(pinned)}**",
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


def fail_unreadable(args: argparse.Namespace, reason: str) -> int:
    """Report an unusable report as a failure, never as CLEAN.

    Everything this script produces still gets written - a workflow annotation and the job
    summary - so the failure is visible everywhere a verdict would have been, and the exit
    code turns the job red.

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

    # Exit 0 for every verdict the report supports: the scheduled scan reports findings
    # through its `report` job and never fails a job over them. An unreadable report is the
    # one exception - it is not a verdict.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
