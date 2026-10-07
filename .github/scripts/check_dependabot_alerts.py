#!/usr/bin/env python3
"""Validate the Dependabot alert feed and list its unwaived critical/high alerts.

WHERE IT RUNS
scheduled-security-scan.yml fetches the open alerts with `gh api` and runs this script
with `--all` in its `dependabot` job: the job log then lists every unwaived
critical/high alert, and an unreadable feed fails the job. The Slack report is built
separately by format_security_report.py, which imports this module for the feed reader
(read_feed, parse_feed, normalize) and the waiver list (waived_cve_ids), so the log and
the report cannot disagree about which alerts count. The script never shells out to
`gh`, so every decision it makes is unit-testable.

WHY THE WAIVER FILTER IS THE WHOLE POINT
At the time of writing, all three open HIGH alerts on this repo - CVE-2026-50271
(ddtrace), CVE-2026-54283 and CVE-2026-48818 (starlette) - are CVEs already triaged and
waived in `.trivyignore.yaml` and `.docker/scout/pdp-v2.vex.json`, because opal-common
0.9.6 caps the dependency that would otherwise fix them. A report that listed "any open
critical/high" would carry the same three CVEs every run, and the channel would be muted
inside a week - at which point the alert that DOES matter arrives in a muted channel. So
the filter is not a nicety: an alert is listed only if the same waiver list the image
scanners read does not already answer it.

The waiver list is keyed by CVE id. An alert carrying only a GHSA id therefore cannot be
matched against it, and is LISTED rather than dropped - being unable to check something
is not the same as having checked it.

THE TIME WINDOW
Without `--all`, only alerts created in the last `--new-since` hours (default 73) are
listed, for a by-hand look at what is new. The summary line still counts the whole
unwaived backlog.

A feed that cannot be read is NOT "nothing new": a missing or malformed alerts file
exits non-zero with a message naming the file.
"""

# NOTE: deliberately no `from __future__ import annotations`. It turns every annotation
# into a string, and @dataclass then resolves those strings through
# `sys.modules[cls.__module__]` - which does not exist for a module loaded by path, the
# way the tests and .github/scripts/ generally load these standalone CLIs. The result is
# an `AttributeError: 'NoneType' object has no attribute '__dict__'` at import time, in
# the tests only. Native annotations need Python 3.10, which the runner and the image
# (3.13) both exceed.
import argparse
import importlib.util
import json
import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

# Exit code for "the alert feed itself is unusable", distinct from "no new alerts".
EXIT_UNREADABLE_FEED = 2

# Dependabot's severities arrive lower-case in the API payload.
REPORTABLE_SEVERITIES = frozenset({"critical", "high"})

# The 72-hour schedule of scheduled-security-scan.yml plus an hour of overlap, so a by-hand
# `--new-since` run covers everything opened since the last scheduled one.
DEFAULT_WINDOW_HOURS = 73

WAIVER_FILE = ".trivyignore.yaml"


def _load_waiver_parity():
    """Import the sibling parity checker so both scripts read waivers the same way.

    `.github/scripts/` is a directory of standalone CLIs, not a package, so there is
    nothing to import by name. Loading the module by path is still worth it: if this
    script parsed `.trivyignore.yaml` itself, a schema change would make the scheduled
    Slack report and the blocking `waiver-parity` pre-commit hook disagree about which
    CVEs are waived - silently, and in the direction that pings the channel.

    Returns:
        The imported ``check_waiver_parity`` module.

    Raises:
        SystemExit: The sibling script is missing or cannot be loaded as a module.
    """
    path = Path(__file__).resolve().parent / "check_waiver_parity.py"
    if not path.is_file():
        raise SystemExit(
            f"{path} is missing. check_dependabot_alerts.py reads the Trivy waiver list "
            f"through it and must not fall back to an unfiltered alert list."
        )
    spec = importlib.util.spec_from_file_location("check_waiver_parity", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"{path} exists but could not be loaded as a Python module.")
    module = importlib.util.module_from_spec(spec)
    # Registered before exec, the way the import system does it: a module missing from
    # sys.modules breaks anything that resolves `sys.modules[cls.__module__]`, which
    # includes @dataclass under string annotations.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


waiver_parity = _load_waiver_parity()


class AlertFeedError(Exception):
    """The Dependabot alert feed cannot be read, so no honest count can be reported."""


@dataclass(frozen=True)
class Alert:
    """One Dependabot alert, reduced to the fields this script decides on."""

    number: int
    state: str
    severity: str
    package: str
    cve_id: str | None
    ghsa_id: str | None
    created_at: datetime

    @property
    def identifier(self) -> str:
        """The best id available: a CVE if the advisory has one, else its GHSA."""
        return self.cve_id or self.ghsa_id or "unidentified advisory"

    def is_waived(self, waived_cves: set[str] | frozenset[str]) -> bool:
        """Whether `.trivyignore.yaml` already answers this alert.

        Args:
            waived_cves: CVE ids read from the Trivy waiver list.

        Returns:
            True only for an alert carrying a CVE id that is on the list. A GHSA-only
            alert can never match a CVE-keyed list, so it counts as unwaived.
        """
        return self.cve_id is not None and self.cve_id in waived_cves


@dataclass(frozen=True)
class Selection:
    """What the filter decided, split the three ways the workflow reports on."""

    reported: list[Alert]
    unwaived: list[Alert]
    waived: list[Alert]


def waived_cve_ids(trivyignore: Path | None = None, today: date | None = None) -> set[str]:
    """Read the CVE ids that are CURRENTLY waived for Trivy.

    A waiver past its `expired_at` is not a waiver any more: Trivy reports the CVE again,
    so the Dependabot alert must come back too.

    Args:
        trivyignore: Waiver file to read. Defaults to the repository's own
            `.trivyignore.yaml`, located the way the parity checker locates it.
        today: Date to judge expiry against. Defaults to today.

    Returns:
        Every waived CVE id whose waiver has not expired.

    Raises:
        SystemExit: The waiver file is missing or malformed, as raised by the loader.
    """
    path = trivyignore or waiver_parity.repo_root() / waiver_parity.TRIVYIGNORE
    today = today or datetime.now(UTC).date()
    return {cve for cve, expires in waiver_parity.load_trivyignore(path).items() if expires is None or expires >= today}


def read_feed(source: Path | None) -> str:
    """Read the raw alerts JSON from a file or from stdin.

    Args:
        source: Path passed to `--alerts`, or None to read stdin.

    Returns:
        The raw text.

    Raises:
        AlertFeedError: The file does not exist, is empty, or nothing was piped in.
    """
    if source is None:
        raw = sys.stdin.read()
        if not raw.strip():
            raise AlertFeedError(
                "No alert JSON on stdin. Pass --alerts PATH, or pipe the output of "
                "`gh api --paginate 'repos/OWNER/REPO/dependabot/alerts?state=open'`."
            )
        return raw
    if not source.is_file():
        raise AlertFeedError(
            f"{source} does not exist. The `gh api .../dependabot/alerts` step did not "
            f"write a feed - check that it ran and that its redirect matches --alerts."
        )
    raw = source.read_text(encoding="utf-8", errors="replace")
    if not raw.strip():
        raise AlertFeedError(
            f"{source} is empty (0 usable bytes). `gh api` exited before writing any "
            f"alerts; check the fetch step's log for a 403 on the alerts endpoint."
        )
    return raw


def parse_feed(raw: str, origin: str) -> list[dict]:
    """Parse the alerts JSON into a list of alert objects.

    Args:
        raw: Raw JSON text.
        origin: Where it came from, named in the error messages.

    Returns:
        The decoded alert list.

    Raises:
        AlertFeedError: The text is not JSON, or is not a JSON array of objects.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AlertFeedError(
            f"{origin} is not valid JSON ({exc}). `gh api` writes its error text to "
            f"stdout on failure, so this usually means the request itself was rejected."
        ) from exc
    if not isinstance(data, list):
        raise AlertFeedError(
            f"{origin} is a JSON {type(data).__name__}, expected an array of alerts. "
            f"An object with a `message` key here is GitHub refusing the request - read it."
        )
    for entry in data:
        if not isinstance(entry, dict):
            raise AlertFeedError(f"{origin} contains a non-object entry: {entry!r}")
    return data


def _parse_created_at(value: object, number: object) -> datetime:
    """Turn an alert's `created_at` into an aware UTC datetime, failing loudly on junk."""
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError as exc:
        raise AlertFeedError(
            f"Alert #{number} has `created_at: {value!r}`, which is not an ISO-8601 "
            f"timestamp. The feed's schema changed; --new-since cannot be applied."
        ) from exc
    if stamp.tzinfo is None:
        return stamp.replace(tzinfo=UTC)
    return stamp.astimezone(UTC)


def _optional_id(value: object) -> str | None:
    """Normalize an advisory id, treating null and the empty string alike."""
    text = str(value).strip() if value is not None else ""
    return text or None


def normalize(entry: dict) -> Alert:
    """Reduce one raw API alert to an :class:`Alert`.

    Args:
        entry: One object from the alerts array.

    Returns:
        The fields this script filters on.

    Raises:
        AlertFeedError: A field the filter depends on is missing. Guessing a default
            here would mean guessing whether to wake somebody up.
    """
    number = entry.get("number", "?")
    advisory = entry.get("security_advisory")
    if not isinstance(advisory, dict):
        raise AlertFeedError(
            f"Alert #{number} has no `security_advisory` object, so its severity is "
            f"unknown. Refusing to treat an unclassifiable alert as harmless."
        )
    severity = str(advisory.get("severity") or "").strip().lower()
    if not severity:
        raise AlertFeedError(f"Alert #{number} has no `security_advisory.severity`.")
    state = str(entry.get("state") or "").strip().lower()
    if not state:
        raise AlertFeedError(f"Alert #{number} has no `state`; cannot tell open from fixed.")
    package = ((entry.get("dependency") or {}).get("package") or {}).get("name") or "?"
    return Alert(
        number=int(number) if str(number).isdigit() else -1,
        state=state,
        severity=severity,
        package=str(package),
        cve_id=_optional_id(advisory.get("cve_id")),
        ghsa_id=_optional_id(advisory.get("ghsa_id")),
        created_at=_parse_created_at(entry.get("created_at"), number),
    )


def select(
    alerts: list[Alert],
    waived_cves: set[str],
    now: datetime,
    window_hours: int | None,
) -> Selection:
    """Split open critical/high alerts into reported, unwaived and waived.

    Args:
        alerts: Every alert from the feed, already normalized.
        waived_cves: CVE ids from `.trivyignore.yaml`.
        now: Reference time for the `--new-since` window.
        window_hours: Report only alerts created within this many hours. None (from
            `--all`) reports the whole unwaived backlog.

    Returns:
        A :class:`Selection`. `reported` is what gets listed, `unwaived` is the
        standing backlog it was drawn from, `waived` is what the filter suppressed.
    """
    severe = [a for a in alerts if a.state == "open" and a.severity in REPORTABLE_SEVERITIES]
    waived: list[Alert] = []
    unwaived: list[Alert] = []
    for alert in severe:
        if alert.is_waived(waived_cves):
            waived.append(alert)
        else:
            unwaived.append(alert)
    # Critical first, then newest first: the alert most likely to need action today
    # heads the list.
    unwaived.sort(key=lambda a: (a.severity != "critical", -a.created_at.timestamp(), a.number))
    if window_hours is None:
        reported = list(unwaived)
    else:
        cutoff = now - timedelta(hours=window_hours)
        reported = [a for a in unwaived if a.created_at >= cutoff]
    return Selection(reported=reported, unwaived=unwaived, waived=waived)


def _one_line(text: str) -> str:
    """Collapse whitespace in feed text, so a value cannot start a new log line.

    The runner reads any log line that starts with `::` as a workflow command; a newline
    inside a package name must not be able to forge one.
    """
    return " ".join(text.split())


def _alert_line(alert: Alert) -> str:
    """Render one reported alert as a log line."""
    line = f"#{alert.number} {alert.severity.upper()} {_one_line(alert.package)} {_one_line(alert.identifier)}"
    if alert.cve_id is None:
        # Fail loud: say why the waiver list could not answer this one.
        line += f" (no CVE id - a GHSA id cannot match the CVE-keyed {WAIVER_FILE})"
    return line


def log_summary(selection: Selection) -> str:
    """Render the job-log summary: the counts, then every reported alert.

    Args:
        selection: Output of :func:`select`.

    Returns:
        Plain text, one alert per line.
    """
    waived = len(selection.waived)
    if not selection.reported:
        return (
            f"No new unwaived CRITICAL/HIGH Dependabot alerts. "
            f"{len(selection.unwaived)} unwaived open alert(s); "
            f"{waived} already waived in {WAIVER_FILE}."
        )
    lines = [
        (
            f"{len(selection.reported)} unwaived CRITICAL/HIGH Dependabot alert(s) need triage "
            f"({waived} other open alert(s) already waived in {WAIVER_FILE}):"
        )
    ]
    lines += [_alert_line(alert) for alert in selection.reported]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--alerts",
        type=Path,
        help="Dependabot alerts JSON array. Reads stdin when omitted.",
    )
    ap.add_argument(
        "--new-since",
        type=int,
        default=DEFAULT_WINDOW_HOURS,
        metavar="HOURS",
        help=f"Report only alerts created in the last N hours (default {DEFAULT_WINDOW_HOURS}).",
    )
    ap.add_argument(
        "--all",
        action="store_true",
        help="Ignore --new-since and report the whole unwaived critical/high backlog.",
    )
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    origin = str(args.alerts) if args.alerts else "The alert JSON on stdin"
    try:
        alerts = [normalize(entry) for entry in parse_feed(read_feed(args.alerts), origin)]
    except AlertFeedError as exc:
        message = f"Cannot read the Dependabot alert feed: {exc}"
        print(f"::error::{message}")
        print(message, file=sys.stderr)
        return EXIT_UNREADABLE_FEED

    selection = select(
        alerts,
        waived_cve_ids(),
        now=datetime.now(UTC),
        window_hours=None if args.all else args.new_since,
    )
    print(log_summary(selection))

    # Exit 0 whatever the alerts say: they reach Slack through the report job, and a red
    # run every time an alert exists would train everyone to ignore it.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
