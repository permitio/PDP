#!/usr/bin/env python3
"""Report NEW, UNWAIVED critical/high Dependabot alerts - and nothing else.

WHY A SCHEDULED POLL
GitHub has no `dependabot_alert` workflow trigger, and Dependabot's own PR runs get a
read-only GITHUB_TOKEN plus an empty Dependabot secret store, so a webhook is not
reachable from there. The only way to turn an alert into a Slack message is to ask the
REST API on a schedule, which is what dependabot-alert-watch.yml does. This script is
the half that decides whether the answer is worth anybody's attention, and it never
shells out to `gh`, so every decision it makes is unit-testable.

WHY THE WAIVER FILTER IS THE WHOLE POINT
At the time of writing, all three open HIGH alerts on this repo - CVE-2026-50271
(ddtrace), CVE-2026-54283 and CVE-2026-48818 (starlette) - are CVEs already triaged and
waived in `.trivyignore.yaml` and `.docker/scout/pdp-v2.vex.json`, because opal-common
0.9.6 caps the dependency that would otherwise fix them. A watcher that alerted on "any
open critical/high" would post the same three CVEs every morning, and the channel would
be muted inside a week - at which point the alert that DOES matter arrives in a muted
channel. So the filter is not a nicety: an alert reaches Slack only if the same waiver
list the image scanners read does not already answer it.

The waiver list is keyed by CVE id. An alert carrying only a GHSA id therefore cannot be
matched against it, and is REPORTED rather than dropped - being unable to check
something is not the same as having checked it.

WHY A TIME WINDOW
`--new-since` keeps a daily cron from re-reporting the same unwaived alert forever. The
default is 25 hours, one hour more than the schedule, so an alert opened between two
runs cannot fall through the gap. `--all` drops the window for `workflow_dispatch` and
for the weekly digest, which want the standing backlog rather than the delta.

A feed that cannot be read is NOT "nothing new": a missing or malformed alerts file
exits non-zero with a message naming the file, and writes no counts at all.
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
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Exit code for "the alert feed itself is unusable", distinct from "no new alerts".
EXIT_UNREADABLE_FEED = 2

# Dependabot's severities arrive lower-case in the API payload.
REPORTABLE_SEVERITIES = frozenset({"critical", "high"})

# One hour of overlap on top of the daily schedule in dependabot-alert-watch.yml.
DEFAULT_WINDOW_HOURS = 25

# Slack renders a wall of text as a wall of text. Past this the message is truncated and
# the run link carries the rest.
SLACK_LIMIT = 900
MAX_SLACK_ALERTS = 8

WAIVER_FILE = ".trivyignore.yaml"


def _load_waiver_parity():
    """Import the sibling parity checker so both scripts read waivers the same way.

    `.github/scripts/` is a directory of standalone CLIs, not a package, so there is
    nothing to import by name. Loading the module by path is still worth it: if this
    watcher parsed `.trivyignore.yaml` itself, a schema change would make the daily
    Slack alert and the blocking `waiver-parity` pre-commit hook disagree about which
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


def slack_escape(text: str) -> str:
    """Escape untrusted text for a Slack message body.

    Slack's mrkdwn needs `&`, `<` and `>` escaped - `&` FIRST, or `&lt;` becomes
    `&amp;lt;` and renders literally. `|` has no entity, because it separates url from
    label inside `<url|label>`, so it is swapped for U+2502 BOX DRAWINGS LIGHT VERTICAL.

    The same three statements exist in classify_image_cves.py and, in shell, in
    notify-slack.yml. Hoisting them into a shared module is the right move and is
    tracked separately; duplicating two statements is cheaper than making this watcher
    import the Trivy image classifier.

    Args:
        text: Untrusted text, e.g. a package name or an advisory id.

    Returns:
        Text that renders as written in Slack.
    """
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return escaped.replace("|", "│")


def waived_cve_ids(trivyignore: Path | None = None) -> set[str]:
    """Read the CVE ids waived for Trivy.

    Args:
        trivyignore: Waiver file to read. Defaults to the repository's own
            `.trivyignore.yaml`, located the way the parity checker locates it.

    Returns:
        Every waived CVE id.

    Raises:
        SystemExit: The waiver file is missing or malformed, as raised by the loader.
    """
    path = trivyignore or waiver_parity.repo_root() / waiver_parity.TRIVYIGNORE
    return set(waiver_parity.load_trivyignore(path))


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
        return stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


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
        A :class:`Selection`. `reported` is what goes to Slack, `unwaived` is the
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
    # Critical first, then newest first: the top of a truncated Slack message should
    # carry the alert most likely to need action today.
    unwaived.sort(key=lambda a: (a.severity != "critical", -a.created_at.timestamp(), a.number))
    if window_hours is None:
        reported = list(unwaived)
    else:
        cutoff = now - timedelta(hours=window_hours)
        reported = [a for a in unwaived if a.created_at >= cutoff]
    return Selection(reported=reported, unwaived=unwaived, waived=waived)


def _alert_line(alert: Alert) -> str:
    """Render one reported alert as a Slack line, escaping the untrusted parts."""
    package = slack_escape(alert.package)
    advisory = slack_escape(alert.identifier)
    line = f"#{alert.number} {alert.severity.upper()} {package} {advisory}"
    if alert.cve_id is None:
        # Fail loud: say why the waiver list could not answer this one.
        line += f" (no CVE id - a GHSA id cannot match the CVE-keyed {WAIVER_FILE})"
    return line


def slack_summary(selection: Selection, limit: int = SLACK_LIMIT) -> str:
    """Render the Slack message body for this run.

    Args:
        selection: Output of :func:`select`.
        limit: Hard cap on the returned length, so one bad day cannot post a novel.

    Returns:
        Plain text, already Slack-escaped, at most `limit` characters.
    """
    waived = len(selection.waived)
    if not selection.reported:
        return (
            f"No new unwaived CRITICAL/HIGH Dependabot alerts. "
            f"{len(selection.unwaived)} unwaived open alert(s); "
            f"{waived} already waived in {WAIVER_FILE}."
        )
    lines = [
        f"{len(selection.reported)} unwaived CRITICAL/HIGH Dependabot alert(s) need triage "
        f"({waived} other open alert(s) already waived in {WAIVER_FILE}):"
    ]
    lines += [_alert_line(alert) for alert in selection.reported[:MAX_SLACK_ALERTS]]
    if len(selection.reported) > MAX_SLACK_ALERTS:
        lines.append(f"+{len(selection.reported) - MAX_SLACK_ALERTS} more")
    return "\n".join(lines)[:limit]


def write_github_output(path: Path, selection: Selection) -> None:
    """Append the counts the workflow branches on to `$GITHUB_OUTPUT`.

    Args:
        path: File named by `--github-output`.
        selection: Output of :func:`select`.
    """
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"new_count={len(selection.reported)}\n")
        fh.write(f"total_unwaived={len(selection.unwaived)}\n")
        fh.write(f"waived_count={len(selection.waived)}\n")


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
    ap.add_argument("--slack-output", type=Path, help="Write the Slack-ready summary here.")
    ap.add_argument(
        "--github-output",
        type=Path,
        help="Append new_count/total_unwaived/waived_count here ($GITHUB_OUTPUT).",
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
        now=datetime.now(timezone.utc),
        window_hours=None if args.all else args.new_since,
    )
    summary = slack_summary(selection)
    print(summary)

    if args.slack_output:
        args.slack_output.write_text(summary, encoding="utf-8")
    if args.github_output:
        write_github_output(args.github_output, selection)

    # Exit 0 whatever the counts say: the workflow decides from new_count whether to
    # post, and a red run every time an alert exists would train everyone to ignore it.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
