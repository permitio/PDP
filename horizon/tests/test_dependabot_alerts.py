"""Tests for .github/scripts/check_dependabot_alerts.py.

They live here because the required `pytests` job runs `pytest horizon/tests/`, so a
test anywhere else would never run in CI. The script is a standalone CLI rather than a
package, so it is loaded by path - and registered in ``sys.modules`` while it is, which
is what a real import does and what ``@dataclass`` needs.

The load-bearing test in this file is the waiver one. Every open HIGH Dependabot alert
on this repo is a CVE already waived in `.trivyignore.yaml`; if the filter regresses,
the daily watch posts the same three CVEs every morning until somebody mutes the
channel, and the next alert that matters arrives in a muted channel.
"""

import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / ".github" / "scripts" / "check_dependabot_alerts.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


watch = _load("ci_scripts_check_dependabot_alerts", SCRIPT)

NOW = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
WAIVED = {"CVE-2026-50271", "CVE-2026-54283", "CVE-2026-48818"}


def _raw(
    number=1,
    severity="high",
    state="open",
    package="starlette",
    cve="CVE-2026-99999",
    ghsa="GHSA-aaaa-bbbb-cccc",
    created=None,
):
    """Build one raw alert in the shape GET /repos/{o}/{r}/dependabot/alerts returns."""
    return {
        "number": number,
        "state": state,
        "created_at": (created or NOW).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dependency": {"package": {"ecosystem": "pip", "name": package}},
        "security_advisory": {"severity": severity, "cve_id": cve, "ghsa_id": ghsa},
    }


def _select(*raws, waived=WAIVED, window=25, now=NOW):
    alerts = [watch.normalize(entry) for entry in raws]
    return watch.select(alerts, set(waived), now=now, window_hours=window)


# --------------------------------------------------------------------------- the filter


def test_waived_alerts_are_excluded_from_the_report():
    selection = _select(
        _raw(number=11, cve="CVE-2026-50271", package="ddtrace"),
        _raw(number=10, cve="CVE-2026-54283"),
        _raw(number=8, cve="CVE-2026-48818"),
    )
    assert selection.reported == []
    assert selection.unwaived == []
    assert len(selection.waived) == 3


def test_unwaived_critical_and_high_are_reported():
    selection = _select(
        _raw(number=20, severity="critical", cve="CVE-2026-11111", package="jinja2"),
        _raw(number=21, severity="high", cve="CVE-2026-22222", package="requests"),
    )
    assert [a.number for a in selection.reported] == [20, 21]
    assert len(selection.unwaived) == 2
    assert selection.waived == []


def test_waived_and_unwaived_in_the_same_feed_are_split():
    selection = _select(
        _raw(number=8, cve="CVE-2026-48818"),
        _raw(number=30, cve="CVE-2026-33333", package="urllib3"),
    )
    assert [a.number for a in selection.reported] == [30]
    assert [a.number for a in selection.waived] == [8]


def test_medium_and_low_are_ignored_even_when_unwaived():
    selection = _select(
        _raw(number=9, severity="low", cve="CVE-2026-54282"),
        _raw(number=7, severity="medium", cve="CVE-2026-48817"),
        _raw(number=6, severity="moderate", cve="CVE-2026-00001"),
    )
    assert selection.reported == []
    assert selection.unwaived == []
    assert selection.waived == []


def test_closed_alerts_are_ignored_even_at_critical():
    for state in ("fixed", "dismissed", "auto_dismissed"):
        selection = _select(_raw(number=40, severity="critical", state=state, cve="CVE-2026-4"))
        assert selection.reported == [], state
        assert selection.unwaived == [], state


def test_critical_sorts_above_high_so_truncation_keeps_the_worst():
    selection = _select(
        _raw(number=1, severity="high", cve="CVE-2026-1"),
        _raw(number=2, severity="critical", cve="CVE-2026-2"),
    )
    assert [a.number for a in selection.reported] == [2, 1]


# --------------------------------------------------------------------------- the window


def test_alert_inside_the_window_is_reported():
    selection = _select(_raw(cve="CVE-2026-7", created=NOW - timedelta(hours=24, minutes=59)))
    assert len(selection.reported) == 1


def test_alert_exactly_on_the_window_boundary_is_reported():
    # `>= cutoff`, not `>`: an alert created at the exact boundary must not fall between
    # two runs of a daily cron.
    selection = _select(_raw(cve="CVE-2026-7", created=NOW - timedelta(hours=25)))
    assert len(selection.reported) == 1


def test_alert_just_outside_the_window_is_not_reported_but_still_counted():
    selection = _select(
        _raw(cve="CVE-2026-7", created=NOW - timedelta(hours=25, seconds=1)),
    )
    assert selection.reported == []
    assert len(selection.unwaived) == 1


def test_all_mode_ignores_the_window():
    selection = _select(_raw(cve="CVE-2026-7", created=NOW - timedelta(days=90)), window=None)
    assert len(selection.reported) == 1


# --------------------------------------------------------------------------- GHSA-only


def test_ghsa_only_alert_is_reported_not_silently_dropped():
    selection = _select(_raw(number=50, cve=None, ghsa="GHSA-zzzz-yyyy-xxxx"))
    assert [a.number for a in selection.reported] == [50]


def test_ghsa_only_alert_says_why_the_waiver_list_could_not_answer_it():
    selection = _select(_raw(number=50, cve=None, ghsa="GHSA-zzzz-yyyy-xxxx"))
    summary = watch.slack_summary(selection)
    assert "GHSA-zzzz-yyyy-xxxx" in summary
    assert "no CVE id" in summary
    assert ".trivyignore.yaml" in summary


def test_a_null_cve_id_is_not_mistaken_for_a_waived_empty_string():
    # `"" in waived_cves` would be False anyway, but only by luck; assert the intent.
    alert = watch.normalize(_raw(cve=None, ghsa="GHSA-1"))
    assert alert.cve_id is None
    assert alert.is_waived({""}) is False


# --------------------------------------------------------------------------- feed errors


def test_empty_array_is_a_clean_result_not_an_error():
    selection = _select()
    assert selection.reported == []
    assert watch.slack_summary(selection).startswith("No new unwaived")


def test_malformed_json_fails_loudly(tmp_path):
    bad = tmp_path / "alerts.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(watch.AlertFeedError) as exc:
        watch.parse_feed(bad.read_text(encoding="utf-8"), str(bad))
    assert "not valid JSON" in str(exc.value)


def test_a_json_object_instead_of_an_array_is_an_error_naming_the_refusal():
    # This is what `gh api` writes to stdout when the token lacks the permission.
    raw = json.dumps({"message": "Resource not accessible by integration"})
    with pytest.raises(watch.AlertFeedError) as exc:
        watch.parse_feed(raw, "the feed")
    assert "expected an array" in str(exc.value)


def test_missing_file_is_an_error_naming_the_file(tmp_path):
    missing = tmp_path / "nope.json"
    with pytest.raises(watch.AlertFeedError) as exc:
        watch.read_feed(missing)
    assert str(missing) in str(exc.value)


def test_empty_file_is_an_error_not_an_empty_feed(tmp_path):
    empty = tmp_path / "alerts.json"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(watch.AlertFeedError) as exc:
        watch.read_feed(empty)
    assert "empty" in str(exc.value)


def test_alert_without_a_severity_is_an_error_not_a_harmless_alert():
    with pytest.raises(watch.AlertFeedError) as exc:
        watch.normalize({"number": 3, "state": "open", "created_at": "2026-01-01T00:00:00Z"})
    assert "security_advisory" in str(exc.value)


def test_alert_without_a_state_is_an_error():
    entry = _raw()
    del entry["state"]
    with pytest.raises(watch.AlertFeedError) as exc:
        watch.normalize(entry)
    assert "state" in str(exc.value)


def test_unparseable_created_at_is_an_error():
    entry = _raw()
    entry["created_at"] = "last tuesday"
    with pytest.raises(watch.AlertFeedError) as exc:
        watch.normalize(entry)
    assert "ISO-8601" in str(exc.value)


# --------------------------------------------------------------------------- Slack text


def test_slack_escapes_ampersand_first_then_angle_brackets():
    assert watch.slack_escape("a & b < c > d") == "a &amp; b &lt; c &gt; d"


def test_slack_escape_does_not_double_escape_the_ampersand():
    assert "&amp;lt;" not in watch.slack_escape("<x>")


def test_slack_escape_swaps_the_pipe_for_a_lookalike():
    assert watch.slack_escape("a|b") == "a│b"


def test_untrusted_package_name_is_escaped_in_the_summary():
    selection = _select(_raw(number=60, package="<!channel>|evil&", cve="CVE-2026-8"))
    summary = watch.slack_summary(selection)
    assert "<!channel>" not in summary
    assert "&lt;!channel&gt;│evil&amp;" in summary


def test_summary_is_capped_and_folds_the_tail_into_a_count():
    raws = [_raw(number=n, cve=f"CVE-2026-{n}", package=f"pkg-{n}") for n in range(30)]
    selection = _select(*raws)
    summary = watch.slack_summary(selection)
    assert len(summary) <= watch.SLACK_LIMIT
    assert f"+{30 - watch.MAX_SLACK_ALERTS} more" in summary


def test_summary_respects_an_explicit_limit():
    raws = [_raw(number=n, cve=f"CVE-2026-{n}") for n in range(30)]
    assert len(watch.slack_summary(_select(*raws), limit=80)) == 80


def test_quiet_summary_reports_the_waived_count_so_silence_is_explainable():
    selection = _select(_raw(number=8, cve="CVE-2026-48818"))
    summary = watch.slack_summary(selection)
    assert "No new unwaived" in summary
    assert "1 already waived" in summary


# --------------------------------------------------------------------------- waiver load


def test_waived_ids_come_from_the_real_trivyignore():
    ids = watch.waived_cve_ids()
    assert ids, ".trivyignore.yaml produced no waivers; the alert filter would be inert."
    assert all(i.startswith(("CVE-", "GHSA-")) for i in ids)


def test_waived_ids_can_be_read_from_an_explicit_file(tmp_path):
    waiver = tmp_path / ".trivyignore.yaml"
    waiver.write_text(
        "vulnerabilities:\n  - id: CVE-2026-1\n    expired_at: 2099-01-01\n",
        encoding="utf-8",
    )
    assert watch.waived_cve_ids(waiver) == {"CVE-2026-1"}


# --------------------------------------------------------------------------- the CLI


def _run(args, stdin=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        input=stdin,
        check=False,
    )


def test_cli_reports_an_unwaived_alert_and_writes_both_outputs(tmp_path):
    feed = tmp_path / "alerts.json"
    feed.write_text(json.dumps([_raw(number=77, cve="CVE-2026-90001")]), encoding="utf-8")
    slack = tmp_path / "slack.txt"
    outputs = tmp_path / "gh.txt"
    result = _run(
        [
            "--alerts",
            str(feed),
            "--all",
            "--slack-output",
            str(slack),
            "--github-output",
            str(outputs),
        ]
    )
    assert result.returncode == 0, result.stderr
    assert "#77 HIGH" in slack.read_text(encoding="utf-8")
    written = dict(line.split("=", 1) for line in outputs.read_text().splitlines())
    assert written == {"new_count": "1", "total_unwaived": "1", "waived_count": "0"}


def test_cli_suppresses_an_alert_waived_in_the_real_trivyignore(tmp_path):
    waived_id = sorted(watch.waived_cve_ids())[0]
    feed = tmp_path / "alerts.json"
    feed.write_text(json.dumps([_raw(number=78, cve=waived_id)]), encoding="utf-8")
    outputs = tmp_path / "gh.txt"
    result = _run(["--alerts", str(feed), "--all", "--github-output", str(outputs)])
    assert result.returncode == 0, result.stderr
    written = dict(line.split("=", 1) for line in outputs.read_text().splitlines())
    assert written == {"new_count": "0", "total_unwaived": "0", "waived_count": "1"}


def test_cli_reads_stdin_when_no_alerts_path_is_given():
    result = _run([], stdin="[]")
    assert result.returncode == 0, result.stderr
    assert "No new unwaived" in result.stdout


def test_cli_exits_non_zero_and_writes_no_counts_on_an_unreadable_feed(tmp_path):
    outputs = tmp_path / "gh.txt"
    result = _run(["--alerts", str(tmp_path / "missing.json"), "--github-output", str(outputs)])
    assert result.returncode == watch.EXIT_UNREADABLE_FEED
    assert "::error::" in result.stdout
    assert "does not exist" in result.stderr
    # Silence in $GITHUB_OUTPUT is what stops the workflow reading a broken fetch as
    # `new_count=0`.
    assert not outputs.exists()


def test_cli_exits_non_zero_on_a_permission_error_body(tmp_path):
    feed = tmp_path / "alerts.json"
    feed.write_text('{"message": "Resource not accessible by integration"}', encoding="utf-8")
    result = _run(["--alerts", str(feed)])
    assert result.returncode == watch.EXIT_UNREADABLE_FEED
    assert "expected an array" in result.stderr
