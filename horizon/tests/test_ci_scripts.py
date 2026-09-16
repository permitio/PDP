"""Tests for the CI security-scan helper scripts under .github/scripts/.

They live here on purpose: the required `pytests` job runs exactly
`pytest -s --cache-clear horizon/tests/`, so a test anywhere else would never run in CI.
The scripts are standalone CLI tools rather than a package, so they are loaded by path.
"""

import importlib.util
import json
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / ".github" / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"ci_scripts_{name}", SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fmt = _load("format_scan_report")
classifier = _load("classify_image_cves")
parity = _load("check_waiver_parity")


def _vuln(cve, severity="HIGH", pkg="openssl", fixed="3.5.5-r0", title="something"):
    return {
        "VulnerabilityID": cve,
        "PkgName": pkg,
        "InstalledVersion": "3.5.4-r0",
        "FixedVersion": fixed,
        "Severity": severity,
        "Title": title,
        "PrimaryURL": f"https://avd.aquasec.com/nvd/{cve.lower()}",
    }


def _trivy(*vulns, target_type="alpine"):
    return {"Results": [{"Target": "img", "Type": target_type, "Vulnerabilities": list(vulns)}]}


def _write(path: Path, payload) -> Path:
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- format_scan_report


def test_marker_is_the_very_first_thing_in_the_body():
    body, _ = fmt.format_report(_trivy(_vuln("CVE-2026-1")), None, "permitio/pdp-v2:next")
    assert body.startswith(fmt.MARKER + "\n")


def test_findings_render_a_table_and_correct_counts():
    report = _trivy(
        _vuln("CVE-2026-1", "CRITICAL"),
        _vuln("CVE-2026-2", "HIGH", pkg="libssl3"),
    )
    body, counts = fmt.format_report(report, None, "permitio/pdp-v2:next")
    assert counts == {"critical": 1, "high": 1, "total": 2, "parse_ok": True}
    assert "1 CRITICAL / 1 HIGH" in body
    assert "| CRITICAL | `openssl` | `3.5.4-r0` | [CVE-2026-1]" in body
    assert "https://avd.aquasec.com/nvd/cve-2026-2" in body


def test_clean_report_says_clean():
    body, counts = fmt.format_report(_trivy(), None, "permitio/pdp-v2:next")
    assert counts["total"] == 0
    assert counts["parse_ok"] is True
    assert ":white_check_mark:" in body


def test_results_null_is_not_a_parse_failure():
    body, counts = fmt.format_report({"Results": None}, None, "permitio/pdp-v2:next")
    assert counts == {"critical": 0, "high": 0, "total": 0, "parse_ok": True}
    assert ":white_check_mark:" in body


def test_below_high_findings_are_folded_away():
    report = _trivy(_vuln("CVE-2026-1", "HIGH"), _vuln("CVE-2026-9", "MEDIUM", pkg="busybox"))
    body, counts = fmt.format_report(report, None, "permitio/pdp-v2:next")
    top, fold = body.split("<details>")
    assert "CVE-2026-1" in top
    assert "CVE-2026-1" not in fold
    assert "CVE-2026-9" in fold
    assert counts["high"] == 1


def test_duplicate_rows_are_collapsed_once_not_double_counted():
    report = {
        "Results": [
            {"Type": "alpine", "Vulnerabilities": [_vuln("CVE-2026-1", "CRITICAL")]},
            {"Type": "alpine", "Vulnerabilities": [_vuln("CVE-2026-1", "CRITICAL")]},
        ]
    }
    _, counts = fmt.format_report(report, None, "permitio/pdp-v2:next")
    assert counts["total"] == 1


@pytest.mark.parametrize(
    ("payload", "needle"),
    [
        ("", "is empty"),
        ("   \n", "is empty"),
        ('{"Results": [', "not valid JSON"),
        ("[1, 2, 3]", "expected an object"),
    ],
)
def test_unparseable_reports_fail_closed(tmp_path, payload, needle):
    report = _write(tmp_path / "trivy.json", payload)
    data, error = fmt.read_json(report)
    assert data is None
    assert needle in error
    body, counts = fmt.format_report(None, None, "permitio/pdp-v2:next", trivy_error=error)
    assert counts["parse_ok"] is False
    assert body.startswith(fmt.MARKER + "\n")
    assert "could not be parsed" in body
    assert ":white_check_mark:" not in body


def test_missing_report_file_fails_closed(tmp_path):
    data, error = fmt.read_json(tmp_path / "nope.json")
    assert data is None
    assert "does not exist" in error


def test_table_cells_survive_a_hostile_cve_title():
    hostile = "pipe | newline\nand <img src=x onerror=alert(1)> & more"
    cell = fmt.escape_cell(hostile)
    assert "\n" not in cell
    assert "|" not in cell.replace("\\|", "")
    assert "<img" not in cell
    assert "&amp;lt;" not in cell


def test_hostile_package_name_does_not_add_table_columns():
    report = _trivy(_vuln("CVE-2026-1", "HIGH", pkg="evil | col | col"))
    body, _ = fmt.format_report(report, None, "permitio/pdp-v2:next")
    row = next(line for line in body.splitlines() if "CVE-2026-1" in line and line.startswith("|"))
    assert row.replace("\\|", "").count("|") == 7  # 6 columns -> 7 delimiters


def test_hostile_cve_id_never_becomes_a_markdown_link():
    # escape_cell protects the link TEXT; the TARGET used to be interpolated raw, so an id
    # carrying `)` closed the link early and `|` sheared the cell.
    hostile = "CVE-9999-1|EXTRA) [x](http://evil"
    report = _trivy(_vuln(hostile, "CRITICAL"))
    body, counts = fmt.format_report(report, None, "permitio/pdp-v2:next")
    assert counts["critical"] == 1
    # The id is still SHOWN - it is just never a link TARGET and never live link syntax.
    assert "](https://avd.aquasec.com/nvd/cve-9999-1" not in body
    assert "\\[x\\](http://evil" in body
    row = next(line for line in body.splitlines() if "EXTRA" in line and line.startswith("|"))
    assert row.replace("\\|", "").count("|") == 7  # 6 columns -> 7 delimiters


def test_hostile_scanner_text_cannot_plant_its_own_link():
    # A live [Looks safe](https://evil.example) inside a comment posted under this repo's
    # bot identity is a phishing primitive, so link syntax is escaped in every cell.
    # Uses the Scout `detail` column: the Trivy table renders no free-text field at all.
    rules = [{"id": "CVE-2026-3", "properties": {"security-severity": "9.1"}}]
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"rules": rules}},
                "results": [{"ruleId": "CVE-2026-3", "message": {"text": "[Click here](https://evil.example)"}}],
            }
        ]
    }
    body, _ = fmt.format_report({}, sarif, "img:next")
    assert "Click here" in body
    assert "\\[Click here\\]" in body


def test_non_cve_advisory_ids_render_as_plain_text_not_links():
    body, _ = fmt.format_report(_trivy(_vuln("GHSA-jm78-9fvv-mhgr", "HIGH")), None, "img:next")
    assert "GHSA-jm78-9fvv-mhgr" in body
    assert "](https://avd.aquasec.com/nvd/ghsa" not in body


def test_well_formed_cve_ids_still_link_to_the_advisory():
    assert fmt.cve_link("CVE-2026-50271") == "[CVE-2026-50271](https://avd.aquasec.com/nvd/cve-2026-50271)"


def test_scout_rule_without_a_security_severity_falls_back_instead_of_crashing():
    # `security-severity` is an OPTIONAL SARIF property: absent is normal, not an error.
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "CVE-2026-3", "properties": {}}]}},
                "results": [{"ruleId": "CVE-2026-3", "level": "error"}],
            }
        ]
    }
    _, counts = fmt.format_report({}, sarif, "img:next")
    assert counts == {"critical": 0, "high": 1, "total": 1, "parse_ok": True}


def test_huge_report_is_truncated_under_githubs_comment_size_limit():
    # GitHub 422s an issue-comment body over 65536 characters, which would turn the
    # comment step red on a report that is merely large.
    report = _trivy(
        *(_vuln(f"CVE-2026-{n}", "CRITICAL", pkg=f"package-number-{n}", title="x" * 120) for n in range(4000))
    )
    body, counts = fmt.format_report(report, None, "permitio/pdp-v2:next")
    # The COUNTS are never capped - only the rows are.
    assert counts == {"critical": 4000, "high": 0, "total": 4000, "parse_ok": True}
    assert "4000 CRITICAL / 0 HIGH" in body
    assert len(body) <= fmt.MAX_BODY_CHARS
    assert "more finding(s), omitted to fit GitHub" in body
    assert body.startswith(fmt.MARKER + "\n")


def test_a_report_that_fits_is_not_truncated():
    report = _trivy(*(_vuln(f"CVE-2026-{n}", "CRITICAL") for n in range(20)))
    body, counts = fmt.format_report(report, None, "permitio/pdp-v2:next")
    assert counts["total"] == 20
    assert "omitted to fit GitHub" not in body
    assert "CVE-2026-19" in body


def test_missing_scout_sarif_is_unavailable_not_clean():
    body, counts = fmt.format_report(_trivy(), None, "permitio/pdp-v2:next", scout_error="`scout.sarif` does not exist")
    assert counts["parse_ok"] is False
    assert "Docker Scout results unavailable" in body
    assert "did not run" not in body


def test_scout_not_requested_says_so_without_failing():
    body, counts = fmt.format_report(_trivy(), None, "permitio/pdp-v2:next")
    assert counts["parse_ok"] is True
    assert "Docker Scout did not run" in body


def test_scout_sarif_findings_are_rendered_and_deduplicated_against_trivy():
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "CVE-2026-1", "properties": {"security-severity": "9.8"}},
                            {"id": "CVE-2026-7", "properties": {"security-severity": "7.5"}},
                        ]
                    }
                },
                "results": [
                    {"ruleId": "CVE-2026-1", "message": {"text": "openssl 3.5.4-r0"}},
                    {"ruleId": "CVE-2026-7", "message": {"text": "starlette 0.50.0"}},
                ],
            }
        ]
    }
    body, counts = fmt.format_report(_trivy(_vuln("CVE-2026-1", "CRITICAL")), sarif, "img:next")
    assert counts == {"critical": 1, "high": 1, "total": 2, "parse_ok": True}
    assert "### Docker Scout" in body
    assert "starlette 0.50.0" in body
    assert "Scanned by Trivy, Docker Scout" in body


def test_scout_severity_falls_back_to_the_result_level():
    sarif = {"runs": [{"tool": {"driver": {}}, "results": [{"ruleId": "CVE-2026-3", "level": "error"}]}]}
    _, counts = fmt.format_report({}, sarif, "img:next")
    assert counts["high"] == 1


def test_format_cli_writes_outputs_and_exits_zero(tmp_path):
    report = _write(tmp_path / "trivy.json", _trivy(_vuln("CVE-2026-1", "CRITICAL")))
    out = tmp_path / "body.md"
    gh_out = tmp_path / "gh_output"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "format_scan_report.py"),
            "--trivy",
            str(report),
            "--image",
            "permitio/pdp-v2:next",
            "--out",
            str(out),
            "--github-output",
            str(gh_out),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert out.read_text(encoding="utf-8").startswith(fmt.MARKER)
    outputs = dict(line.split("=", 1) for line in gh_out.read_text().splitlines())
    assert outputs == {"critical": "1", "high": "0", "total": "1", "parse_ok": "true"}


def test_format_cli_still_exits_zero_on_a_zero_byte_report(tmp_path):
    report = _write(tmp_path / "trivy.json", "")
    gh_out = tmp_path / "gh_output"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "format_scan_report.py"),
            "--trivy",
            str(report),
            "--image",
            "permitio/pdp-v2:next",
            "--github-output",
            str(gh_out),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith(fmt.MARKER)
    assert "parse_ok=false" in gh_out.read_text()


# --------------------------------------------------------------------------- classify_image_cves


def test_os_package_with_a_fix_is_rebuildable(tmp_path):
    report = _write(tmp_path / "t.json", _trivy(_vuln("CVE-2026-1", "CRITICAL")))
    findings = classifier.collect(report)
    assert [f["action"] for f in findings] == ["rebuild"]


def test_permit_opa_go_module_forces_source(tmp_path):
    report = _write(
        tmp_path / "t.json",
        _trivy(
            _vuln("CVE-2026-2", "HIGH", pkg="golang.org/x/crypto", fixed="0.56.0"),
            target_type="gobinary",
        ),
    )
    findings = classifier.collect(report)
    assert findings[0]["action"] == "permit-opa"


def test_go_stdlib_is_still_classified_as_rebuildable(tmp_path):
    report = _write(
        tmp_path / "t.json",
        _trivy(_vuln("CVE-2026-3", "HIGH", pkg="stdlib", fixed="1.25.4"), target_type="gobinary"),
    )
    assert classifier.collect(report)[0]["action"] == "rebuild"


def test_finding_without_a_fix_needs_a_decision(tmp_path):
    report = _write(tmp_path / "t.json", _trivy(_vuln("CVE-2026-4", "HIGH", fixed="")))
    assert classifier.collect(report)[0]["action"] == "no-fix"


def test_severity_breakdown_counts_each_severity_not_just_critical():
    findings = [
        {"severity": "CRITICAL"},
        {"severity": "HIGH"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
    ]
    assert classifier.severity_breakdown(findings) == "1 CRITICAL, 2 HIGH, 1 MEDIUM"


def test_render_reports_medium_findings_as_medium(tmp_path):
    report = _write(
        tmp_path / "t.json",
        _trivy(_vuln("CVE-2026-1", "CRITICAL"), _vuln("CVE-2026-9", "MEDIUM", pkg="busybox")),
    )
    findings = classifier.collect(report)
    body = classifier.render("latest", findings, "REBUILD")
    assert "1 CRITICAL, 1 MEDIUM" in body


def test_slack_summary_escapes_and_stays_short(tmp_path):
    report = _write(
        tmp_path / "t.json",
        _trivy(*[_vuln(f"CVE-2026-{i}", "HIGH", pkg=f"p<{i}>&|") for i in range(9)]),
    )
    findings = classifier.collect(report)
    text = classifier.slack_summary("latest", findings, "SOURCE")
    # The `->` separator is ours, not scanner text, so it must survive unescaped.
    assert text.startswith("permitio/pdp-v2:latest -> SOURCE (9 findings: 9 HIGH)")
    assert "+4 more" in text
    assert "&lt;" in text and "&amp;" in text
    assert "|" not in text
    assert "│" in text
    assert "&amp;lt;" not in text
    assert len(text) <= 600


def test_slack_summary_for_a_clean_image():
    assert classifier.slack_summary("latest", [], "CLEAN") == (
        "permitio/pdp-v2:latest -> CLEAN (no CRITICAL/HIGH findings after waivers)"
    )


@pytest.mark.parametrize("payload", ["", "not json at all", '{"Results": ['])
def test_classifier_refuses_to_call_an_unreadable_report_clean(tmp_path, payload):
    report = _write(tmp_path / "trivy.json", payload)
    with pytest.raises(classifier.ReportUnreadableError):
        classifier.collect(report)


def test_classifier_cli_fails_loudly_on_a_zero_byte_report(tmp_path):
    report = _write(tmp_path / "trivy.json", "")
    gh_out = tmp_path / "gh_output"
    slack = tmp_path / "slack.txt"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "classify_image_cves.py"),
            "--report",
            str(report),
            "--tag",
            "latest",
            "--github-output",
            str(gh_out),
            "--slack-output",
            str(slack),
        ],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )
    assert result.returncode == classifier.EXIT_UNREADABLE_REPORT
    assert "::error::" in result.stdout
    outputs = dict(line.split("=", 1) for line in gh_out.read_text().splitlines())
    assert outputs["verdict"] == "ERROR"
    assert outputs["parse_ok"] == "false"
    assert "is empty" in slack.read_text(encoding="utf-8")


def test_classifier_cli_reports_a_verdict_and_exits_zero(tmp_path):
    report = _write(
        tmp_path / "trivy.json",
        _trivy(_vuln("CVE-2026-1", "CRITICAL"), _vuln("CVE-2026-4", "HIGH", fixed="")),
    )
    gh_out = tmp_path / "gh_output"
    slack = tmp_path / "slack.txt"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "classify_image_cves.py"),
            "--report",
            str(report),
            "--tag",
            "latest",
            "--github-output",
            str(gh_out),
            "--slack-output",
            str(slack),
        ],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    outputs = dict(line.split("=", 1) for line in gh_out.read_text().splitlines())
    assert outputs == {
        "verdict": "SOURCE",
        "findings": "2",
        "critical": "1",
        "high": "1",
        "parse_ok": "true",
    }
    assert slack.read_text(encoding="utf-8").startswith("permitio/pdp-v2:latest -> SOURCE")


# --------------------------------------------------------------------------- check_waiver_parity


def test_the_repos_own_waiver_files_are_in_parity():
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "check_waiver_parity.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Waiver parity OK" in result.stdout


def test_warn_days_prints_one_line_and_still_exits_zero():
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "check_waiver_parity.py"), "--warn-days", "36500"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "waiver(s) expire within 36500 days:" in result.stdout
    assert len(result.stdout.strip().splitlines()) == 1


def test_parity_break_names_the_cve_and_the_file_to_fix():
    errors = parity.parity_errors({"CVE-A": date(2030, 1, 1)}, {"CVE-A", "CVE-B"})
    assert len(errors) == 1
    assert "CVE-B" in errors[0]
    assert ".trivyignore.yaml" in errors[0]

    errors = parity.parity_errors({"CVE-A": date(2030, 1, 1), "CVE-C": None}, {"CVE-A"})
    assert len(errors) == 1
    assert "CVE-C" in errors[0]
    assert "pdp-v2.vex.json" in errors[0]


def test_expired_and_undated_waivers_are_errors():
    today = date(2026, 9, 16)
    errors = parity.expiry_errors({"CVE-A": date(2026, 9, 15), "CVE-B": None}, today)
    assert any("CVE-A" in e and "expired on 2026-09-15" in e for e in errors)
    assert any("CVE-B" in e and "no `expired_at:`" in e for e in errors)
    assert parity.expiry_errors({"CVE-A": today}, today) == []


def test_expiring_soon_only_lists_waivers_inside_the_window():
    today = date(2026, 9, 16)
    waivers = {
        "CVE-SOON": today + timedelta(days=10),
        "CVE-LATER": today + timedelta(days=90),
        "CVE-NONE": None,
    }
    assert parity.expiring_soon(waivers, today, 30) == ["CVE-SOON (2026-09-26)"]
    assert parity.expiring_soon(waivers, today, 0) == []


def test_loaders_reject_malformed_waiver_files(tmp_path):
    bad_yaml = _write(tmp_path / "bad.yaml", "vulnerabilities: not-a-list\n")
    with pytest.raises(SystemExit, match="vulnerabilities"):
        parity.load_trivyignore(bad_yaml)

    no_id = _write(tmp_path / "noid.yaml", "vulnerabilities:\n  - statement: hi\n")
    with pytest.raises(SystemExit, match="without an `id:`"):
        parity.load_trivyignore(no_id)

    bad_date = _write(tmp_path / "date.yaml", "vulnerabilities:\n  - id: CVE-A\n    expired_at: 'soon'\n")
    with pytest.raises(SystemExit, match="not a YYYY-MM-DD date"):
        parity.load_trivyignore(bad_date)

    with pytest.raises(SystemExit, match="does not exist"):
        parity.load_vex(tmp_path / "missing.json")

    bad_vex = _write(tmp_path / "vex.json", {"statements": [{"vulnerability": {}}]})
    with pytest.raises(SystemExit, match=r"vulnerability\.name"):
        parity.load_vex(bad_vex)


def test_waiver_loaders_agree_on_the_real_files():
    waivers = parity.load_trivyignore(REPO_ROOT / parity.TRIVYIGNORE)
    vex_ids = parity.load_vex(REPO_ROOT / parity.VEX)
    assert set(waivers) == vex_ids
    assert all(expiry is not None for expiry in waivers.values())
