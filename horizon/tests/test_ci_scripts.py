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


def _vuln(cve, severity="HIGH", pkg="openssl", fixed="3.5.5-r0", title="something", *, installed="3.5.4-r0"):
    return {
        "VulnerabilityID": cve,
        "PkgName": pkg,
        "InstalledVersion": installed,
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


def test_non_string_trivy_fields_are_read_as_text():
    vuln = {"VulnerabilityID": 2026, "PkgName": 7, "InstalledVersion": 1, "FixedVersion": 2.5}
    vuln |= {"Severity": 9, "Title": 4}
    [row] = fmt.collect_trivy({"Results": [{"Type": 0, "Vulnerabilities": [vuln]}]})
    assert row == {
        "pkg": "7",
        "cve": "2026",
        "severity": "9",
        "installed": "1",
        "fixed": "2.5",
        "title": "4",
        "type": "?",
    }


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


def test_go_stdlib_needs_the_golang_base_digest_to_move(tmp_path):
    # The golang build stage is digest-pinned, so a rebuild reuses the same toolchain.
    report = _write(
        tmp_path / "t.json",
        _trivy(_vuln("CVE-2026-3", "HIGH", pkg="stdlib", fixed="1.26.9"), target_type="gobinary"),
    )
    assert classifier.collect(report, pins=set())[0]["action"] == "base-digest"


# A uv.lock as main might hold it; "forked" is locked at two versions, one per resolution fork.
MAINS_LOCK = {"httpx": {"0.28.1"}, "starlette": {"0.50.0"}, "typing-extensions": {"4.14.0"}, "forked": {"1.0", "2.0"}}


@pytest.mark.parametrize(
    ("pkg", "installed", "fixed", "action"),
    [
        # Trivy's FixedVersion does not say which versions above it are still vulnerable, so
        # however main's uv.lock compares to it, a fixed Python package is never a rebuild.
        pytest.param("httpx", "0.28.1", "0.28.2", "lock", id="lock-holds-the-image-version"),
        pytest.param("httpx", "0.28.0", "9.9.9", "lock", id="lock-below-the-fix"),
        pytest.param("httpx", "0.28.0", "0.28.1", "lock", id="lock-at-the-fix"),
        pytest.param("httpx", "0.27.0", "0.27.5", "lock", id="lock-above-the-fix"),
        pytest.param("httpx", "0.27.0", "0.27.2, 0.28.1", "lock", id="lock-at-one-of-several-fixes"),
        pytest.param("forked", "0.1", "0.5", "lock", id="every-fork-above-the-fix"),
        pytest.param("httpx", "0.28.0", "not a version", "lock", id="unparsable-fix"),
        pytest.param("Typing_Extensions", "4.13.0", "4.14.0", "lock", id="name-spelled-differently"),
        pytest.param("not-locked", "1.0.0", "1.0.1", "lock", id="not-in-the-lock"),
        # An `==` pin makes the owner the pin, wherever main's pinned version stands.
        pytest.param("Starlette", "0.49.0", "0.51.0", "pinned", id="pin-below-the-fix"),
        pytest.param("starlette", "0.49.0", "0.50.0", "pinned", id="pin-at-the-fix"),
        pytest.param("starlette", "0.49.0", "0.49.1", "pinned", id="pin-above-the-fix"),
    ],
)
def test_a_fixed_python_package_is_lock_or_pinned_whatever_mains_lock_holds(tmp_path, pkg, installed, fixed, action):
    report = _write(
        tmp_path / "t.json",
        _trivy(_vuln("CVE-2026-5", pkg=pkg, fixed=fixed, installed=installed), target_type="python-pkg"),
    )
    assert classifier.collect(report, pins={"starlette"}, locked=MAINS_LOCK)[0]["action"] == action


def test_a_python_package_without_a_fix_still_needs_a_decision(tmp_path):
    report = _write(
        tmp_path / "t.json",
        _trivy(_vuln("CVE-2026-5", pkg="httpx", fixed="", installed="0.28.1"), target_type="python-pkg"),
    )
    [finding] = classifier.collect(report, pins=set(), locked=MAINS_LOCK)
    assert finding["action"] == "no-fix"
    assert finding["lock_note"] == ""


ONE_VERSION = "if that version carries the fix"
EVERY_VERSION = "if every one of those versions carries the fix"
UPGRADE = "run `uv lock --upgrade-package {}`"


@pytest.mark.parametrize(
    ("pkg", "action", "held", "judged", "update"),
    [
        ("httpx", "lock", "httpx 0.28.1", ONE_VERSION, UPGRADE.format("httpx")),
        # Trivy's spelling is looked up, and named, the way uv.lock normalises it.
        ("Typing_Extensions", "lock", "typing-extensions 4.14.0", ONE_VERSION, UPGRADE.format("typing-extensions")),
        (
            "starlette",
            "pinned",
            "starlette 0.50.0",
            ONE_VERSION,
            "raise the `==` pin for starlette in pyproject.toml and run `uv lock`",
        ),
        ("forked", "lock", "forked 1.0, 2.0", EVERY_VERSION, UPGRADE.format("forked")),
    ],
)
def test_lock_note_names_mains_locked_version(pkg, action, held, judged, update):
    assert classifier.lock_note(pkg, action, MAINS_LOCK) == (
        f"main's uv.lock has {held} - {judged}, cutting a release clears this; otherwise {update}, then cut a release"
    )


@pytest.mark.parametrize(
    ("pkg", "action"),
    [
        # Not in main's lock: say nothing about the lock at all.
        ("not-locked", "lock"),
        ("not-locked", "pinned"),
        # In main's lock, but not a finding the lock decides.
        ("httpx", "rebuild"),
        ("httpx", "no-fix"),
        ("httpx", "permit-opa"),
    ],
)
def test_lock_note_is_empty_when_mains_lock_has_nothing_to_say(pkg, action):
    assert classifier.lock_note(pkg, action, MAINS_LOCK) == ""


def test_collect_reads_non_string_report_fields_as_text(tmp_path):
    numbers = {"VulnerabilityID": 2026, "PkgName": 7, "InstalledVersion": 1, "FixedVersion": [2], "Title": 404}
    httpx = _vuln("CVE-2026-5", pkg="httpx", fixed=0.29, installed=28) | {"Severity": 7}
    report = _write(tmp_path / "t.json", _trivy(numbers, httpx, target_type="python-pkg"))

    findings = classifier.collect(report, pins=set(), locked=MAINS_LOCK)

    rows = {f["cve"]: {k: f[k] for k in ("pkg", "severity", "installed", "fixed", "title", "action")} for f in findings}
    assert rows == {
        "2026": {"pkg": "7", "severity": "UNKNOWN", "installed": "1", "fixed": "[2]", "title": "404", "action": "lock"},
        "CVE-2026-5": {
            "pkg": "httpx",
            "severity": "7",
            "installed": "28",
            "fixed": "0.29",
            "title": "something",
            "action": "lock",
        },
    }
    assert "main's uv.lock has httpx 0.28.1" in classifier.render("latest", findings, "SOURCE")


def test_locked_versions_reads_every_package_by_normalised_name(tmp_path):
    lock = _write(
        tmp_path / "uv.lock",
        "version = 1\n"
        "[[package]]\n"
        'name = "typing-extensions"\n'
        'version = "4.14.0"\n'
        "[[package]]\n"
        'name = "Foo_Bar"\n'
        'version = "1.0"\n'
        "[[package]]\n"
        'name = "foo-bar"\n'
        'version = "2.0"\n',
    )
    assert classifier.locked_versions(lock) == {"typing-extensions": {"4.14.0"}, "foo-bar": {"1.0", "2.0"}}


def test_pins_and_lock_default_to_the_repo_files_from_any_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert "starlette" in classifier.exact_pins()
    assert classifier.locked_versions()["starlette"]


@pytest.mark.parametrize(
    ("requirement", "pins"),
    [
        ("foo==1.0", {"foo"}),
        ("foo == 1.0", {"foo"}),
        ("foo[extra]==1.0", {"foo"}),
        ("foo [extra] == 1.0", {"foo"}),
        ("Foo.Bar==1.0 ; python_version >= '3.13'", {"foo-bar"}),
        ("foo>=1.0", set()),
        ("foo~=1.0", set()),
    ],
)
def test_exact_pins_follows_pep_508_spacing(tmp_path, requirement, pins):
    pyproject = _write(tmp_path / "pyproject.toml", f"[project]\ndependencies = [{json.dumps(requirement)}]\n")
    assert classifier.exact_pins(pyproject) == pins


def test_exact_pins_reads_dependencies_and_uv_overrides(tmp_path):
    pyproject = _write(
        tmp_path / "pyproject.toml",
        "[project]\n"
        'dependencies = ["starlette==0.50.0", "ddtrace[opentracing]==3.19.8", "httpx>=0.27",\n'
        '  # "pydantic==2",\n'
        "]\n"
        "[dependency-groups]\n"
        'dev = ["pytest==8.0.0"]\n'
        "[tool.uv]\n"
        'override-dependencies = ["aiofiles==24.1.0"]\n',
    )
    assert classifier.exact_pins(pyproject) == {"starlette", "ddtrace", "aiofiles"}


def test_exact_pins_reads_the_repo_pyproject():
    pins = classifier.exact_pins(REPO_ROOT / "pyproject.toml")
    assert {"starlette", "ddtrace", "websockets", "aiofiles"} <= pins
    assert "fastapi" not in pins


def test_classifier_table_cells_survive_hostile_scanner_text(tmp_path):
    report = _write(
        tmp_path / "t.json",
        _trivy(_vuln("CVE-2026-7|x", "HIGH", pkg="evil|pkg`\nrow", fixed="1|2")),
    )
    body = classifier.render("next", classifier.collect(report, pins=set()), "REBUILD")
    row = next(line for line in body.splitlines() if "evil" in line)
    assert row.count(" | ") == 5  # still exactly six cells
    assert "](https://" not in row  # a malformed id is not turned into a link


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


@pytest.mark.parametrize("payload", ["", "not json at all", '{"Results": ['])
def test_classifier_refuses_to_call_an_unreadable_report_clean(tmp_path, payload):
    report = _write(tmp_path / "trivy.json", payload)
    with pytest.raises(classifier.ReportUnreadableError):
        classifier.collect(report)


def _python_report(tmp_path, *cves, pkg="httpx", fixed="0.28.1"):
    vulns = [_vuln(cve, pkg=pkg, fixed=fixed, installed="0.28.0") for cve in cves]
    return _write(tmp_path / "t.json", _trivy(*vulns, target_type="python-pkg"))


def test_a_lock_only_report_names_uv_lock_and_mains_locked_version_once_per_package(tmp_path):
    # main's lock is AT the fix, and the finding is still the lock's to settle.
    report = _python_report(tmp_path, "CVE-2026-6", "CVE-2026-7")
    findings = classifier.collect(report, pins=set(), locked={"httpx": {"0.28.1"}})
    body = classifier.render("latest", findings, "SOURCE")
    rows = [line for line in body.splitlines() if "`httpx`" in line]
    assert len(rows) == 2
    assert all(row.endswith("| **uv.lock** |") for row in rows)
    assert "**A rebuild alone may not clear this image.** 2 finding(s) are in Python packages" in body
    assert "- Need a uv.lock update, unless main's lock already has the fix: **2**" in body
    assert "- Cleared by rebuilding this repo: **0**" in body
    note = (
        "- main's uv.lock has httpx 0.28.1 - if that version carries the fix, cutting a release clears "
        "this; otherwise run `uv lock --upgrade-package httpx`, then cut a release."
    )
    assert body.count(note) == 1
    assert "Update httpx in uv.lock" not in body


@pytest.mark.parametrize(
    ("pins", "locked", "step"),
    [
        pytest.param(
            set(),
            {},
            "- Update httpx in uv.lock (merge Dependabot's `uv` PR, or `uv lock --upgrade-package NAME`), "
            "then cut a release.",
            id="lock",
        ),
        pytest.param(
            {"httpx"},
            {},
            "- Raise the `==` pin for httpx in pyproject.toml and run `uv lock` (or waive it with a "
            "reachability argument).",
            id="pinned",
        ),
    ],
)
def test_a_package_mains_lock_does_not_hold_gets_no_word_about_the_lock(tmp_path, pins, locked, step):
    findings = classifier.collect(_python_report(tmp_path, "CVE-2026-6"), pins=pins, locked=locked)
    body = classifier.render("latest", findings, "SOURCE")
    assert step in body
    assert "main's uv.lock has" not in body


def test_a_pinned_report_names_mains_pinned_version(tmp_path):
    report = _python_report(tmp_path, "CVE-2026-6", pkg="starlette", fixed="0.50.0")
    findings = classifier.collect(report, pins={"starlette"}, locked={"starlette": {"0.50.0"}})
    body = classifier.render("latest", findings, "SOURCE")
    row = next(line for line in body.splitlines() if "`starlette`" in line)
    assert row.endswith("| **pyproject.toml pin** |")
    assert (
        "- main's uv.lock has starlette 0.50.0 - if that version carries the fix, cutting a release clears "
        "this; otherwise raise the `==` pin for starlette in pyproject.toml and run `uv lock`, then cut a release."
    ) in body
    assert "Raise the `==` pin" not in body


def test_a_finding_a_rebuild_cannot_clear_outranks_the_python_maybe(tmp_path):
    vulns = [
        _vuln("CVE-2026-6", pkg="httpx", fixed="0.28.1"),
        _vuln("CVE-2026-8", pkg="golang.org/x/net", fixed="0.41.0"),
    ]
    report = _write(
        tmp_path / "t.json",
        {
            "Results": [
                {"Target": "py", "Type": "python-pkg", "Vulnerabilities": vulns[:1]},
                {"Target": "opa", "Type": "gobinary", "Vulnerabilities": vulns[1:]},
            ]
        },
    )
    body = classifier.render("latest", classifier.collect(report, pins=set(), locked={}), "SOURCE")
    assert "**A rebuild alone will NOT clear this image.**" in body


def _classify_cli(report: Path, summary: Path) -> subprocess.CompletedProcess:
    """Run the classifier the way the scheduled scan does, from a directory outside the repo."""
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "classify_image_cves.py"),
            "--report",
            str(report),
            "--tag",
            "latest",
            "--summary",
            str(summary),
        ],
        capture_output=True,
        text=True,
        cwd=report.parent,
        check=False,
    )


def test_classifier_cli_fails_loudly_on_a_zero_byte_report(tmp_path):
    report = _write(tmp_path / "trivy.json", "")
    summary = tmp_path / "summary.md"
    result = _classify_cli(report, summary)
    assert result.returncode == classifier.EXIT_UNREADABLE_REPORT
    assert "::error::" in result.stdout
    assert "is empty" in result.stderr
    assert summary.read_text().startswith("## `permitio/pdp-v2:latest` - SCAN FAILED\n")
    assert "has NOT been cleared" in summary.read_text()


def test_classifier_cli_reports_a_verdict_and_exits_zero(tmp_path):
    report = _write(
        tmp_path / "trivy.json",
        _trivy(_vuln("CVE-2026-1", "CRITICAL"), _vuln("CVE-2026-4", "HIGH", fixed="")),
    )
    summary = tmp_path / "summary.md"
    result = _classify_cli(report, summary)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("## `permitio/pdp-v2:latest` - SOURCE\n")
    assert "- Findings: **2** (1 CRITICAL, 1 HIGH)" in result.stdout
    assert summary.read_text() == result.stdout


HTTPX_IN_MAINS_LOCK = ", ".join(sorted(classifier.locked_versions()["httpx"]))


@pytest.mark.parametrize(
    ("installed", "fixed"),
    [
        pytest.param(HTTPX_IN_MAINS_LOCK, "99.0.0", id="lock-holds-the-image-version"),
        pytest.param("0.0.1", "99.0.0", id="lock-below-the-fix"),
        pytest.param("0.0.1", HTTPX_IN_MAINS_LOCK, id="lock-at-the-fix"),
        pytest.param("0.0.1", "0.0.2", id="lock-above-the-fix"),
    ],
)
def test_classifier_cli_never_calls_a_python_finding_a_rebuild(tmp_path, installed, fixed):
    report = _write(
        tmp_path / "trivy.json",
        _trivy(_vuln("CVE-2026-6", pkg="httpx", fixed=fixed, installed=installed), target_type="python-pkg"),
    )
    result = _classify_cli(report, tmp_path / "summary.md")
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("## `permitio/pdp-v2:latest` - SOURCE\n")
    row = next(line for line in result.stdout.splitlines() if "`httpx`" in line)
    assert row.endswith("| **uv.lock** |")
    assert f"- main's uv.lock has httpx {HTTPX_IN_MAINS_LOCK} - if " in result.stdout


# --------------------------------------------------------------------------- check_waiver_parity


def _waiver_tree(tmp_path, expires="2030-01-01"):
    """A minimal repo tree with one waiver in both files.

    The real waiver files are checked by the pre-commit hook. The unit tests use their
    own, so they never fail because a real waiver expired or was removed.
    """
    _write(
        tmp_path / parity.TRIVYIGNORE,
        f"vulnerabilities:\n  - id: CVE-2026-1\n    expired_at: {expires}\n",
    )
    (tmp_path / parity.VEX).parent.mkdir(parents=True)
    _write(tmp_path / parity.VEX, {"statements": [{"vulnerability": {"name": "CVE-2026-1"}}]})
    return tmp_path


def _run_parity(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "check_waiver_parity.py"), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_parity_cli_passes_on_matching_files(tmp_path):
    root = _waiver_tree(tmp_path)
    result = _run_parity("--root", str(root), "--today", "2026-10-01")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Waiver parity OK" in result.stdout


def test_parity_cli_fails_once_a_waiver_has_expired(tmp_path):
    root = _waiver_tree(tmp_path, expires="2026-09-30")
    result = _run_parity("--root", str(root), "--today", "2026-10-01")
    assert result.returncode == 1
    assert "CVE-2026-1" in result.stdout
    assert "expired on 2026-09-30" in result.stdout


def test_warn_days_prints_one_line_and_still_exits_zero(tmp_path):
    root = _waiver_tree(tmp_path)
    result = _run_parity("--root", str(root), "--today", "2026-10-01", "--warn-days", "36500")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 waiver(s) expire within 36500 days: CVE-2026-1 (2030-01-01)" in result.stdout
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
