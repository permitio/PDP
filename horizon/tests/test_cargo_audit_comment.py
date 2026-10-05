"""Tests for .github/scripts/format_cargo_audit.py, the cargo audit PR comment."""

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "format_cargo_audit.py"


def _load():
    spec = importlib.util.spec_from_file_location("ci_scripts_format_cargo_audit", SCRIPT)
    assert spec is not None, f"cannot load {SCRIPT}"
    assert spec.loader is not None, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = _load()

HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"  # 7.5
MEDIUM = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"  # 4.8


def _vuln(rustsec, cvss=None, *, name="h2", version="0.3.27", title="h2 issue", patched=(">=0.4.16",)):
    return {
        "advisory": {"id": rustsec, "title": title, "cvss": cvss, "url": None},
        "package": {"name": name, "version": version},
        "versions": {"patched": list(patched)},
    }


def _report(*vulns, warnings=None):
    return {"vulnerabilities": {"count": len(vulns), "list": list(vulns)}, "warnings": warnings or {}}


@pytest.fixture
def run(tmp_path):
    """Write a report, run the CLI, and return (body, outputs)."""

    def _run(report):
        path = tmp_path / "cargo-audit.json"
        if report is not None:
            path.write_text(report if isinstance(report, str) else json.dumps(report), encoding="utf-8")
        out, gh = tmp_path / "comment.md", tmp_path / "gh.txt"
        assert audit.main(["--report", str(path), "--out", str(out), "--github-output", str(gh)]) == 0
        outputs = dict(line.split("=", 1) for line in gh.read_text(encoding="utf-8").splitlines())
        return out.read_text(encoding="utf-8"), outputs

    return _run


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        (HIGH, 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
        (MEDIUM, 4.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", None),
        ("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None),
        ("", None),
    ],
)
def test_cvss3_base_score(vector, expected):
    assert audit.cvss3_base_score(vector) == expected


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (9.0, "critical"),
        (7.0, "high"),
        (6.9, "medium"),
        (4.0, "medium"),
        (0.1, "low"),
        (0.0, "unscored"),
        (None, "unscored"),
    ],
)
def test_severity_from_score(score, expected):
    assert audit.severity_from_score(score) == expected


def test_clean_report_is_green_and_lists_warnings(run):
    warnings = {
        "unmaintained": [{"package": {"name": "paste", "version": "1.0.15"}, "advisory": {"id": "RUSTSEC-2024-0436"}}]
    }
    body, outputs = run(_report(warnings=warnings))
    assert body.startswith(f"{audit.MARKER}\n## :white_check_mark: Cargo Security Audit")
    assert "No vulnerable crates in `Cargo.lock`." in body
    assert "1 warning(s): unmaintained or yanked crates" in body
    assert "[RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436)" in body
    assert outputs == {"parse_ok": "true", "vulnerable": "0"}


def test_findings_split_into_a_table_and_a_fold(run):
    body, outputs = run(
        _report(
            _vuln("RUSTSEC-2026-0001", cvss=MEDIUM, name="medium-crate"),
            _vuln("RUSTSEC-2026-0002", cvss=HIGH, name="high-crate"),
            _vuln("RUSTSEC-2026-0003", cvss=None, name="unscored-crate"),
        )
    )
    assert body.startswith(f"{audit.MARKER}\n## :x: Cargo Security Audit")
    assert "![high: 1](https://img.shields.io/badge/high-1-orange)" in body
    assert "![critical: 0](https://img.shields.io/badge/critical-0-lightgrey)" in body
    table, fold = body.split("<details>", 1)
    assert "| high 7.5 | `high-crate` |" in table
    assert "medium-crate" not in table
    assert "unscored-crate" not in table
    assert "<summary>1 medium, 1 unscored - click to expand</summary>" in fold
    assert "| unscored | `unscored-crate` |" in fold
    assert outputs == {"parse_ok": "true", "vulnerable": "3"}


def test_only_lower_severity_still_says_so(run):
    body, _ = run(_report(_vuln("RUSTSEC-2026-0004", cvss=MEDIUM)))
    assert "No critical or high vulnerabilities." in body
    assert "| medium 4.8 |" in body


@pytest.mark.parametrize("raw", [None, "", "not json", "[]", '{"vulnerabilities": {}}'])
def test_unreadable_report_renders_the_parse_failure(run, raw):
    body, outputs = run(raw)
    assert body.strip() == audit.PARSE_FAILURE
    assert body.startswith(audit.MARKER)
    assert outputs == {"parse_ok": "false", "vulnerable": "0"}


def test_untrusted_advisory_text_is_inert(run):
    hostile = _vuln("NOT-RUSTSEC|x", cvss=HIGH, title="<img src=x> [click](https://evil.example) | pwn")
    hostile["advisory"]["url"] = "javascript:alert(1)"
    body, _ = run(_report(hostile))
    row = next(line for line in body.splitlines() if "NOT-RUSTSEC" in line)
    assert "<img" not in row
    assert "&lt;img" in row
    assert "\\[click\\]" in row
    assert "javascript:" not in row
    assert "NOT-RUSTSEC\\|x" in row


def test_rustsec_ids_link_to_rustsec():
    assert audit.advisory_url({"id": "RUSTSEC-2026-0189"}) == "https://rustsec.org/advisories/RUSTSEC-2026-0189"
    assert audit.advisory_url({"id": "GHSA-x", "url": "https://github.com/advisories/GHSA-x"}) == (
        "https://github.com/advisories/GHSA-x"
    )
    assert audit.advisory_url({"id": "x", "url": "http://plain.example"}) == ""
