"""Tests for .github/scripts/format_security_report.py, the scheduled scan's Slack report."""

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "format_security_report.py"


def _load():
    spec = importlib.util.spec_from_file_location("ci_scripts_format_security_report", SCRIPT)
    assert spec is not None and spec.loader is not None, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


report = _load()


def _trivy(*vulns, result_type="alpine"):
    return {"Results": [{"Target": "img", "Type": result_type, "Vulnerabilities": list(vulns)}]}


def _vuln(cve, severity="HIGH", pkg="libssl3", fixed="3.5.8-r0", title="OpenSSL issue", score=7.5):
    return {
        "VulnerabilityID": cve,
        "PkgName": pkg,
        "InstalledVersion": "3.5.7-r0",
        "FixedVersion": fixed,
        "Severity": severity,
        "SeveritySource": "nvd",
        "Title": title,
        "PrimaryURL": f"https://avd.aquasec.com/nvd/{cve.lower()}",
        "CVSS": {"nvd": {"V3Score": score}},
    }


def _sarif(*results):
    rules = [
        {"id": r["id"], "helpUri": f"https://scout.docker.com/v/{r['id']}", "help": {"text": r.get("help", "")}}
        for r in results
    ]
    return {
        "runs": [
            {
                "tool": {"driver": {"name": "Docker Scout", "rules": rules}},
                "results": [
                    {
                        "ruleId": r["id"],
                        "message": {
                            "text": (
                                f"Vulnerability    :{r['id']}\n"
                                f"Severity         :{r.get('severity', 'HIGH')}\n"
                                f"Package          :{r.get('purl', 'pkg:golang/golang.org/x/crypto@0.55.0')}\n"
                                f"Fixed version    :{r.get('fixed', '0.56.0')}\n"
                                f"CVSS Score       :{r.get('score', '7.5')}\n"
                            )
                        },
                    }
                    for r in results
                ],
            }
        ]
    }


def _alert(number, cve, severity="high", ghsa=None, package="starlette", summary="Starlette bug"):
    return {
        "number": number,
        "state": "open",
        "created_at": "2026-10-01T00:00:00Z",
        "html_url": f"https://github.com/permitio/PDP/security/dependabot/{number}",
        "dependency": {"package": {"name": package, "ecosystem": "pip"}},
        "security_advisory": {
            "severity": severity,
            "cve_id": cve,
            "ghsa_id": ghsa or f"GHSA-{number:04d}-aaaa-bbbb",
            "summary": summary,
            "cvss": {"score": 7.5},
        },
        "security_vulnerability": {"first_patched_version": {"identifier": "1.3.1"}},
    }


CLEAN_CARGO = {"vulnerabilities": {"found": False, "count": 0, "list": []}, "warnings": {}}


def _cargo(*vulns, warnings=None):
    return {"vulnerabilities": {"count": len(vulns), "list": list(vulns)}, "warnings": warnings or {}}


def _crate(rustsec, cvss=None, name="rmcp", version="0.12.0", aliases=(), patched=(">=1.4.0",)):
    return {
        "advisory": {"id": rustsec, "title": f"{name} advisory", "cvss": cvss, "aliases": list(aliases)},
        "package": {"name": name, "version": version},
        "versions": {"patched": list(patched)},
    }


@pytest.fixture
def run(tmp_path, monkeypatch):
    """Write the given inputs, run the CLI, and return (message, headline, outputs)."""
    monkeypatch.setattr(report.dependabot, "waived_cve_ids", lambda: {"CVE-2099-0001"})

    def _run(trivy=None, scout=None, alerts=None, cargo=CLEAN_CARGO, extra_args=()):
        args = ["--repo", "permitio/PDP", "--run-url", "https://github.com/permitio/PDP/actions/runs/1"]
        for tag, data in (trivy or {}).items():
            path = tmp_path / f"trivy-{tag}.json"
            if data is not None:
                path.write_text(json.dumps(data) if isinstance(data, dict) else data, encoding="utf-8")
            args += ["--trivy", f"{tag}={path}"]
        if scout is not None:
            path = tmp_path / "scout.sarif"
            path.write_text(json.dumps(scout) if isinstance(scout, dict) else scout, encoding="utf-8")
            args += ["--scout", f"latest={path}"]
        if alerts is not None:
            path = tmp_path / "alerts.json"
            path.write_text(json.dumps(alerts) if isinstance(alerts, list) else alerts, encoding="utf-8")
            args += ["--dependabot", str(path)]
        if cargo is not None:
            path = tmp_path / "cargo-audit.json"
            path.write_text(json.dumps(cargo) if isinstance(cargo, dict) else cargo, encoding="utf-8")
            args += ["--cargo", str(path)]
        out, headline, gh = tmp_path / "slack.txt", tmp_path / "headline.txt", tmp_path / "gh.txt"
        args += ["--out", str(out), "--headline-out", str(headline), "--github-output", str(gh), *extra_args]
        assert report.main(args) == 0
        outputs = dict(line.split("=", 1) for line in gh.read_text(encoding="utf-8").splitlines())
        return out.read_text(encoding="utf-8"), headline.read_text(encoding="utf-8").strip(), outputs

    return _run


def test_all_clean_is_silent_and_green(run):
    message, headline, outputs = run(trivy={"latest": _trivy()}, scout=_sarif(), alerts=[])
    assert message.startswith(":white_check_mark: *permitio/PDP: no high/critical vulnerabilities found*")
    assert headline == "no high/critical vulnerabilities found"
    assert outputs == {"notify": "false", "status": "ok", "severe": "0", "unscored": "0"}


def test_same_cve_from_every_source_is_one_line_naming_all_sources(run):
    cve = "CVE-2026-0001"
    message, headline, outputs = run(
        trivy={"latest": _trivy(_vuln(cve)), "0.9.16": _trivy(_vuln(cve, pkg="libcrypto3"))},
        scout=_sarif({"id": cve, "purl": "pkg:apk/alpine/libssl3@3.5.7-r0"}),
        alerts=[_alert(7, cve, package="openssl")],
    )
    listed = [line for line in message.splitlines() if cve in line and line.startswith("• *high")]
    assert len(listed) == 1
    assert "Trivy latest, Trivy 0.9.16, Docker Scout latest, Dependabot" in listed[0]
    assert "libssl3@3.5.7-r0" in listed[0] and "libcrypto3@3.5.7-r0" in listed[0]
    assert headline == "1 high/critical vulnerability found"
    assert outputs == {"notify": "true", "status": "warn", "severe": "1", "unscored": "0"}


def test_ghsa_alias_merges_a_dependabot_alert_into_the_scanner_finding(run):
    message, _, outputs = run(
        trivy={"latest": _trivy(_vuln("CVE-2026-0002"))},
        scout=_sarif(),
        alerts=[_alert(3, None, ghsa="GHSA-zzzz-0002-cccc"), _alert(4, "CVE-2026-0002")],
    )
    assert outputs["severe"] == "2"
    assert "GHSA-zzzz-0002-cccc" in message


def test_worst_severity_wins_on_merge(run):
    cve = "CVE-2026-0003"
    message, _, _ = run(
        trivy={"latest": _trivy(_vuln(cve, severity="HIGH", score=7.5))},
        scout=_sarif({"id": cve, "severity": "CRITICAL", "score": "9.8"}),
        alerts=[],
    )
    assert "*critical 9.8*" in message
    assert "*high" not in message


def test_missing_report_is_incomplete_never_clean(run):
    message, headline, outputs = run(trivy={"latest": _trivy(), "0.9.16": None}, scout=_sarif(), alerts=[])
    assert message.startswith(":warning: *permitio/PDP: security scan incomplete*")
    assert "*Trivy* (`pdp-v2:0.9.16`): :warning: did not complete" in message
    assert str(Path("/")) + "private" not in message
    assert headline == "security scan incomplete"
    assert outputs["status"] == "fail" and outputs["notify"] == "true"


def test_unparseable_sarif_and_feed_are_incomplete(run):
    message, _, outputs = run(trivy={"latest": _trivy()}, scout="{not json", alerts="also not json")
    assert "*Docker Scout* (`pdp-v2:latest`): :warning: did not complete" in message
    assert "*Dependabot alerts* (`all ecosystems`): :warning: did not complete" in message
    assert outputs["status"] == "fail"


def test_no_scout_cargo_or_dependabot_argument_reads_as_incomplete(run):
    message, _, outputs = run(trivy={"latest": _trivy()}, cargo=None)
    incomplete = [line for line in message.splitlines() if line.startswith("• ") and "did not complete" in line]
    assert len(incomplete) == 3
    assert outputs["status"] == "fail"


def test_cargo_finding_is_scored_from_its_vector_and_linked_to_rustsec(run):
    crate = _crate("RUSTSEC-2026-0189", cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
    message, _, outputs = run(trivy={"latest": _trivy()}, scout=_sarif(), alerts=[], cargo=_cargo(crate))
    line = next(line for line in message.splitlines() if "RUSTSEC-2026-0189" in line)
    assert line.startswith("• *high 7.5*")
    assert "<https://rustsec.org/advisories/RUSTSEC-2026-0189|RUSTSEC-2026-0189>" in line
    assert "fix: &gt;=1.4.0" in line and "_(cargo audit)_" in line
    assert outputs["severe"] == "1"


def test_cargo_alias_merges_with_the_dependabot_alert(run):
    crate = _crate("RUSTSEC-2026-0190", cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", aliases=["CVE-2026-0190"])
    message, _, _ = run(
        trivy={"latest": _trivy()},
        scout=_sarif(),
        alerts=[_alert(9, "CVE-2026-0190", package="rmcp")],
        cargo=_cargo(crate),
    )
    listed = [line for line in message.splitlines() if "CVE-2026-0190" in line or "RUSTSEC-2026-0190" in line]
    assert len(listed) == 1
    assert "cargo audit, Dependabot" in listed[0]


def test_unscored_cargo_advisory_is_listed_and_notifies(run):
    crate = _crate("RUSTSEC-2026-0258", cvss=None, name="h2", version="0.3.27")
    message, headline, outputs = run(trivy={"latest": _trivy()}, scout=_sarif(), alerts=[], cargo=_cargo(crate))
    assert message.startswith(":large_yellow_circle: *permitio/PDP: no high/critical vulnerabilities; 1 unscored")
    assert "*Unscored* (the advisory has no CVSS v3 score; triage manually)" in message
    assert "• *unscored* — `h2@0.3.27`" in message
    assert headline == "no high/critical vulnerabilities; 1 unscored to triage"
    assert outputs == {"notify": "true", "status": "warn", "severe": "0", "unscored": "1"}


def test_cargo_warnings_are_counted_not_alerted(run):
    warnings = {"unmaintained": [{"advisory": {"id": "RUSTSEC-2024-0436"}}], "yanked": []}
    message, _, outputs = run(trivy={"latest": _trivy()}, scout=_sarif(), alerts=[], cargo=_cargo(warnings=warnings))
    assert "*cargo audit* (`Cargo.lock`): clean · 1 warning(s): unmaintained or yanked crates" in message
    assert outputs["notify"] == "false"


def test_unreadable_cargo_report_is_incomplete(run):
    message, _, outputs = run(trivy={"latest": _trivy()}, scout=_sarif(), alerts=[], cargo="{}")
    assert "*cargo audit* (`Cargo.lock`): :warning: did not complete: the report has no vulnerability list" in message
    assert outputs["status"] == "fail"


def test_findings_and_an_incomplete_source_still_lead_with_the_count(run):
    message, headline, outputs = run(trivy={"latest": _trivy(_vuln("CVE-2026-0004")), "0.9.16": None})
    assert message.startswith(":rotating_light: *permitio/PDP: 1 high/critical vulnerability found*")
    assert ":warning: Some scans did not complete" in message
    assert headline == "1 high/critical vulnerability found (some scans did not complete)"
    assert outputs["status"] == "fail"


def test_waived_alerts_are_counted_not_listed(run):
    message, _, outputs = run(
        trivy={"latest": _trivy()}, scout=_sarif(), alerts=[_alert(1, "CVE-2099-0001"), _alert(2, "CVE-2026-0005")]
    )
    assert "CVE-2099-0001" not in message
    assert "CVE-2026-0005" in message
    assert "1 waived in .trivyignore.yaml" in message
    assert outputs["severe"] == "1"


def test_medium_findings_are_counted_but_not_alerted(run):
    message, _, outputs = run(trivy={"latest": _trivy(_vuln("CVE-2026-0006", severity="MEDIUM", score=5.0))})
    assert "1 medium" in message
    assert "*High / critical*" not in message
    assert outputs["severe"] == "0"


@pytest.mark.parametrize(
    ("pkg", "result_type", "hint"),
    [
        ("libssl3", "alpine", "a release rebuild picks it up"),
        ("golang.org/x/net", "gobinary", "bump it in permit-opa"),
        ("stdlib", "gobinary", "needs the golang base-image digest bump"),
        ("starlette", "python-pkg", "bump the exact pin in pyproject.toml"),
        ("httpx", "python-pkg", "update it in uv.lock"),
    ],
)
def test_trivy_remediation_names_who_acts(run, pkg, result_type, hint):
    vuln = _vuln("CVE-2026-0007", pkg=pkg)
    message, _, _ = run(trivy={"latest": _trivy(vuln, result_type=result_type)}, scout=_sarif(), alerts=[])
    assert f"fix: 3.5.8-r0, {hint}" in message


def test_no_fix_is_said_out_loud(run):
    message, _, _ = run(trivy={"latest": _trivy(_vuln("CVE-2026-0008", fixed=""))}, scout=_sarif(), alerts=[])
    assert "no fix released" in message


def test_untrusted_text_cannot_ping_link_or_break_formatting(run):
    hostile = _vuln("CVE-2026-0009", title="<!channel> pwn | <https://evil.example|click>", pkg="pkg`x")
    hostile["PrimaryURL"] = "javascript:alert(1)"
    message, _, _ = run(trivy={"latest": _trivy(hostile)}, scout=_sarif(), alerts=[])
    line = next(line for line in message.splitlines() if "CVE-2026-0009" in line)
    assert "<!channel>" not in line and "&lt;!channel&gt;" in line
    assert "<https://evil.example" not in line
    assert "javascript:" not in line
    assert "pkg'x" in line


def test_listing_is_capped(run):
    vulns = [_vuln(f"CVE-2026-{1000 + i}") for i in range(report.MAX_LISTED + 4)]
    message, headline, _ = run(trivy={"latest": _trivy(*vulns)}, scout=_sarif(), alerts=[])
    assert sum(1 for line in message.splitlines() if line.startswith("• *high")) == report.MAX_LISTED
    assert "…and 4 more (see the run)" in message
    assert headline.startswith(f"{report.MAX_LISTED + 4} high/critical")


def test_scout_title_drops_markdown_links_and_code_spans():
    rule = {"help": {"text": "> ### Summary\nUses [`os.path.realpath`](https://docs.python.org) badly."}}
    assert report._scout_title(rule) == "Uses os.path.realpath badly."


@pytest.mark.parametrize(
    ("value", "score", "expected"),
    [
        ("CRITICAL", None, "critical"),
        ("moderate", None, "medium"),
        ("UNSPECIFIED", 9.1, "critical"),
        ("UNKNOWN", 7.0, "high"),
        ("", 4.0, "medium"),
        ("", 0.5, "low"),
        ("", None, "unscored"),
    ],
)
def test_normalise_severity(value, score, expected):
    assert report.normalise_severity(value, score) == expected


def test_bad_trivy_argument_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        report.parse_args(["--repo", "r", "--run-url", "u", "--out", "o", "--trivy", "no-equals-sign"])
    assert exc.value.code == 2
