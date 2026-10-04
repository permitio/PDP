#!/usr/bin/env python3
"""Render `cargo audit --json` as the sticky PR comment, in permitio/agent-security's layout.

The body ALWAYS starts with ``MARKER`` so the workflow can find and rewrite its own comment
instead of adding one per push. A report that cannot be read renders a loud "could not be
parsed" comment and sets ``parse_ok=false``; the workflow's fail step blocks on that, so an
unreadable report never passes as clean. This script itself exits 0 whenever it wrote a body.

cargo audit gives an advisory's CVSS vector, not a severity, and many RustSec advisories
carry no vector at all. The severity is computed from a CVSS v3.x vector; anything else is
"unscored" and shown, never dropped. format_security_report.py imports the calculator from
here.
"""

import argparse
import json
import re
from pathlib import Path

MARKER = "<!-- pdp-cargo-audit -->"
TITLE = "Cargo Security Audit"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unscored": 4}
SEVERITY_COLOURS = {"critical": "red", "high": "orange", "medium": "yellow", "low": "blue", "unscored": "lightgrey"}

_RUSTSEC_ID = re.compile(r"^RUSTSEC-\d{4}-\d{4}$")
_WHITESPACE = re.compile(r"\s+")

# CVSS v3.x base-metric weights, from the FIRST CVSS v3.1 specification, section 7.4.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

PARSE_FAILURE = (
    f"{MARKER}\n## :x: {TITLE}\n\n**The audit report could not be parsed.** `cargo audit --json` "
    "produced no usable report - the audit step likely failed before it could write one. Check the "
    "job log and re-run. This check fails until it reads a report."
)


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: the smallest one-decimal number >= value, float-safe."""
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000
    return (scaled // 10_000 + 1) / 10


def cvss3_base_score(vector: str) -> float | None:
    """Base score of a CVSS v3.0/v3.1 vector; None for any other version or a malformed one."""
    parts = vector.strip().split("/")
    if parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics = dict(part.split(":", 1) for part in parts[1:] if ":" in part)
    scope = metrics.get("S")
    if scope not in ("U", "C"):
        return None
    privileges = _PR_CHANGED if scope == "C" else _PR_UNCHANGED
    try:
        av, ac = _AV[metrics["AV"]], _AC[metrics["AC"]]
        pr, ui = privileges[metrics["PR"]], _UI[metrics["UI"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return _roundup(min(raw, 10))


def severity_from_score(score: float | None) -> str:
    """critical/high/medium/low from a CVSS score, or unscored when there is none."""
    if score is None or score <= 0:
        return "unscored"
    for floor, name in ((9.0, "critical"), (7.0, "high"), (4.0, "medium")):
        if score >= floor:
            return name
    return "low"


def advisory_url(advisory: dict) -> str:
    """The RustSec page for a well-formed RUSTSEC id; otherwise the advisory's own https URL."""
    advisory_id = str(advisory.get("id") or "")
    if _RUSTSEC_ID.match(advisory_id):
        return f"https://rustsec.org/advisories/{advisory_id}"
    url = str(advisory.get("url") or "")
    return url if url.startswith("https://") and not re.search(r"[\s()<>\[\]]", url) else ""


def load_report(path: Path) -> dict | None:
    """The parsed report, or None when it is missing, empty, not JSON or has no vulnerability list."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or not isinstance((data.get("vulnerabilities") or {}).get("list"), list):
        return None
    return data


def _cell(text: object) -> str:
    """Untrusted advisory text made safe for a Markdown table cell."""
    flat = _WHITESPACE.sub(" ", str(text)).strip()
    flat = flat.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return flat.replace("[", "\\[").replace("]", "\\]").replace("|", "\\|") or "-"


def _rows(data: dict) -> list[dict]:
    rows = []
    for entry in data["vulnerabilities"]["list"]:
        if not isinstance(entry, dict):
            continue
        advisory = entry.get("advisory") or {}
        package = entry.get("package") or {}
        score = cvss3_base_score(str(advisory.get("cvss") or ""))
        rows.append(
            {
                "id": str(advisory.get("id") or "?"),
                "url": advisory_url(advisory),
                "title": str(advisory.get("title") or ""),
                "crate": str(package.get("name") or "?"),
                "installed": str(package.get("version") or "?"),
                "patched": ", ".join((entry.get("versions") or {}).get("patched") or []) or "no fix released",
                "severity": severity_from_score(score),
                "score": score or None,
            }
        )
    return sorted(rows, key=lambda r: (SEVERITY_ORDER[r["severity"]], -(r["score"] or 0), r["id"]))


def _table(rows: list[dict]) -> list[str]:
    lines = ["| Severity | Crate | Installed | Fixed | Title | Advisory |", "| --- | --- | --- | --- | --- | --- |"]
    for row in rows:
        label = row["severity"] if row["score"] is None else f"{row['severity']} {row['score']:.1f}"
        advisory = f"[{_cell(row['id'])}]({row['url']})" if row["url"] else _cell(row["id"])
        lines.append(
            f"| {label} | `{_cell(row['crate'])}` | {_cell(row['installed'])} | {_cell(row['patched'])} "
            f"| {_cell(row['title'])} | {advisory} |"
        )
    return lines


def _warnings(data: dict) -> list[str]:
    """Unmaintained / yanked / unsound crates: reported in a fold, never failing the check."""
    items = []
    for kind, entries in (data.get("warnings") or {}).items():
        for entry in entries if isinstance(entries, list) else []:
            package = (entry or {}).get("package") or {}
            advisory = (entry or {}).get("advisory") or {}
            name = f"`{_cell(package.get('name') or '?')}@{_cell(package.get('version') or '?')}`"
            reference = advisory.get("id")
            link = f" ([{_cell(reference)}]({advisory_url(advisory)}))" if reference and advisory_url(advisory) else ""
            items.append(f"- {_cell(kind)}: {name}{link}")
    if not items:
        return []
    summary = f"<summary>{len(items)} warning(s): unmaintained or yanked crates</summary>"
    return ["", "<details>", summary, "", *items, "", "</details>"]


def render(data: dict | None) -> str:
    """The full comment body for a parsed report, or the parse-failure body for None."""
    if data is None:
        return PARSE_FAILURE
    rows = _rows(data)
    if not rows:
        clean = [MARKER, f"## :white_check_mark: {TITLE}", "", "No vulnerable crates in `Cargo.lock`."]
        return "\n".join([*clean, *_warnings(data)])
    counts = {severity: sum(1 for r in rows if r["severity"] == severity) for severity in SEVERITY_ORDER}
    badges = " ".join(
        f"![{severity}: {count}](https://img.shields.io/badge/{severity}-{count}-"
        f"{SEVERITY_COLOURS[severity] if count else 'lightgrey'})"
        for severity, count in counts.items()
        if severity != "unscored" or count
    )
    severe = [r for r in rows if r["severity"] in ("critical", "high")]
    rest = [r for r in rows if r["severity"] not in ("critical", "high")]
    body = [MARKER, f"## :x: {TITLE}", "", badges, ""]
    body += [
        f"**{len(rows)} vulnerable crate(s) in `Cargo.lock`.** Any vulnerable crate fails this check and blocks "
        "a release. Upgrade it (`cargo update -p NAME`), or - only with a written reachability argument - "
        "ignore the advisory in `.cargo/audit.toml`.",
        "",
    ]
    body += [*_table(severe), ""] if severe else ["No critical or high vulnerabilities.", ""]
    if rest:
        summary = ", ".join(f"{counts[s]} {s}" for s in ("medium", "low", "unscored") if counts[s])
        body += ["<details>", f"<summary>{summary} - click to expand</summary>", "", *_table(rest), "", "</details>"]
    return "\n".join([*body, *_warnings(data)])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Render cargo audit JSON as the sticky PR comment.")
    ap.add_argument("--report", type=Path, required=True, help="`cargo audit --json` output.")
    ap.add_argument("--out", type=Path, required=True, help="Write the comment body here.")
    ap.add_argument("--github-output", type=Path, help="Append parse_ok and vulnerable here.")
    args = ap.parse_args(argv)
    data = load_report(args.report)
    body = render(data)
    args.out.write_text(body + "\n", encoding="utf-8")
    if args.github_output:
        vulnerable = len(_rows(data)) if data is not None else 0
        with args.github_output.open("a", encoding="utf-8") as fh:
            fh.write(f"parse_ok={'true' if data is not None else 'false'}\nvulnerable={vulnerable}\n")
    print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
