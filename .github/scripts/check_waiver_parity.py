#!/usr/bin/env python3
"""Enforce the rule `.trivyignore.yaml` states but nothing used to check.

Two scanners run against the PDP image and they read waivers from different files:
Trivy from `.trivyignore.yaml`, Docker Scout from `.docker/scout/pdp-v2.vex.json`.
A waiver added to one and forgotten in the other does not fail anything - it just
means one scanner keeps reporting a CVE the team already triaged, until somebody
waives it a second time under time pressure or, worse, a release gate goes red for a
finding that was answered months ago.

The same applies to expiry. Every `.trivyignore.yaml` entry carries `expired_at`
precisely so a waiver cannot become permanent by accident; a missing or already-past
date is an error here, and `--warn-days` gives the weekly digest its heads-up line.
"""

from __future__ import annotations

import argparse
import json
from datetime import date, datetime, timedelta
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError as exc:  # pragma: no cover - environment problem, not logic
    raise SystemExit(
        "check_waiver_parity.py needs PyYAML to read .trivyignore.yaml. Install it with "
        "`pip install pyyaml` (CI installs it via the pre-commit hook's additional_dependencies)."
    ) from exc

TRIVYIGNORE = Path(".trivyignore.yaml")
VEX = Path(".docker/scout/pdp-v2.vex.json")


def repo_root() -> Path:
    """Return the repository root, derived from this script's location."""
    return Path(__file__).resolve().parents[2]


def load_trivyignore(path: Path) -> dict[str, date | None]:
    """Read `.trivyignore.yaml` into {CVE id: expiry date or None}.

    Args:
        path: Path to the Trivy ignore file.

    Returns:
        One entry per waived id. The value is None when the entry has no
        `expired_at` at all, which is itself an error the caller reports.

    Raises:
        SystemExit: The file is missing, is not YAML, or has the wrong shape.
    """
    if not path.is_file():
        raise SystemExit(f"{path} does not exist - the Trivy waiver list is required.")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise SystemExit(f"{path} is not valid YAML: {exc}") from exc
    entries = data.get("vulnerabilities")
    if not isinstance(entries, list):
        raise SystemExit(f"{path} has no `vulnerabilities:` list - expected a list of waivers.")
    waivers: dict[str, date | None] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("id"):
            raise SystemExit(f"{path} has a waiver entry without an `id:` - fix it: {entry!r}")
        waivers[str(entry["id"])] = _as_date(entry.get("expired_at"), path, str(entry["id"]))
    return waivers


def _as_date(value: object, path: Path, cve: str) -> date | None:
    """Coerce a YAML `expired_at` value to a date, failing loudly on junk."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise SystemExit(f"{path}: `expired_at: {value!r}` on {cve} is not a YYYY-MM-DD date.") from exc


def load_vex(path: Path) -> set[str]:
    """Read the OpenVEX document into the set of ids it carries a statement for.

    Args:
        path: Path to the OpenVEX JSON document.

    Returns:
        Every `statements[].vulnerability.name`.

    Raises:
        SystemExit: The file is missing, is not JSON, or has the wrong shape.
    """
    if not path.is_file():
        raise SystemExit(f"{path} does not exist - the Docker Scout waiver doc is required.")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path} is not valid JSON: {exc}") from exc
    statements = data.get("statements")
    if not isinstance(statements, list):
        raise SystemExit(f"{path} has no `statements` list - expected an OpenVEX document.")
    ids: set[str] = set()
    for statement in statements:
        name = ((statement or {}).get("vulnerability") or {}).get("name")
        if not name:
            raise SystemExit(f"{path} has a statement without `vulnerability.name`: {statement!r}")
        ids.add(str(name))
    return ids


def parity_errors(waivers: dict[str, date | None], vex_ids: set[str]) -> list[str]:
    """Name every id that only one of the two waiver files knows about."""
    errors = []
    for cve in sorted(vex_ids - set(waivers)):
        errors.append(
            f"{cve} is waived in {VEX} but missing from {TRIVYIGNORE}. Add it under "
            f"`vulnerabilities:` with a short `statement:` and an `expired_at:`."
        )
    for cve in sorted(set(waivers) - vex_ids):
        errors.append(
            f"{cve} is waived in {TRIVYIGNORE} but missing from {VEX}. Add a matching "
            f"statement with its `status`, `justification` and `impact_statement`."
        )
    return errors


def expiry_errors(waivers: dict[str, date | None], today: date) -> list[str]:
    """Name every waiver with no expiry date or with one that has already passed."""
    errors = []
    for cve, expires in sorted(waivers.items()):
        if expires is None:
            errors.append(
                f"{cve} in {TRIVYIGNORE} has no `expired_at:`. A waiver without one never "
                f"gets re-checked; give it a date."
            )
        elif expires < today:
            errors.append(
                f"{cve} in {TRIVYIGNORE} expired on {expires.isoformat()}. Re-check whether "
                f"the fix is reachable now, then push the date out or delete the waiver."
            )
    return errors


def expiring_soon(waivers: dict[str, date | None], today: date, warn_days: int) -> list[str]:
    """Return `CVE (YYYY-MM-DD)` for each waiver expiring within `warn_days` days."""
    soon = []
    for cve, expires in sorted(waivers.items()):
        if expires is not None and today <= expires <= today + timedelta(days=warn_days):
            soon.append(f"{cve} ({expires.isoformat()})")
    return soon


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--warn-days",
        type=int,
        default=0,
        help="Print a one-line warning for waivers expiring within N days (exit stays 0).",
    )
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    root = repo_root()
    waivers = load_trivyignore(root / TRIVYIGNORE)
    vex_ids = load_vex(root / VEX)
    today = date.today()

    errors = parity_errors(waivers, vex_ids) + expiry_errors(waivers, today)
    if errors:
        print(f"Waiver check failed ({len(errors)} problem(s)):")
        for error in errors:
            print(f"  - {error}")
        return 1

    if args.warn_days > 0:
        soon = expiring_soon(waivers, today, args.warn_days)
        detail = f": {', '.join(soon)}" if soon else "."
        print(f"{len(soon)} waiver(s) expire within {args.warn_days} days{detail}")
    else:
        print(f"Waiver parity OK: {len(waivers)} CVE(s) in both {TRIVYIGNORE} and {VEX}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
