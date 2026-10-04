"""Unit tests for OPAL's offline-mode ``OpalClient.backup_store()`` (PER-16234, permitio/PDP#340).

On CPython >= 3.12 the only aiofiles that opal-client 0.9.6 admits (0.8.0) breaks
``backup_store()``, and ``requirements-override.txt`` installs a working one over it - see that
file. These tests run OPAL's real ``backup_store()``, so on CPython >= 3.12 they fail if the
override is missing.

``backup_store()`` catches every exception and only logs it, so a broken backup never raises: it
leaves the previous backup in place plus a stray zero-byte ``*.json.tmp``. Every assertion is
therefore on what is left on disk, never on whether the call raised.

Clients are built with ``object.__new__(OpalClient)``, so ``__init__`` never runs: only the
attributes ``backup_store()`` reads (``_backup_lock``, ``store_backup_path``, ``policy_store``)
are set, and no policy engine, PubSub client or updater task starts.
"""

import asyncio
import json
from pathlib import Path

import pytest
from opal_client.client import OpalClient

EXPORT = {"policies": {"p.rego": "package p"}, "data": {"k": "v"}}


class _StubPolicyStore:
    """The only collaborator ``backup_store()`` calls - writes the fixed ``EXPORT`` payload."""

    async def full_export(self, writer) -> None:
        await writer.write(json.dumps(EXPORT))


def _client_without_init(backup_path: Path) -> OpalClient:
    """Build an ``OpalClient`` with only what ``backup_store()`` touches - see module docstring."""
    client = object.__new__(OpalClient)
    client._backup_lock = asyncio.Lock()
    client.store_backup_path = str(backup_path)
    client.policy_store = _StubPolicyStore()
    return client


@pytest.mark.asyncio
async def test_backup_store_writes_the_export(tmp_path: Path) -> None:
    backup_path = tmp_path / "opa_backup.json"

    await _client_without_init(backup_path).backup_store()

    assert json.loads(backup_path.read_text()) == EXPORT
    assert list(tmp_path.glob("*.json.tmp")) == [], "a failed export must not leak its tmp file"


@pytest.mark.asyncio
async def test_backup_store_replaces_a_previous_backup(tmp_path: Path) -> None:
    backup_path = tmp_path / "opa_backup.json"
    backup_path.write_text('{"stale": true}')

    await _client_without_init(backup_path).backup_store()

    assert json.loads(backup_path.read_text()) == EXPORT
    assert list(tmp_path.glob("*.json.tmp")) == [], "a failed export must not leak its tmp file"


@pytest.mark.asyncio
async def test_backup_store_creates_the_backup_directory_when_missing(tmp_path: Path) -> None:
    """Offline mode's backup directory (``/app/backup`` in the image) may not exist on first run."""
    backup_dir = tmp_path / "backup"
    backup_path = backup_dir / "opa_backup.json"

    await _client_without_init(backup_path).backup_store()

    assert json.loads(backup_path.read_text()) == EXPORT
    assert list(backup_dir.glob("*.json.tmp")) == [], "a failed export must not leak its tmp file"
