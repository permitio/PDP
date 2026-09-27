"""Build-time check for the aiofiles override in requirements-override.txt (PER-16234).

The Dockerfile pip layer bind-mounts and runs this as its last step, so it sees exactly what
ships. It fails the image build if:

1. opal-client is no longer 0.9.6. The override is installed with --no-deps, which also silences
   pip's conflict report, so a bumped opal-client would otherwise keep the overridden aiofiles
   whatever it declares. Re-evaluate the override first; this check goes away with it (see the
   exit note in requirements-override.txt).
2. OPAL's offline-mode backup does not work in the image: the real OpalClient.backup_store() must
   write the backup and leave no *.json.tmp behind - the same call path that broke on aiofiles
   0.8.0 (delete=False/dir=/suffix= temp file, write, os.replace). backup_store() swallows its own
   exceptions, so this checks the files it leaves, not whether it raised. This check stays after
   the override is gone: with no lockfile, release builds re-resolve without running pytests.

horizon/tests/test_offline_backup.py covers (2) in the pytests job; this covers the image itself.
"""

import asyncio
import importlib.metadata
import json
import sys
import tempfile
from pathlib import Path

EXPECTED_OPAL_CLIENT = "0.9.6"
EXPORT = {"policies": {}, "data": {}}


class _StubPolicyStore:
    async def full_export(self, writer) -> None:
        await writer.write(json.dumps(EXPORT))


def check_opal_client_pin() -> None:
    version = importlib.metadata.version("opal-client")
    if version != EXPECTED_OPAL_CLIENT:
        sys.exit(
            f"opal-client is {version}, not {EXPECTED_OPAL_CLIENT}: re-evaluate the aiofiles "
            "override in requirements-override.txt (PER-16234)"
        )


def check_backup_store() -> None:
    # Imported here, after the pin check, so a moved opal-client fails with the message above.
    from opal_client.client import OpalClient

    with tempfile.TemporaryDirectory() as backup_dir:
        backup_path = Path(backup_dir) / "policy_store_backup.json"
        client = object.__new__(OpalClient)  # skip __init__: no policy engine, no updaters
        client._backup_lock = asyncio.Lock()
        client.store_backup_path = str(backup_path)
        client.policy_store = _StubPolicyStore()
        asyncio.run(client.backup_store())

        left = sorted(path.name for path in Path(backup_dir).iterdir())
        if left != [backup_path.name] or json.loads(backup_path.read_text()) != EXPORT:
            sys.exit(f"OPAL backup_store() is broken in this image (PER-16234): left {left}")


if __name__ == "__main__":
    check_opal_client_pin()
    check_backup_store()
