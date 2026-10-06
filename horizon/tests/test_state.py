"""PersistentStateHandler.seen_sdk on a state file whose seen_sdks is absent or null.

PersistentState declares seen_sdks optional, so such a file loads; the PDP must keep its instance id
and record the SDK rather than fail every request that names one.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from horizon.state import PersistentStateHandler

INSTANCE_ID = str(uuid4())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stored",
    [{"pdp_instance_id": INSTANCE_ID}, {"pdp_instance_id": INSTANCE_ID, "seen_sdks": None}],
    ids=["seen-sdks-absent", "seen-sdks-null"],
)
async def test_the_first_sdk_seen_is_reported_and_saved(tmp_path: Path, monkeypatch, stored: dict):
    state_file = tmp_path / "persistent_state.json"
    state_file.write_text(json.dumps(stored))
    handler = PersistentStateHandler(str(state_file), "env-api-key")
    report = AsyncMock()
    monkeypatch.setattr(handler, "_report", report)

    await handler.seen_sdk("python")

    report.assert_awaited_once()
    assert json.loads(state_file.read_text()) == {"pdp_instance_id": INSTANCE_ID, "seen_sdks": ["python"]}
