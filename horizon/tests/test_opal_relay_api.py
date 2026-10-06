"""Tests for the uptime ping the OPAL relay client sends to the control plane.

The control plane is mocked at the HTTP boundary with aioresponses. ``get_env_api_key`` (a control
plane fetch) and ``PersistentStateHandler.get_runtime_state`` (it shells out to ``opa version``)
are replaced, as is the persistent-state singleton, which only the PDP's startup initializes.
"""

import asyncio
import base64
import json
import re
import time
from collections.abc import AsyncIterator, Iterator
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import MagicMock
from uuid import uuid4

import aiohttp
import pytest
import pytest_asyncio
from aioresponses import aioresponses
from loguru import logger
from pydantic import ValidationError

from horizon.config import sidecar_config
from horizon.opal_relay_api import OpalRelayAPIClient, RelayAPIError
from horizon.state import PersistentStateHandler

if TYPE_CHECKING:
    from loguru import Record

RELAY_JWT_URL = re.compile(r".*/v2/relay_jwt/.*")
PING_URL = re.compile(r".*/v2/pdp/ping$")
RUNTIME_STATE = {
    "pdp": {
        "version": "0.0.0",
        "os_name": "Linux",
        "os_machine": "x86_64",
        "os_version": "1",
        "os_release": "1",
        "os_platform": "Linux-1",
        "python_version": "3.13.0",
        "python_implementation": "CPython",
    },
    "opa": {"version": "1.0.0", "go_version": "go1", "platform": "linux/amd64", "have_webassembly": False},
}


@pytest_asyncio.fixture
async def relay_client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[OpalRelayAPIClient]:
    monkeypatch.setattr("horizon.opal_relay_api.get_env_api_key", lambda: "env-api-key")
    opal_client = MagicMock()
    opal_client.policy_updater.topics = ["policy:topic"]
    context = {"org_id": str(uuid4()), "project_id": str(uuid4()), "env_id": str(uuid4())}
    client = OpalRelayAPIClient(context, opal_client=opal_client)
    yield client
    for session in (client._api_session, client._relay_session):
        if session is not None:
            await session.close()


@pytest.fixture
def logged_warnings() -> Iterator[list["Record"]]:
    """Every loguru record at WARNING or above emitted during the test."""
    records: list[Record] = []
    sink_id = logger.add(lambda message: records.append(message.record), level="WARNING")
    yield records
    logger.remove(sink_id)


@pytest.mark.asyncio
async def test_ping_loop_logs_a_transport_failure_in_one_line_and_anything_else_with_a_traceback(
    relay_client: OpalRelayAPIClient,
    logged_warnings: list["Record"],
    monkeypatch: pytest.MonkeyPatch,
):
    """An unreachable control plane is routine and repeats every interval, so it stays one line. Any
    other failure keeps the loop alive too, but is logged with the traceback that explains it."""
    monkeypatch.setattr(sidecar_config, "PING_INTERVAL", 0)
    with aioresponses() as mocked:
        mocked.post(RELAY_JWT_URL, exception=aiohttp.ClientConnectionError("connection refused"))
        mocked.post(RELAY_JWT_URL, status=200, payload={"not_a_token": "x"})
        task = asyncio.create_task(relay_client._run())
        try:
            async with asyncio.timeout(5):
                while len(logged_warnings) < 2:  # noqa: ASYNC110 - polls a log sink, not an asyncio primitive
                    await asyncio.sleep(0)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    transport_failure, unexpected_failure = logged_warnings[:2]
    assert "ClientConnectionError: connection refused" in transport_failure["message"]
    assert transport_failure["exception"] is None
    assert unexpected_failure["exception"] is not None
    assert unexpected_failure["exception"].type is ValidationError


def _relay_jwt(expires_at: float) -> str:
    """A token whose claims carry `exp`, which is all the client reads from it."""
    claims = base64.b64encode(json.dumps({"exp": int(expires_at)}).encode()).decode()
    return f"header.{claims}.signature"


@pytest.mark.asyncio
async def test_ping_loop_logs_a_repeated_failure_with_its_traceback_once_until_a_ping_succeeds(
    relay_client: OpalRelayAPIClient,
    logged_warnings: list["Record"],
    monkeypatch: pytest.MonkeyPatch,
):
    """The loop retries every PING_INTERVAL and some failures last until a restart, so a traceback each
    time would flood the log. The first failure of a type carries it; a successful ping starts over."""
    monkeypatch.setattr(sidecar_config, "PING_INTERVAL", 0)
    monkeypatch.setattr(
        PersistentStateHandler, "_instance", SimpleNamespace(_state=SimpleNamespace(pdp_instance_id=uuid4()))
    )
    # The first ping that gets this far is sent; every later one has a runtime state that does not validate.
    runtime_states = iter([RUNTIME_STATE])
    monkeypatch.setattr(PersistentStateHandler, "get_runtime_state", lambda: next(runtime_states, {}))
    with aioresponses() as mocked:
        mocked.post(RELAY_JWT_URL, status=200, payload={"not_a_token": "x"}, repeat=2)
        mocked.post(RELAY_JWT_URL, status=200, payload={"token": _relay_jwt(time.time() + 24 * 3600)})
        mocked.post(PING_URL, status=202)
        task = asyncio.create_task(relay_client._run())
        try:
            async with asyncio.timeout(5):
                while len(logged_warnings) < 4:  # noqa: ASYNC110 - polls a log sink, not an asyncio primitive
                    await asyncio.sleep(0)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    first, repeated, after_a_ping, repeated_after_a_ping = logged_warnings[:4]
    assert first["exception"] is not None
    assert first["exception"].type is ValidationError
    assert repeated["exception"] is None
    assert "ValidationError: 1 validation error for RelayJWTResponse" in repeated["message"]
    assert after_a_ping["exception"] is not None
    assert after_a_ping["exception"].type is ValidationError
    assert repeated_after_a_ping["exception"] is None
    assert "ValidationError" in repeated_after_a_ping["message"]


@pytest.mark.asyncio
async def test_ping_with_a_bad_status_and_an_undecodable_body_still_raises_relay_api_error(
    relay_client: OpalRelayAPIClient,
    monkeypatch: pytest.MonkeyPatch,
):
    """The body only decorates the error message, so failing to decode it must not replace the
    RelayAPIError that reports the bad status."""
    monkeypatch.setattr(
        PersistentStateHandler, "_instance", SimpleNamespace(_state=SimpleNamespace(pdp_instance_id=uuid4()))
    )
    monkeypatch.setattr(PersistentStateHandler, "get_runtime_state", lambda: RUNTIME_STATE)
    with aioresponses() as mocked:
        mocked.post(RELAY_JWT_URL, status=200, payload={"token": "header.payload.signature"})
        mocked.post(PING_URL, status=500, body=b"\xff\xfe", content_type="text/plain; charset=utf-8")
        with pytest.raises(RelayAPIError) as excinfo:
            await relay_client.send_ping()

    assert excinfo.value.service == "relay-api"
    assert excinfo.value.status_code == 500
