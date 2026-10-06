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
from opal_client.config import opal_client_config
from pydantic import ValidationError

from horizon.config import sidecar_config
from horizon.opal_relay_api import (
    MAX_JWT_EXPIRY_BUFFER_TIME,
    OpalRelayAPIClient,
    RelayAPIError,
    get_jwt_expiry_time,
)
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
# Relay JWT subjects keyed by the length, mod 4, of the payload segment they give a token from _relay_jwt:
# every length an unpadded base64url segment can have. Each holds a run of "?" (0x3F3F3F), which base64url
# writes as "Pz8_" where standard base64 writes "Pz8/".
SUBJECTS_BY_PAYLOAD_LENGTH_MOD_4 = {0: "??????", 2: "???????", 3: "????????"}


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


def _base64url(data: bytes) -> str:
    """A JWT segment: base64url without its padding (RFC 7515)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt_with_payload(payload: bytes) -> str:
    """A JWT laid out as the control plane issues one, around ``payload``. The client reads only its `exp`."""
    header = _base64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    return f"{header}.{_base64url(payload)}.{_base64url(b'signature')}"


def _relay_jwt(expires_at: float, subject: str = "pdp") -> str:
    return _jwt_with_payload(json.dumps({"exp": int(expires_at), "sub": subject}).encode())


def _use_pdp_state(monkeypatch: pytest.MonkeyPatch, runtime_states: Iterator[dict]) -> None:
    """Give pings a PDP instance id and take their runtime states from ``runtime_states``. Once it runs
    out, every runtime state is ``{}``, which PDPPingPlatformState does not validate."""
    monkeypatch.setattr(
        PersistentStateHandler, "_instance", SimpleNamespace(_state=SimpleNamespace(pdp_instance_id=uuid4()))
    )
    monkeypatch.setattr(PersistentStateHandler, "get_runtime_state", lambda: next(runtime_states, {}))


@pytest.mark.asyncio
async def test_ping_loop_logs_expected_failures_in_one_line_and_anything_else_with_a_traceback(
    relay_client: OpalRelayAPIClient,
    logged_warnings: list["Record"],
    monkeypatch: pytest.MonkeyPatch,
):
    """An unreachable control plane, or a token response the PDP cannot use, repeats every interval, so
    each stays one line, which says why. A token response is described, not quoted: it may hold a token
    under a key the PDP does not read. Any other failure keeps the loop alive too, but is logged with
    the traceback that explains it."""
    monkeypatch.setattr(sidecar_config, "PING_INTERVAL", 0)
    _use_pdp_state(monkeypatch, iter([]))
    misplaced_token = _relay_jwt(time.time() + 24 * 3600)
    unusable_token_body = json.dumps({"data": {"token": misplaced_token}})
    with aioresponses() as mocked:
        mocked.post(RELAY_JWT_URL, exception=aiohttp.ClientConnectionError("connection refused"))
        mocked.post(RELAY_JWT_URL, status=200, body=unusable_token_body, content_type="application/json")
        mocked.post(RELAY_JWT_URL, status=200, payload={"token": _relay_jwt(time.time() + 24 * 3600)})
        task = asyncio.create_task(relay_client._run())
        try:
            async with asyncio.timeout(5):
                while len(logged_warnings) < 3:  # noqa: ASYNC110 - polls a log sink, not an asyncio primitive
                    await asyncio.sleep(0)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    transport_failure, unusable_token_response, unexpected_failure = logged_warnings[:3]
    assert "ClientConnectionError: connection refused" in transport_failure["message"]
    assert transport_failure["exception"] is None
    reason = (
        "Server responded to token request with an invalid result: "
        f"{len(unusable_token_body)} bytes of application/json"
    )
    assert f"got status code 200 from relay-jwt-api: {reason}." in unusable_token_response["message"]
    assert misplaced_token not in unusable_token_response["message"]
    assert unusable_token_response["exception"] is None
    assert unexpected_failure["exception"] is not None
    assert unexpected_failure["exception"].type is ValidationError
    assert "PDPPingPlatformState" in str(unexpected_failure["exception"].value)


@pytest.mark.asyncio
async def test_ping_loop_logs_a_repeated_failure_with_its_traceback_once_until_a_ping_succeeds(
    relay_client: OpalRelayAPIClient,
    logged_warnings: list["Record"],
    monkeypatch: pytest.MonkeyPatch,
):
    """The loop retries every PING_INTERVAL and some failures last until a restart, so a traceback each
    time would flood the log. The first failure of a type carries it; a successful ping starts over."""
    monkeypatch.setattr(sidecar_config, "PING_INTERVAL", 0)
    # Two pings fail on their runtime state, the third is sent, and every later one fails again.
    _use_pdp_state(monkeypatch, iter([{}, {}, RUNTIME_STATE]))
    with aioresponses() as mocked:
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
    assert "ValidationError: 2 validation errors for PDPPingPlatformState" in repeated["message"]
    assert after_a_ping["exception"] is not None
    assert after_a_ping["exception"].type is ValidationError
    assert repeated_after_a_ping["exception"] is None
    assert "ValidationError" in repeated_after_a_ping["message"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token_response",
    [
        {"payload": {"not_a_token": "x"}},
        {"payload": [1]},
        {"body": "", "content_type": "application/json"},
        {"body": "not json", "content_type": "application/json"},
        {"body": b"\xff\xfe", "content_type": "application/json"},
        {"body": "<html>bad gateway</html>", "content_type": "text/html"},
    ],
    ids=["no-token", "not-an-object", "empty", "not-json", "not-utf8", "html"],
)
async def test_a_token_response_without_a_relay_jwt_raises_relay_api_error(
    relay_client: OpalRelayAPIClient, token_response: dict
):
    """A 200 token response the PDP cannot use is a RelayAPIError, which the ping loop logs in one line."""
    with aioresponses() as mocked:
        mocked.post(RELAY_JWT_URL, status=200, **token_response)
        with pytest.raises(RelayAPIError, match=r"invalid result: \d+ bytes of [\w/]+$") as excinfo:
            await relay_client.relay_session()

    assert excinfo.value.service == "relay-jwt-api"
    assert excinfo.value.status_code == 200


@pytest.mark.parametrize(
    ("payload_length_mod_4", "subject"),
    SUBJECTS_BY_PAYLOAD_LENGTH_MOD_4.items(),
    ids=[f"payload-length-mod-4-is-{n}" for n in SUBJECTS_BY_PAYLOAD_LENGTH_MOD_4],
)
def test_relay_jwt_expiry_is_read_from_its_unpadded_base64url_payload(payload_length_mod_4: int, subject: str):
    expires_at = int(time.time()) + 24 * 3600
    token = _relay_jwt(expires_at, subject)

    payload = token.split(".")[1]
    assert len(payload) % 4 == payload_length_mod_4
    assert "_" in payload
    assert get_jwt_expiry_time(token) == expires_at


def test_relay_jwt_expiry_may_be_fractional():
    """RFC 7519 allows a NumericDate that is not an integer."""
    expires_at = time.time() + 24 * 3600

    assert get_jwt_expiry_time(_jwt_with_payload(json.dumps({"exp": expires_at}).encode())) == expires_at


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "subject",
    SUBJECTS_BY_PAYLOAD_LENGTH_MOD_4.values(),
    ids=[f"payload-length-mod-4-is-{n}" for n in SUBJECTS_BY_PAYLOAD_LENGTH_MOD_4],
)
async def test_relay_session_reuses_a_relay_jwt_far_from_expiry(relay_client: OpalRelayAPIClient, subject: str):
    """The token is requested once; a second request would find no mock."""
    with aioresponses() as mocked:
        mocked.post(RELAY_JWT_URL, status=200, payload={"token": _relay_jwt(time.time() + 24 * 3600, subject)})
        first = await relay_client.relay_session()
        second = await relay_client.relay_session()

    assert second is first


@pytest.mark.asyncio
async def test_relay_session_replaces_a_relay_jwt_near_expiry(relay_client: OpalRelayAPIClient):
    """The session that carried the replaced token is closed; one left to the garbage collector logs
    "Unclosed client session" at every refresh."""
    near_expiry = _relay_jwt(time.time() + MAX_JWT_EXPIRY_BUFFER_TIME / 2, SUBJECTS_BY_PAYLOAD_LENGTH_MOD_4[2])
    fresh = _relay_jwt(time.time() + 24 * 3600, SUBJECTS_BY_PAYLOAD_LENGTH_MOD_4[3])
    with aioresponses() as mocked:
        mocked.post(RELAY_JWT_URL, status=200, payload={"token": near_expiry})
        mocked.post(RELAY_JWT_URL, status=200, payload={"token": fresh})
        replaced = await relay_client.relay_session()
        refreshed = await relay_client.relay_session()
        reused = await relay_client.relay_session()

    assert refreshed is not replaced
    assert replaced.closed
    assert refreshed.headers["Authorization"] == f"Bearer {fresh}"
    assert reused is refreshed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token",
    [
        "opaque-token",
        "header.a.signature",
        _jwt_with_payload(b"not json"),
        _jwt_with_payload(b"\xff"),
        _jwt_with_payload(b"[1]"),
        _jwt_with_payload(b'{"sub": "pdp"}'),
        _jwt_with_payload(b'{"exp": "soon"}'),
        _jwt_with_payload(b'{"exp": true}'),
        _jwt_with_payload(b'{"exp": NaN}'),
    ],
    ids=[
        "no-payload-segment",
        "payload-not-base64url",
        "payload-not-json",
        "payload-not-utf8",
        "payload-not-an-object",
        "no-exp",
        "exp-a-string",
        "exp-a-boolean",
        "exp-not-finite",
    ],
)
async def test_a_relay_jwt_without_a_readable_expiry_is_refused_and_the_next_call_asks_again(
    relay_client: OpalRelayAPIClient, token: str
):
    """The expiry decides when to ask for a new token. A token kept without a readable one would fail
    every ping until a restart, and no new token would be requested."""
    fresh = _relay_jwt(time.time() + 24 * 3600)
    with aioresponses() as mocked:
        mocked.post(RELAY_JWT_URL, status=200, payload={"token": token})
        mocked.post(RELAY_JWT_URL, status=200, payload={"token": fresh})
        with pytest.raises(RelayAPIError, match="invalid result: a token whose expiry cannot be read") as excinfo:
            await relay_client.relay_session()
        session = await relay_client.relay_session()

    assert excinfo.value.service == "relay-jwt-api"
    assert excinfo.value.status_code == 200
    assert session.headers["Authorization"] == f"Bearer {fresh}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("policy_topics", "reported_topics"),
    [(["policy:topic"], ["policy_data", "policy:topic"]), (None, ["policy_data"])],
    ids=["policy-updater", "no-policy-updater"],
)
async def test_ping_reports_the_data_topics_and_any_policy_updater_topics(
    relay_client: OpalRelayAPIClient,
    monkeypatch: pytest.MonkeyPatch,
    policy_topics: list[str] | None,
    reported_topics: list[str],
):
    """OPAL builds no policy updater when OPAL_POLICY_UPDATER_ENABLED is false; the ping then reports
    only the data topics."""
    _use_pdp_state(monkeypatch, iter([RUNTIME_STATE]))
    monkeypatch.setattr(opal_client_config, "DATA_TOPICS", ["policy_data"])
    monkeypatch.setattr(opal_client_config, "SCOPE_ID", "default")
    policy_updater = None if policy_topics is None else SimpleNamespace(topics=policy_topics)
    monkeypatch.setattr(relay_client._opal_client, "policy_updater", policy_updater)
    with aioresponses() as mocked:
        mocked.post(RELAY_JWT_URL, status=200, payload={"token": _relay_jwt(time.time() + 24 * 3600)})
        mocked.post(PING_URL, status=202)
        await relay_client.send_ping()

    [ping] = [call for (_, url), calls in mocked.requests.items() if PING_URL.match(str(url)) for call in calls]
    assert ping.kwargs["json"]["topics"] == reported_topics


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
        mocked.post(RELAY_JWT_URL, status=200, payload={"token": _relay_jwt(time.time() + 24 * 3600)})
        mocked.post(PING_URL, status=500, body=b"\xff\xfe", content_type="text/plain; charset=utf-8")
        with pytest.raises(RelayAPIError, match="Server responded to the ping with a bad status: None") as excinfo:
            await relay_client.send_ping()

    assert excinfo.value.service == "relay-api"
    assert excinfo.value.status_code == 500
