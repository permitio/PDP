from collections.abc import Callable, Iterator
from dataclasses import dataclass
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi_websocket_pubsub.exceptions import PubSubClientInvalidStateException
from fastapi_websocket_rpc.rpc_channel import RpcChannelClosedException
from httpx import Response as HttpxResponse
from loguru import logger
from starlette import status
from starlette.requests import Request as FastApiRequest
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK
from websockets.frames import Close

from horizon.config import sidecar_config
from horizon.facts.client import FactsClient, get_facts_client
from horizon.facts.dependencies import get_data_update_subscriber
from horizon.facts.opal_forwarder import get_opal_data_base_url, get_opal_data_topic
from horizon.facts.router import facts_router, forward_remaining_requests, forward_request_then_wait_for_update
from horizon.facts.update_subscriber import DataUpdateSubscriber

if TYPE_CHECKING:
    from loguru import Record

PDP_TOKEN = "facts-router-test-token"
AUTH = {"Authorization": f"Bearer {PDP_TOKEN}"}
CREATED_USER = {"id": "4f1d2a60-0000-4000-8000-000000000001", "key": "user-1"}


def _make_request(headers: dict[str, str] | None = None) -> FastApiRequest:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/facts/users",
        "raw_path": b"/facts/users",
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return FastApiRequest(scope, receive)


@pytest.mark.asyncio
async def test_forward_request_then_wait_for_update_sets_consistent_update_flag():
    """The wait-for-update proxy path MUST pass is_consistent_update=True to the client."""
    client = MagicMock(spec=FactsClient)
    client.send_forward_request = AsyncMock(return_value=HttpxResponse(status_code=204))
    client.extract_body = MagicMock(return_value=None)
    client.convert_response = MagicMock(return_value=MagicMock())

    update_subscriber = MagicMock()
    request = _make_request(headers={"authorization": "Bearer token"})

    await forward_request_then_wait_for_update(
        client,
        request,
        update_subscriber,
        wait_timeout=0,
        path="/users",
        entries_callback=lambda _r, _body, _update_id: [],
    )

    assert client.send_forward_request.await_count == 1
    call = client.send_forward_request.await_args
    assert call is not None
    assert call.kwargs.get("is_consistent_update") is True


@pytest.mark.asyncio
async def test_forward_remaining_requests_does_not_set_consistent_update_header():
    """The fallback proxy route MUST NOT mark the request as a consistent update."""
    client = FactsClient()

    mock_remote_config = MagicMock()
    mock_remote_config.context = {"project_id": "proj1", "env_id": "env1"}

    captured = {}

    async def fake_send(request, *, stream=False):  # noqa: ARG001
        captured["headers"] = dict(request.headers)
        return HttpxResponse(status_code=204)

    with (
        patch("horizon.facts.client.get_remote_config", return_value=mock_remote_config),
        patch("horizon.facts.client.get_env_api_key", return_value="test_api_key"),
        patch.object(FactsClient, "send", side_effect=fake_send),
    ):
        request = _make_request(headers={"authorization": "Bearer token", "content-type": "application/json"})
        await forward_remaining_requests(request, client, full_path="some/other/path")

    assert "X-Permit-Consistent-Update" not in captured["headers"]
    assert "x-permit-consistent-update" not in captured["headers"]


@dataclass
class FactsHarness:
    app: FastAPI
    client: TestClient
    subscriber: MagicMock
    backend_calls: list[httpx.Request]


@pytest.fixture
def facts(monkeypatch) -> Iterator[FactsHarness]:
    """The facts router as the PDP mounts it, with its two boundaries replaced: the control
    plane's facts API (an httpx MockTransport answering every call with CREATED_USER) and the
    OPAL update subscriber, whose publish_and_wait result each test sets."""
    remote_config = MagicMock()
    remote_config.context = {"org_id": "org", "project_id": "proj", "env_id": "env", "client_id": "pdp"}
    monkeypatch.setattr("horizon.startup.remote_config._remote_config", remote_config)
    monkeypatch.setattr("horizon.startup.api_keys._env_api_key", PDP_TOKEN)
    monkeypatch.setattr(sidecar_config, "LOCAL_FACTS_TIMEOUT_POLICY", "ignore")
    # Both are @cache'd off the remote config: start clean and leave nothing built from this fake.
    get_opal_data_base_url.cache_clear()
    get_opal_data_topic.cache_clear()

    backend_calls: list[httpx.Request] = []

    def control_plane(request: httpx.Request) -> httpx.Response:
        backend_calls.append(request)
        return httpx.Response(status.HTTP_200_OK, json=CREATED_USER)

    facts_client = FactsClient()
    facts_client._client = httpx.AsyncClient(
        base_url="http://control-plane", transport=httpx.MockTransport(control_plane)
    )
    subscriber = MagicMock(spec=DataUpdateSubscriber)
    subscriber.publish_and_wait = AsyncMock(return_value=True)

    app = FastAPI()
    app.include_router(facts_router, prefix="/facts")
    app.dependency_overrides[get_facts_client] = lambda: facts_client
    app.dependency_overrides[get_data_update_subscriber] = lambda: subscriber

    yield FactsHarness(app=app, client=TestClient(app), subscriber=subscriber, backend_calls=backend_calls)

    get_opal_data_base_url.cache_clear()
    get_opal_data_topic.cache_clear()


def _create_user(facts: FactsHarness, headers: dict[str, str]) -> httpx.Response:
    return facts.client.post("/facts/users", headers={**AUTH, **headers}, json={"key": CREATED_USER["key"]})


@pytest.mark.parametrize(
    ("update_arrived", "config_policy", "headers"),
    [
        (True, "ignore", {"X-Timeout-Policy": "fail"}),
        (True, "ignore", {"X-Timeout-Policy": "ignore"}),
        (False, "ignore", {"X-Timeout-Policy": "ignore"}),
        (False, "fail", {"X-Timeout-Policy": "IGNORE"}),
        (False, "ignore", {}),
    ],
    ids=[
        "arrived-fail",
        "arrived-ignore",
        "timed-out-ignore",
        "timed-out-header-overrides-config-fail",
        "timed-out-config-default-ignore",
    ],
)
def test_facts_write_returns_the_backend_response(facts, monkeypatch, update_arrived, config_policy, headers):
    """The backend response passes through when the update arrived, or when it timed out
    under the ignore policy."""
    monkeypatch.setattr(sidecar_config, "LOCAL_FACTS_TIMEOUT_POLICY", config_policy)
    facts.subscriber.publish_and_wait.return_value = update_arrived

    response = _create_user(facts, headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == CREATED_USER
    facts.subscriber.publish_and_wait.assert_awaited_once()


@pytest.mark.parametrize(
    ("config_policy", "headers"),
    [
        ("ignore", {"X-Timeout-Policy": "fail"}),
        ("ignore", {"X-Timeout-Policy": "FAIL"}),
        ("fail", {}),
    ],
    ids=["header-fail", "header-is-case-insensitive", "config-default-fail"],
)
def test_facts_write_timed_out_under_fail_policy_is_424(facts, monkeypatch, config_policy, headers):
    monkeypatch.setattr(sidecar_config, "LOCAL_FACTS_TIMEOUT_POLICY", config_policy)
    facts.subscriber.publish_and_wait.return_value = False

    response = _create_user(facts, headers)

    assert response.status_code == status.HTTP_424_FAILED_DEPENDENCY
    assert response.json() == {"detail": "Timeout waiting for update to be received"}
    assert len(facts.backend_calls) == 1


def test_facts_write_waits_for_the_requested_timeout(facts):
    _create_user(facts, {"X-Wait-timeout": "0.5"})

    assert facts.subscriber.publish_and_wait.await_args.kwargs["timeout"] == 0.5


@pytest.mark.parametrize(
    ("header", "value"),
    [("X-Timeout-Policy", "sometimes"), ("X-Timeout-Policy", ""), ("X-Wait-timeout", "soon")],
)
def test_facts_write_with_an_invalid_wait_header_is_400_before_forwarding(facts, header, value):
    response = _create_user(facts, {header: value})

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"].startswith(f"Invalid {header} header")
    assert facts.backend_calls == []
    facts.subscriber.publish_and_wait.assert_not_awaited()


def test_facts_read_forwards_every_value_of_a_repeated_query_parameter(facts):
    """GET /facts/role_assignments?user=a&user=b lists both users' assignments: permitio/PDP#299."""
    response = facts.client.get("/facts/role_assignments?user=u2&tenant=t1&user=u1&role=r1&role=r2", headers=AUTH)

    assert response.status_code == status.HTTP_200_OK
    (backend_call,) = facts.backend_calls
    assert backend_call.url.path == "/v2/facts/proj/env/role_assignments"
    params = backend_call.url.params
    assert sorted(params.keys()) == ["role", "tenant", "user"]
    assert params.get_list("user") == ["u2", "u1"]
    assert params.get_list("tenant") == ["t1"]
    assert params.get_list("role") == ["r1", "r2"]


@pytest.mark.parametrize(
    ("method", "path"),
    [("DELETE", "/facts/role_assignments"), ("DELETE", "/facts/users/user-1/roles")],
    ids=["role-assignments", "user-roles"],
)
def test_facts_unassign_sends_return_deleted_true_whatever_the_caller_sent(facts, method, path):
    facts.client.request(
        method,
        f"{path}?return_deleted=false&tenant=t1&tenant=t2&return_deleted=0",
        headers=AUTH,
        json={"user": "user-1", "role": "viewer", "tenant": "t1"},
    )

    (backend_call,) = facts.backend_calls
    params = backend_call.url.params
    assert sorted(params.keys()) == ["return_deleted", "tenant"]
    assert params.get_list("return_deleted") == ["true"]
    assert params.get_list("tenant") == ["t1", "t2"]


@pytest.fixture
def logged_warnings() -> Iterator[list["Record"]]:
    """Every loguru record at WARNING or above emitted during the test."""
    records: list[Record] = []
    sink_id = logger.add(lambda message: records.append(message.record), level="WARNING")
    yield records
    logger.remove(sink_id)


def _pubsub_client_raising(error: Exception) -> AsyncMock:
    client = AsyncMock()
    client.publish.side_effect = error
    return client


# The pub/sub client the OPAL data updater holds when the PDP cannot confirm a publish on it, and the
# reason the 424 detail gives. The updater has no client until it starts. Its client raises
# PubSubClientInvalidStateException until it connects. It keeps a closed connection until it
# reconnects and raises on it: ConnectionClosedError after the server dropped it, ConnectionClosedOK
# after the PDP closed it (OPAL's DataUpdater.stop(), run by /connectivity/disable, disconnects the
# client but keeps it). In those cases the update was not sent. RpcChannelClosedException comes when
# the connection closes after the update was sent and before the server answered; the server starts
# the broadcast before it answers, so the update may have been published.
UNCONFIRMED_PUBSUB_CLIENTS = [
    pytest.param(lambda: None, "the OPAL data updater has no pub/sub client yet", id="no-client"),
    pytest.param(
        lambda: _pubsub_client_raising(PubSubClientInvalidStateException("Client not connected")),
        "no live connection to the OPAL server (PubSubClientInvalidStateException: Client not connected)",
        id="not-connected",
    ),
    pytest.param(
        lambda: _pubsub_client_raising(ConnectionClosedError(Close(1012, ""), Close(1012, ""), rcvd_then_sent=True)),
        "no live connection to the OPAL server "
        "(ConnectionClosedError: received 1012 (service restart); then sent 1012 (service restart))",
        id="connection-closed-by-the-server",
    ),
    pytest.param(
        lambda: _pubsub_client_raising(ConnectionClosedOK(Close(1000, ""), Close(1000, ""), rcvd_then_sent=False)),
        "no live connection to the OPAL server (ConnectionClosedOK: sent 1000 (OK); then received 1000 (OK))",
        id="connection-closed-by-the-pdp",
    ),
    pytest.param(
        lambda: _pubsub_client_raising(RpcChannelClosedException("Channel Closed before RPC response for c-1")),
        "closed before the server confirmed the publish, so the update may have been published "
        "(RpcChannelClosedException: Channel Closed before RPC response for c-1)",
        id="channel-closed-before-the-reply",
    ),
]


def _use_the_real_subscriber(facts: FactsHarness, pubsub_client: AsyncMock | None) -> None:
    """Swap the mocked subscriber for the real one, over a stand-in for an OPAL data updater whose
    pub/sub client is ``pubsub_client`` (None before the updater starts)."""
    reporter = SimpleNamespace(report_update_results=AsyncMock())
    updater = SimpleNamespace(_should_send_reports=False, callbacks_reporter=reporter, _client=pubsub_client)
    subscriber = DataUpdateSubscriber(updater)  # ty: ignore[invalid-argument-type]  # stand-in for OPAL's DataUpdater
    facts.app.dependency_overrides[get_data_update_subscriber] = lambda: subscriber


@pytest.mark.parametrize(("make_pubsub_client", "reason"), UNCONFIRMED_PUBSUB_CLIENTS)
def test_facts_write_whose_publish_is_unconfirmed_is_424_under_fail_policy_and_not_called_a_timeout(
    facts,
    logged_warnings: list["Record"],
    make_pubsub_client: Callable[[], AsyncMock | None],
    reason: str,
):
    _use_the_real_subscriber(facts, make_pubsub_client())

    response = _create_user(facts, {"X-Timeout-Policy": "fail"})

    assert response.status_code == status.HTTP_424_FAILED_DEPENDENCY
    detail = response.json()["detail"]
    assert detail.startswith("Update could not be confirmed as published: ")
    assert reason in detail
    assert len(facts.backend_calls) == 1
    messages = [record["message"] for record in logged_warnings]
    assert any(
        "could not be confirmed as published" in message and reason in message and "failing the request" in message
        for message in messages
    )
    assert not any("Timeout" in message for message in messages)


@pytest.mark.parametrize(("make_pubsub_client", "reason"), UNCONFIRMED_PUBSUB_CLIENTS)
def test_facts_write_whose_publish_is_unconfirmed_returns_the_backend_response_under_ignore_policy(
    facts,
    logged_warnings: list["Record"],
    make_pubsub_client: Callable[[], AsyncMock | None],
    reason: str,
):
    _use_the_real_subscriber(facts, make_pubsub_client())

    response = _create_user(facts, {"X-Timeout-Policy": "ignore"})

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == CREATED_USER
    messages = [record["message"] for record in logged_warnings]
    assert any(
        "could not be confirmed as published" in message
        and reason in message
        and "returning the backend response" in message
        for message in messages
    )
    assert not any("Timeout" in message for message in messages)
