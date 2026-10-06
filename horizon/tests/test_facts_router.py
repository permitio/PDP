from collections.abc import Iterator
from dataclasses import dataclass
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from loguru import logger
from starlette import status
from starlette.requests import Request as FastApiRequest

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


@pytest.fixture
def logged_warnings() -> Iterator[list["Record"]]:
    """Every loguru record at WARNING or above emitted during the test."""
    records: list[Record] = []
    sink_id = logger.add(lambda message: records.append(message.record), level="WARNING")
    yield records
    logger.remove(sink_id)


def _use_a_subscriber_whose_updater_has_no_pubsub_client(facts: FactsHarness) -> None:
    """Swap the mocked subscriber for the real one, over a stand-in for an OPAL data updater that has
    not started yet and so has no pub/sub client to publish on."""
    reporter = SimpleNamespace(report_update_results=AsyncMock())
    updater = SimpleNamespace(_should_send_reports=False, callbacks_reporter=reporter, _client=None)
    subscriber = DataUpdateSubscriber(updater)  # ty: ignore[invalid-argument-type]  # stand-in for OPAL's DataUpdater
    facts.app.dependency_overrides[get_data_update_subscriber] = lambda: subscriber


def test_facts_write_the_pdp_could_not_publish_is_424_under_fail_policy_and_not_called_a_timeout(
    facts, logged_warnings: list["Record"]
):
    _use_a_subscriber_whose_updater_has_no_pubsub_client(facts)

    response = _create_user(facts, {"X-Timeout-Policy": "fail"})

    assert response.status_code == status.HTTP_424_FAILED_DEPENDENCY
    detail = response.json()["detail"]
    assert detail.startswith("Update was not published")
    assert "no pub/sub client" in detail
    assert len(facts.backend_calls) == 1
    messages = [record["message"] for record in logged_warnings]
    assert any("was not published" in message and "failing the request" in message for message in messages)
    assert not any("Timeout" in message for message in messages)


def test_facts_write_the_pdp_could_not_publish_returns_the_backend_response_under_ignore_policy(
    facts, logged_warnings: list["Record"]
):
    _use_a_subscriber_whose_updater_has_no_pubsub_client(facts)

    response = _create_user(facts, {"X-Timeout-Policy": "ignore"})

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == CREATED_USER
    messages = [record["message"] for record in logged_warnings]
    assert any("was not published" in message and "returning the backend response" in message for message in messages)
    assert not any("Timeout" in message for message in messages)
