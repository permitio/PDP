from collections.abc import Iterator
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ByteStream, ResponseNotRead
from httpx import Response as HttpxResponse
from loguru import logger
from starlette.requests import Request as FastApiRequest

from horizon.facts.client import CONSISTENT_UPDATE_HEADER, FactsClient

if TYPE_CHECKING:
    from loguru import Record


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
async def test_build_forward_request_adds_header_when_consistent_update():
    """When is_consistent_update=True, request should carry the X-Permit-Consistent-Update header with value 'true'."""
    client = FactsClient()

    mock_remote_config = MagicMock()
    mock_remote_config.context = {"project_id": "proj1", "env_id": "env1"}

    with (
        patch("horizon.facts.client.get_remote_config", return_value=mock_remote_config),
        patch("horizon.facts.client.get_env_api_key", return_value="test_api_key"),
    ):
        request = _make_request(headers={"authorization": "Bearer user_token", "content-type": "application/json"})
        forward_request = await client.build_forward_request(request, "/users", is_consistent_update=True)

        # Check the literal header name (not the constant) so a constant rename is caught by tests.
        assert "X-Permit-Consistent-Update" in forward_request.headers
        assert forward_request.headers["X-Permit-Consistent-Update"] == "true"


@pytest.mark.asyncio
async def test_build_forward_request_omits_header_by_default():
    """By default (fallback proxy path), the request should NOT carry the consistent-update header."""
    client = FactsClient()

    mock_remote_config = MagicMock()
    mock_remote_config.context = {"project_id": "proj1", "env_id": "env1"}

    with (
        patch("horizon.facts.client.get_remote_config", return_value=mock_remote_config),
        patch("horizon.facts.client.get_env_api_key", return_value="test_api_key"),
    ):
        request = _make_request(headers={"authorization": "Bearer user_token", "content-type": "application/json"})
        forward_request = await client.build_forward_request(request, "/anything")

        assert forward_request.headers.get(CONSISTENT_UPDATE_HEADER) is None


@pytest.mark.asyncio
async def test_send_forward_request_propagates_consistent_update_kwarg():
    """send_forward_request must plumb is_consistent_update into the built request's headers."""
    client = FactsClient()

    mock_remote_config = MagicMock()
    mock_remote_config.context = {"project_id": "proj1", "env_id": "env1"}

    with (
        patch("horizon.facts.client.get_remote_config", return_value=mock_remote_config),
        patch("horizon.facts.client.get_env_api_key", return_value="test_api_key"),
        patch.object(FactsClient, "send", new_callable=AsyncMock) as mock_send,
    ):
        request = _make_request(headers={"authorization": "Bearer user_token", "content-type": "application/json"})
        await client.send_forward_request(request, "/users", is_consistent_update=True)

        assert mock_send.await_count == 1
        assert mock_send.call_args is not None
        sent_request = mock_send.call_args.args[0]
        assert sent_request.headers.get("X-Permit-Consistent-Update") == "true"


@pytest.fixture
def logged_errors() -> Iterator[list["Record"]]:
    """Every loguru record at ERROR or above emitted during the test."""
    records: list[Record] = []
    sink_id = logger.add(lambda message: records.append(message.record), level="ERROR")
    yield records
    logger.remove(sink_id)


def test_extract_body_returns_the_decoded_json():
    assert FactsClient.extract_body(HttpxResponse(200, json={"id": "user-1"})) == {"id": "user-1"}


@pytest.mark.parametrize(
    "content",
    [b"not json", b'{"truncated": ', b'{"key": "\xff"}'],
    ids=["not-json", "truncated-json", "not-utf8"],
)
def test_extract_body_skips_the_wait_on_an_undecodable_body(content: bytes, logged_errors: list["Record"]):
    """A 2xx body that does not decode as JSON leaves nothing to wait for: None, logged with its traceback."""
    assert FactsClient.extract_body(HttpxResponse(200, content=content)) is None
    assert len(logged_errors) == 1
    assert logged_errors[0]["exception"] is not None


def test_extract_body_raises_on_a_streamed_response_nobody_read():
    """Only an undecodable body is skipped. A streamed response that was never read is a caller bug,
    so it must surface instead of silently skipping the wait for the update."""
    response = HttpxResponse(200, stream=ByteStream(b"{}"))

    with pytest.raises(ResponseNotRead):
        FactsClient.extract_body(response)
