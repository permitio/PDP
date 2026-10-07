from collections.abc import Iterator
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ByteStream, ResponseNotRead
from httpx import Response as HttpxResponse
from loguru import logger
from starlette.requests import Request as FastApiRequest

from horizon.facts.client import CONSISTENT_UPDATE_HEADER, FactsClient

if TYPE_CHECKING:
    from loguru import Record


def _make_request(headers: dict[str, str] | None = None, query_string: bytes = b"") -> FastApiRequest:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/facts/users",
        "raw_path": b"/facts/users",
        "query_string": query_string,
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
def facts_environment() -> Iterator[None]:
    """The remote config and API key build_forward_request reads, as the PDP has them once started."""
    remote_config = MagicMock()
    remote_config.context = {"project_id": "proj1", "env_id": "env1"}
    with (
        patch("horizon.facts.client.get_remote_config", return_value=remote_config),
        patch("horizon.facts.client.get_env_api_key", return_value="test_api_key"),
    ):
        yield


def _values_by_key(items: list[tuple[str, str]]) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for key, value in items:
        values.setdefault(key, []).append(value)
    return values


async def _forwarded_query(query_string: bytes, query_params: dict[str, Any] | None = None) -> dict[str, list[str]]:
    """Each query parameter of the request the PDP forwards for one with ``query_string``, with its decoded
    values in order."""
    request = _make_request(query_string=query_string)
    forward_request = await FactsClient().build_forward_request(request, "/role_assignments", query_params=query_params)
    return _values_by_key(forward_request.url.params.multi_items())


@pytest.mark.usefixtures("facts_environment")
@pytest.mark.parametrize(
    "query_string",
    [
        b"",
        b"user=u1",
        b"user=u1&user=u2",
        b"user=u2&role=r1&user=u1&tenant=t1&role=r2&search=b&tenant=t2&search=a",
        b"user=u1&user=u1",
        b"search=a%20b&search=c%26d&search=e%3Df&search=&search=%C3%A9",
    ],
    ids=["none", "single", "repeated", "interleaved-unsorted", "repeated-same-value", "encoded-values"],
)
@pytest.mark.asyncio
async def test_build_forward_request_forwards_every_query_parameter_value_in_order(query_string: bytes):
    incoming = _make_request(query_string=query_string).query_params.multi_items()

    assert await _forwarded_query(query_string) == _values_by_key(incoming)


@pytest.mark.usefixtures("facts_environment")
@pytest.mark.asyncio
async def test_build_forward_request_keeps_each_repeated_value_and_its_order():
    """The generic test above compares against the request's own parsing; pin the decoded values once."""
    forwarded = await _forwarded_query(b"user=u2&role=r1&user=u1&search=c%26d&search=&search=%C3%A9")

    assert forwarded == {"user": ["u2", "u1"], "role": ["r1"], "search": ["c&d", "", "\u00e9"]}


@pytest.mark.usefixtures("facts_environment")
@pytest.mark.parametrize(
    ("query_string", "expected"),
    [
        (b"", {"return_deleted": ["true"]}),
        (b"user=u1&user=u2", {"user": ["u1", "u2"], "return_deleted": ["true"]}),
        (b"return_deleted=false&user=u1&return_deleted=0&user=u2", {"user": ["u1", "u2"], "return_deleted": ["true"]}),
    ],
    ids=["no-request-params", "request-without-the-key", "request-sets-the-key-twice"],
)
@pytest.mark.asyncio
async def test_build_forward_request_query_params_replace_every_request_value_for_their_key(
    query_string: bytes, expected: dict[str, list[str]]
):
    """The router's return_deleted=True must win over whatever the caller sent for return_deleted."""
    assert await _forwarded_query(query_string, query_params={"return_deleted": True}) == expected


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
