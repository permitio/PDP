from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from horizon.facts.client import FactsClient
from horizon.facts.router import forward_remaining_requests, forward_request_then_wait_for_update
from httpx import Response as HttpxResponse
from starlette.requests import Request as FastApiRequest


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
    _, kwargs = client.send_forward_request.await_args
    assert kwargs.get("is_consistent_update") is True


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
