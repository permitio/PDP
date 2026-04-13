from unittest.mock import MagicMock, patch

import pytest
from horizon.facts.client import CONSISTENT_UPDATE_HEADER, FactsClient
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


def test_consistent_update_header_constant():
    assert CONSISTENT_UPDATE_HEADER == "X-Permit-Consistent-Update"


@pytest.mark.asyncio
async def test_build_forward_request_adds_consistent_update_header():
    """Every forwarded request should carry the X-Permit-Consistent-Update: true header."""
    client = FactsClient()

    mock_remote_config = MagicMock()
    mock_remote_config.context = {"project_id": "proj1", "env_id": "env1"}

    with (
        patch("horizon.facts.client.get_remote_config", return_value=mock_remote_config),
        patch("horizon.facts.client.get_env_api_key", return_value="test_api_key"),
    ):
        request = _make_request(headers={"authorization": "Bearer user_token", "content-type": "application/json"})
        forward_request = await client.build_forward_request(request, "/users")

        assert forward_request.headers.get(CONSISTENT_UPDATE_HEADER) == "true"
