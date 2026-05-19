from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from horizon.facts.client import CONSISTENT_UPDATE_HEADER, FactsClient
from starlette.requests import Request as FastApiRequest


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
async def test_build_forward_request_preserves_repeated_query_params():
    client = FactsClient()

    mock_remote_config = MagicMock()
    mock_remote_config.context = {"project_id": "proj1", "env_id": "env1"}

    with (
        patch("horizon.facts.client.get_remote_config", return_value=mock_remote_config),
        patch("horizon.facts.client.get_env_api_key", return_value="test_api_key"),
    ):
        request = _make_request(query_string=b"tenant=tenant_id&user=user_1&user=user_2")
        forward_request = await client.build_forward_request(request, "/role_assignments")

        assert forward_request.url.params.get_list("user") == ["user_1", "user_2"]
        assert forward_request.url.params["tenant"] == "tenant_id"


@pytest.mark.asyncio
async def test_build_forward_request_query_param_overrides_replace_existing_values():
    client = FactsClient()

    mock_remote_config = MagicMock()
    mock_remote_config.context = {"project_id": "proj1", "env_id": "env1"}

    with (
        patch("horizon.facts.client.get_remote_config", return_value=mock_remote_config),
        patch("horizon.facts.client.get_env_api_key", return_value="test_api_key"),
    ):
        request = _make_request(query_string=b"return_deleted=false&user=user_1&user=user_2")
        forward_request = await client.build_forward_request(
            request,
            "/role_assignments",
            query_params={"return_deleted": True},
        )

        assert forward_request.url.params.get_list("user") == ["user_1", "user_2"]
        assert forward_request.url.params["return_deleted"] == "true"


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
