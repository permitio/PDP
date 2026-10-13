from collections.abc import Iterator
from typing import Any

import pytest
from loguru import logger
from pydantic import ValidationError

from horizon.startup import remote_config
from horizon.startup.remote_config import RemoteConfigFetcher

FAKE_CLIENT_TOKEN = "fake-opal-client-token-0123456789"


@pytest.fixture
def logged() -> Iterator[list[str]]:
    """Every log line as plain text and as the JSON a serializing sink writes, extras included."""
    lines: list[str] = []
    text_sink = logger.add(lines.append, format="{message} | {extra}", level="DEBUG")
    json_sink = logger.add(lines.append, serialize=True, level="DEBUG")
    yield lines
    logger.remove(text_sink)
    logger.remove(json_sink)


@pytest.fixture
def fetcher(monkeypatch) -> RemoteConfigFetcher:
    monkeypatch.setattr(remote_config, "get_env_api_key", lambda: "fake-env-key")
    monkeypatch.setattr(remote_config.PersistentStateHandler, "build_state_payload_sync", dict)
    return RemoteConfigFetcher(backend_url="http://control-plane.invalid")


def _control_plane_returns(monkeypatch, body: dict[str, Any]) -> None:
    monkeypatch.setattr(remote_config.BlockingRequest, "post", lambda *_args, **_kwargs: body)


def test_an_invalid_remote_config_logs_the_validation_error_without_the_response_body(
    monkeypatch, fetcher: RemoteConfigFetcher, logged: list[str]
):
    _control_plane_returns(
        monkeypatch, {"opal_client": {"CLIENT_TOKEN": FAKE_CLIENT_TOKEN}, "context": "not-a-mapping"}
    )

    with pytest.raises(ValidationError):
        fetcher._fetch_config()

    assert any("Got invalid config contents" in line and "context" in line for line in logged)
    assert not [line for line in logged if FAKE_CLIENT_TOKEN in line]


def test_a_valid_remote_config_is_returned_without_logging_its_client_token(
    monkeypatch, fetcher: RemoteConfigFetcher, logged: list[str]
):
    body = {"opal_client": {"CLIENT_TOKEN": FAKE_CLIENT_TOKEN}, "context": {"org_id": "org"}}
    _control_plane_returns(monkeypatch, body)

    config = fetcher._fetch_config()

    assert config.opal_client == {"CLIENT_TOKEN": FAKE_CLIENT_TOKEN}
    assert any("Received remote config" in line for line in logged)
    assert not [line for line in logged if FAKE_CLIENT_TOKEN in line]
