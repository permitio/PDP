from typing import ClassVar

import pytest

from horizon.config import MOCK_API_KEY, ApiKeyLevel, sidecar_config
from horizon.startup import api_keys
from horizon.startup.exceptions import ApiKeyError
from horizon.system.consts import GUNICORN_EXIT_APP


@pytest.fixture
def keys(monkeypatch):
    """Start every test with no API key of any level configured."""

    def configure(**values):
        defaults = {
            "API_KEY": MOCK_API_KEY,
            "ORG_API_KEY": None,
            "PROJECT_API_KEY": None,
            "ACTIVE_ENV": None,
            "ACTIVE_PROJECT": None,
        }
        for name, value in (defaults | values).items():
            monkeypatch.setattr(sidecar_config, name, value)

    configure()
    monkeypatch.setattr(api_keys, "_env_api_key", None)
    return configure


class FakeBlockingRequest:
    response: ClassVar[dict] = {}
    urls: ClassVar[list[str]] = []

    def __init__(self, token, timeout):
        self.token = token
        self.timeout = timeout

    def get(self, url):
        self.urls.append(url)
        return self.response


def test_an_environment_key_wins(keys):
    keys(API_KEY="env-key", ORG_API_KEY="org-key")
    assert api_keys.EnvApiKeyFetcher().api_key_level == ApiKeyLevel.ENVIRONMENT


@pytest.mark.usefixtures("keys")
def test_no_key_at_all_is_an_api_key_error():
    with pytest.raises(ApiKeyError, match="No API key specified"):
        api_keys.EnvApiKeyFetcher()


def test_a_project_key_needs_an_active_env(keys):
    keys(PROJECT_API_KEY="project-key")
    with pytest.raises(ApiKeyError, match="PDP_ACTIVE_ENV is not"):
        api_keys.EnvApiKeyFetcher()


def test_an_org_key_needs_an_active_project(keys):
    keys(ORG_API_KEY="org-key", ACTIVE_ENV="env")
    with pytest.raises(ApiKeyError, match="PDP_ACTIVE_PROJECT are not"):
        api_keys.EnvApiKeyFetcher()


@pytest.mark.usefixtures("keys")
def test_get_env_api_key_exits_the_worker_on_a_missing_key():
    with pytest.raises(SystemExit) as exc_info:
        api_keys.get_env_api_key()
    assert exc_info.value.code == GUNICORN_EXIT_APP
    assert isinstance(exc_info.value.__cause__, ApiKeyError)


def test_get_scope_returns_the_scope_dict(keys, monkeypatch):
    keys(API_KEY="env-key")
    monkeypatch.setattr(api_keys.EnvApiKeyFetcher, "fetch_scope", lambda _self, _key: {"project_id": "p1"})
    assert api_keys.get_scope("org-key") == {"project_id": "p1"}


def test_get_scope_raises_when_the_control_plane_returns_nothing(keys, monkeypatch):
    keys(API_KEY="env-key")
    monkeypatch.setattr(api_keys.EnvApiKeyFetcher, "fetch_scope", lambda _self, _key: None)
    with pytest.raises(ApiKeyError, match="Failed to get the scope"):
        api_keys.get_scope("org-key")


def test_a_response_without_a_secret_is_an_api_key_error(keys, monkeypatch):
    keys(API_KEY="env-key")
    monkeypatch.setattr(api_keys, "BlockingRequest", FakeBlockingRequest)
    monkeypatch.setattr(FakeBlockingRequest, "response", {})
    with pytest.raises(ApiKeyError, match="No secret found"):
        api_keys.EnvApiKeyFetcher()._fetch_env_key("org-key", "project", "env")


def test_the_secret_is_returned(keys, monkeypatch):
    keys(API_KEY="env-key")
    monkeypatch.setattr(api_keys, "BlockingRequest", FakeBlockingRequest)
    monkeypatch.setattr(FakeBlockingRequest, "response", {"secret": "env-secret"})
    monkeypatch.setattr(FakeBlockingRequest, "urls", [])
    fetcher = api_keys.EnvApiKeyFetcher(backend_url="https://control.plane")
    assert fetcher._fetch_env_key("org-key", "project", "env") == "env-secret"
    assert FakeBlockingRequest.urls == ["https://control.plane/v2/api-key/project/env"]
