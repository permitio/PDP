"""Tests for horizon/startup/api_keys.py.

The control plane is faked at the network boundary (``requests.get``), so the real
BlockingRequest builds the Authorization header and turns a 401 into InvalidPDPTokenError.
"""

from http import HTTPStatus

import pytest
import requests
from opal_common.logger import logger
from tenacity import stop

from horizon.config import MOCK_API_KEY, ApiKeyLevel, sidecar_config
from horizon.startup import api_keys
from horizon.startup.exceptions import ApiKeyError, InvalidPDPTokenError
from horizon.system.consts import GUNICORN_EXIT_APP

BACKEND = "https://control.plane"
SCOPE_URL = f"{BACKEND}/v2/api-key/scope"
# One attempt, so an error path fails at once instead of after ten backed-off retries.
ONE_ATTEMPT = {"stop": stop.stop_after_attempt(1), "reraise": True}


class FakeResponse:
    def __init__(self, status_code: int, body: object):
        self.status_code = status_code
        self._body = body

    def json(self) -> object:
        return self._body


class FakeControlPlane:
    """Answers GETs per (url, bearer token); any other pair is rejected with a 401."""

    def __init__(self) -> None:
        self.answers: dict[tuple[str, str], object] = {}
        self.requests: list[tuple[str, str | None]] = []

    def get(self, url, headers=None, params=None, timeout=None):  # noqa: ARG002 - requests.get's signature
        authorization = (headers or {}).get("Authorization")
        token = authorization.removeprefix("Bearer ") if authorization else None
        self.requests.append((url, token))
        answer = self.answers.get((url, token))
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            return FakeResponse(HTTPStatus.UNAUTHORIZED, {"detail": "Unauthorized"})
        return FakeResponse(HTTPStatus.OK, answer)


@pytest.fixture
def control_plane(monkeypatch) -> FakeControlPlane:
    plane = FakeControlPlane()
    monkeypatch.setattr(requests, "get", plane.get)
    monkeypatch.setattr(api_keys, "DEFAULT_RETRY_CONFIG", ONE_ATTEMPT)
    return plane


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


@pytest.fixture
def logged():
    messages: list[str] = []
    handler_id = logger.add(messages.append, format="{message}", level="WARNING")
    yield messages
    logger.remove(handler_id)


def env_api_key() -> str:
    return api_keys.EnvApiKeyFetcher(backend_url=BACKEND, retry_config=ONE_ATTEMPT).get_env_api_key_by_level()


# --------------------------------------------------------------------------- key level


def test_an_environment_key_wins(keys):
    keys(API_KEY="env-key", ORG_API_KEY="org-key")
    assert api_keys.EnvApiKeyFetcher().api_key_level == ApiKeyLevel.ENVIRONMENT


def test_an_environment_key_is_used_as_is_without_asking_the_control_plane(keys, control_plane):
    keys(API_KEY="env-key")
    assert env_api_key() == "env-key"
    assert control_plane.requests == []


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


# --------------------------------------------------------------------------- project key


def test_a_project_key_alone_gets_its_project_from_its_own_scope(keys, control_plane):
    keys(PROJECT_API_KEY="project-key", ACTIVE_ENV="env")
    control_plane.answers[SCOPE_URL, "project-key"] = {"project_id": "p1"}
    control_plane.answers[f"{BACKEND}/v2/api-key/p1/env", "project-key"] = {"secret": "env-secret"}

    assert env_api_key() == "env-secret"
    assert control_plane.requests == [
        (SCOPE_URL, "project-key"),
        (f"{BACKEND}/v2/api-key/p1/env", "project-key"),
    ]


def test_a_project_key_ignores_an_org_key_and_active_project_set_alongside_it(keys, control_plane):
    keys(PROJECT_API_KEY="project-key", ORG_API_KEY="org-key", ACTIVE_PROJECT="other", ACTIVE_ENV="env")
    control_plane.answers[SCOPE_URL, "project-key"] = {"project_id": "p1"}
    control_plane.answers[f"{BACKEND}/v2/api-key/p1/env", "project-key"] = {"secret": "env-secret"}

    assert env_api_key() == "env-secret"
    assert all(token == "project-key" for _, token in control_plane.requests)


def test_a_scope_without_a_project_id_is_an_api_key_error_naming_the_key_and_url(keys, control_plane):
    keys(PROJECT_API_KEY="org-level-key", ACTIVE_ENV="env")
    control_plane.answers[SCOPE_URL, "org-level-key"] = {"organization_id": "o1", "project_id": None}

    with pytest.raises(ApiKeyError) as exc_info:
        env_api_key()
    assert "PDP_PROJECT_API_KEY" in str(exc_info.value)
    assert SCOPE_URL in str(exc_info.value)


def test_an_unreachable_scope_endpoint_is_an_api_key_error(keys, control_plane, logged):
    keys(PROJECT_API_KEY="project-key", ACTIVE_ENV="env")
    control_plane.answers[SCOPE_URL, "project-key"] = requests.ConnectionError("connection refused")

    with pytest.raises(ApiKeyError, match="returned no project_id"):
        env_api_key()
    assert any(SCOPE_URL in line and "connection refused" in line for line in logged)


# --------------------------------------------------------------------------- org key


def test_an_org_key_fetches_the_active_project_and_env_key(keys, control_plane):
    keys(ORG_API_KEY="org-key", ACTIVE_PROJECT="proj", ACTIVE_ENV="env")
    control_plane.answers[f"{BACKEND}/v2/api-key/proj/env", "org-key"] = {"secret": "env-secret"}

    assert env_api_key() == "env-secret"
    assert control_plane.requests == [(f"{BACKEND}/v2/api-key/proj/env", "org-key")]


def test_a_response_without_a_secret_is_an_api_key_error_naming_the_url(keys, control_plane):
    keys(ORG_API_KEY="org-key", ACTIVE_PROJECT="proj", ACTIVE_ENV="env")
    control_plane.answers[f"{BACKEND}/v2/api-key/proj/env", "org-key"] = {}

    with pytest.raises(ApiKeyError, match="No secret found") as exc_info:
        env_api_key()
    assert f"{BACKEND}/v2/api-key/proj/env" in str(exc_info.value)


# --------------------------------------------------------------------------- get_env_api_key


@pytest.mark.usefixtures("keys")
def test_get_env_api_key_exits_the_worker_on_a_missing_key():
    with pytest.raises(SystemExit) as exc_info:
        api_keys.get_env_api_key()
    assert exc_info.value.code == GUNICORN_EXIT_APP
    assert isinstance(exc_info.value.__cause__, ApiKeyError)


def test_a_rejected_key_exits_the_worker_and_logs_the_url_and_the_401(keys, control_plane, logged):
    keys(ORG_API_KEY="revoked-key", ACTIVE_PROJECT="proj", ACTIVE_ENV="env")
    env_key_url = f"{sidecar_config.CONTROL_PLANE}/v2/api-key/proj/env"

    with pytest.raises(SystemExit) as exc_info:
        api_keys.get_env_api_key()
    assert exc_info.value.code == GUNICORN_EXIT_APP
    assert isinstance(exc_info.value.__cause__, InvalidPDPTokenError)
    assert control_plane.requests == [(env_key_url, "revoked-key")]
    failure = next(line for line in logged if "Failed to get Environment API Key" in line)
    assert "InvalidPDPTokenError" in failure
    assert env_key_url in failure
    assert "401" in failure
