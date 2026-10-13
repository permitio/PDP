"""Tests for horizon/startup/api_keys.py.

The control plane is faked at the network boundary (``requests.get``), so the real
BlockingRequest builds the Authorization header and turns a 401 into InvalidPDPTokenError.
"""

import re
import stat
from http import HTTPStatus
from pathlib import Path

import pytest
import requests
from opal_common.logger import logger
from tenacity import stop

from horizon import pdp
from horizon.config import MOCK_API_KEY, ApiKeyLevel, sidecar_config
from horizon.startup import api_keys
from horizon.startup.exceptions import ApiKeyError, InvalidPDPTokenError
from horizon.state import PersistentStateHandler
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


def test_a_project_key_alone_gets_its_project_from_its_own_scope(keys, control_plane, logged):
    keys(PROJECT_API_KEY="project-key", ACTIVE_ENV="env")
    control_plane.answers[SCOPE_URL, "project-key"] = {"project_id": "p1"}
    control_plane.answers[f"{BACKEND}/v2/api-key/p1/env", "project-key"] = {"secret": "env-secret"}

    assert env_api_key() == "env-secret"
    assert control_plane.requests == [
        (SCOPE_URL, "project-key"),
        (f"{BACKEND}/v2/api-key/p1/env", "project-key"),
    ]
    assert logged == []


IGNORED_WITH_A_PROJECT_KEY = re.compile(r"^PDP_PROJECT_API_KEY is set, but (PDP_\w+) is also set and will be ignored")


def _ignored_variables(logged: list[str]) -> list[str]:
    """The variable each warning says is ignored; a warning of any other kind is kept whole."""
    return sorted(m.group(1) if (m := IGNORED_WITH_A_PROJECT_KEY.match(line)) else line for line in logged)


@pytest.mark.parametrize(
    ("ignored", "warned"),
    [
        pytest.param({"ORG_API_KEY": "org-key"}, ["PDP_ORG_API_KEY"], id="org-key"),
        pytest.param({"ACTIVE_PROJECT": "other"}, ["PDP_ACTIVE_PROJECT"], id="active-project"),
        pytest.param(
            {"ORG_API_KEY": "org-key", "ACTIVE_PROJECT": "other"},
            ["PDP_ACTIVE_PROJECT", "PDP_ORG_API_KEY"],
            id="both",
        ),
    ],
)
def test_a_project_key_warns_about_each_variable_it_ignores(keys, control_plane, logged, ignored, warned):
    keys(PROJECT_API_KEY="project-key", ACTIVE_ENV="env", **ignored)
    control_plane.answers[SCOPE_URL, "project-key"] = {"project_id": "p1"}
    control_plane.answers[f"{BACKEND}/v2/api-key/p1/env", "project-key"] = {"secret": "env-secret"}

    assert env_api_key() == "env-secret"
    assert control_plane.requests == [
        (SCOPE_URL, "project-key"),
        (f"{BACKEND}/v2/api-key/p1/env", "project-key"),
    ]
    assert _ignored_variables(logged) == warned


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


# --------------------------------------------------------------------------- hand-off to the front server

HANDED_OFF_KEY = "Qx7Lm2Vp-handed-off-env-key"


@pytest.fixture
def handoff_file(tmp_path, monkeypatch) -> Path:
    """PDP_API_KEY_HANDOFF_FILE in an owner-only directory, as the front server sets it."""
    directory = tmp_path / "handoff"
    directory.mkdir(mode=0o700)
    path = directory / "env-api-key"
    monkeypatch.setattr(sidecar_config, "API_KEY_HANDOFF_FILE", str(path))
    return path


@pytest.fixture
def every_log_line():
    """Every record at every level: its message, and loguru's JSON of the whole record."""
    text: list[str] = []
    serialized: list[str] = []
    handler_ids = [
        logger.add(text.append, format="{message}", level="TRACE"),
        logger.add(serialized.append, serialize=True, level="TRACE"),
    ]
    yield text, serialized
    for handler_id in handler_ids:
        logger.remove(handler_id)


def _assert_only_the_key_is_there(path: Path, key: str) -> None:
    assert path.read_bytes() == key.encode()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert list(path.parent.iterdir()) == [path]


def test_the_handoff_file_holds_just_the_key_and_only_its_owner_can_read_it(keys, handoff_file):
    keys(API_KEY=HANDED_OFF_KEY)

    api_keys.hand_off_env_api_key()

    _assert_only_the_key_is_there(handoff_file, HANDED_OFF_KEY)


def test_a_tmp_file_left_by_a_crashed_start_does_not_block_the_handoff(keys, handoff_file):
    keys(API_KEY=HANDED_OFF_KEY)
    handoff_file.with_name(f"{handoff_file.name}.tmp").write_text("half-written")

    api_keys.hand_off_env_api_key()

    _assert_only_the_key_is_there(handoff_file, HANDED_OFF_KEY)


def test_the_handoff_replaces_the_file_an_earlier_start_wrote(keys, handoff_file):
    keys(API_KEY=HANDED_OFF_KEY)
    handoff_file.write_text("rotated-out-key")
    handoff_file.chmod(0o644)

    api_keys.hand_off_env_api_key()

    _assert_only_the_key_is_there(handoff_file, HANDED_OFF_KEY)


@pytest.mark.parametrize(
    ("configured", "answers"),
    [
        pytest.param(
            {"PROJECT_API_KEY": "project-key", "ACTIVE_ENV": "env"},
            {
                ("/v2/api-key/scope", "project-key"): {"project_id": "p1"},
                ("/v2/api-key/p1/env", "project-key"): {"secret": HANDED_OFF_KEY},
            },
            id="project-key",
        ),
        pytest.param(
            {"ORG_API_KEY": "org-key", "ACTIVE_PROJECT": "proj", "ACTIVE_ENV": "env"},
            {("/v2/api-key/proj/env", "org-key"): {"secret": HANDED_OFF_KEY}},
            id="org-key",
        ),
    ],
)
def test_the_env_key_fetched_from_the_control_plane_is_handed_off(
    keys, control_plane, handoff_file, configured, answers
):
    keys(**configured)
    for (route, token), answer in answers.items():
        control_plane.answers[f"{sidecar_config.CONTROL_PLANE}{route}", token] = answer

    api_keys.hand_off_env_api_key()

    _assert_only_the_key_is_there(handoff_file, HANDED_OFF_KEY)


@pytest.mark.parametrize("handoff_setting", [None, ""], ids=["unset", "empty"])
def test_without_a_handoff_file_nothing_is_fetched_or_written(
    keys, control_plane, tmp_path, monkeypatch, handoff_setting
):
    keys(ORG_API_KEY="org-key", ACTIVE_PROJECT="proj", ACTIVE_ENV="env")
    monkeypatch.setattr(sidecar_config, "API_KEY_HANDOFF_FILE", handoff_setting)
    monkeypatch.chdir(tmp_path)

    api_keys.hand_off_env_api_key()

    assert control_plane.requests == []
    assert list(tmp_path.iterdir()) == []


def test_an_unwritable_handoff_file_exits_naming_the_path_and_never_logs_the_key(
    keys, control_plane, tmp_path, monkeypatch, every_log_line
):
    keys(PROJECT_API_KEY="project-key", ACTIVE_ENV="env")
    control_plane.answers[f"{sidecar_config.CONTROL_PLANE}/v2/api-key/scope", "project-key"] = {"project_id": "p1"}
    control_plane.answers[f"{sidecar_config.CONTROL_PLANE}/v2/api-key/p1/env", "project-key"] = {
        "secret": HANDED_OFF_KEY
    }
    path = tmp_path / "no-such-directory" / "env-api-key"
    monkeypatch.setattr(sidecar_config, "API_KEY_HANDOFF_FILE", str(path))

    with pytest.raises(SystemExit) as exc_info:
        api_keys.hand_off_env_api_key()

    assert exc_info.value.code == GUNICORN_EXIT_APP
    assert isinstance(exc_info.value.__cause__, FileNotFoundError)
    text, serialized = every_log_line
    failure = next(line for line in text if "PDP_API_KEY_HANDOFF_FILE" in line)
    # The path itself, not only the .tmp beside it that the OSError names.
    assert re.search(rf"{re.escape(str(path))}(?!\.tmp)", failure)
    assert "FileNotFoundError" in failure
    for line in text + serialized:
        assert HANDED_OFF_KEY not in line
        assert HANDED_OFF_KEY[:8] not in line


def test_a_failed_rename_exits_and_leaves_no_copy_of_the_key_behind(keys, handoff_file, logged):
    keys(API_KEY=HANDED_OFF_KEY)
    # A directory where the key file goes: the rename over it fails.
    handoff_file.mkdir()

    with pytest.raises(SystemExit) as exc_info:
        api_keys.hand_off_env_api_key()

    assert exc_info.value.code == GUNICORN_EXIT_APP
    assert list(handoff_file.parent.iterdir()) == [handoff_file]
    assert any(str(handoff_file) in line for line in logged)


def test_the_pdp_hands_the_key_off_before_it_fetches_its_remote_config(keys, handoff_file, monkeypatch):
    keys(API_KEY=HANDED_OFF_KEY)
    handed_off_by_then: list[bytes] = []

    def no_remote_config() -> None:
        handed_off_by_then.append(handoff_file.read_bytes())

    # It removes every loguru handler, pytest's included.
    monkeypatch.setattr(pdp.PermitPDP, "_setup_temp_logger", lambda _self: None)
    monkeypatch.setattr(PersistentStateHandler, "_instance", None)
    monkeypatch.setattr(pdp, "get_remote_config", no_remote_config)

    with pytest.raises(SystemExit):
        pdp.PermitPDP()

    assert handed_off_by_then == [HANDED_OFF_KEY.encode()]
