"""A PDP whose OPAL data updater is disabled (OPAL_DATA_UPDATER_ENABLED=false): PER-16939.

Each test starts a real PermitPDP against a faked control plane, with the updater on or off. The
TestClient runs without a context manager, so the app lifespan never runs: no OPA, and no
connection to the OPAL server.
"""

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import opal_client.client
import pytest
from fastapi.testclient import TestClient
from loguru import logger
from opal_client.config import opal_client_config
from opal_client.data.updater import DataUpdater
from opal_common.schemas.data import DataUpdateReport
from starlette import status

from horizon.config import sidecar_config
from horizon.facts import dependencies
from horizon.facts.client import CONSISTENT_UPDATE_HEADER, FactsClient, get_facts_client
from horizon.facts.opal_forwarder import get_opal_data_base_url, get_opal_data_topic
from horizon.pdp import PermitPDP
from horizon.startup import api_keys
from horizon.startup.schemas import RemoteConfig
from horizon.state import PersistentStateHandler

if TYPE_CHECKING:
    from loguru import Record

# Every PermitPDP() registers handlers on OPAL's app with on_event, as OPAL itself does (pdp.py
# suppresses the deprecation on each call), and FastAPI warns on each one. The module builds a PDP
# per test, so without this filter it would add about 170 copies of that known warning.
pytestmark = pytest.mark.filterwarnings(r"ignore:\s*on_event is deprecated:DeprecationWarning")

PDP_TOKEN = "data-updater-disabled-test-token"
AUTH = {"Authorization": f"Bearer {PDP_TOKEN}"}
CREATED_USER = {"id": "4f1d2a60-0000-4000-8000-000000000001", "key": "user-1"}
DISABLED_DETAIL = "Data Updater is currently disabled. Dynamic data updates are not available."
# The OPAL client settings PermitPDP() writes; each test gets back the values it started with.
OPAL_CLIENT_SETTINGS_SET_AT_STARTUP = [
    "DATA_UPDATER_CONN_RETRY",
    "OFFLINE_MODE_ENABLED",
    "STORE_BACKUP_PATH",
    "DEFAULT_OPAL_SERVER_CONNECTIVITY_DISABLED",
]
# Startup features that write files, change the process or add log sinks, all off.
SIDECAR_SETTINGS = {
    "API_KEY_HANDOFF_FILE": None,
    "ENABLE_OFFLINE_MODE": False,
    "OPA_DECISION_LOG_ENABLED": False,
    "OPA_DECISION_LOG_CONSOLE": False,
    "OPA_PLUGINS": {},
    "OPA_BEARER_TOKEN_REQUIRED": False,
    "PRINT_CONFIG_ON_STARTUP": False,
    "ENABLE_MONITORING": False,
    "HORIZON_NICENESS": 0,
    "DATA_UPDATE_CALLBACKS": [],
    "CENTRAL_LOG_ENABLED": False,
}


@dataclass
class StartedPDP:
    pdp: PermitPDP
    client: TestClient
    backend_calls: list[httpx.Request] = field(default_factory=list)


@pytest.fixture
def start_pdp(monkeypatch) -> Iterator[Callable[..., StartedPDP]]:
    """Start a real PermitPDP with OPAL's data updater on or off.

    The remote config and the environment API key are the ones the control plane would send, and
    the control plane's facts API answers every call with CREATED_USER.
    """
    remote_config = RemoteConfig(
        context={"org_id": str(uuid4()), "project_id": str(uuid4()), "env_id": str(uuid4()), "client_id": "pdp"}
    )
    monkeypatch.setattr("horizon.startup.remote_config._remote_config", remote_config)
    monkeypatch.setattr(api_keys, "_env_api_key", PDP_TOKEN)
    monkeypatch.setattr(PersistentStateHandler, "_instance", None)
    # Both remove every loguru handler, the tests' included.
    monkeypatch.setattr(PermitPDP, "_setup_temp_logger", lambda _self: None)
    monkeypatch.setattr(opal_client.client, "configure_logs", lambda: None)
    for name, value in SIDECAR_SETTINGS.items():
        monkeypatch.setattr(sidecar_config, name, value)
    for name in OPAL_CLIENT_SETTINGS_SET_AT_STARTUP:
        monkeypatch.setattr(opal_client_config, name, getattr(opal_client_config, name))
    # Built on the first facts write and shared after it: start without one, and leave none behind.
    monkeypatch.setattr(dependencies, "_data_update_subscriber", None)
    # Both are @cache'd off the remote config: start clean and leave nothing built from this fake.
    get_opal_data_base_url.cache_clear()
    get_opal_data_topic.cache_clear()

    def start(*, data_updater_enabled: bool) -> StartedPDP:
        monkeypatch.setattr(opal_client_config, "DATA_UPDATER_ENABLED", data_updater_enabled)
        permit_pdp = PermitPDP()
        started = StartedPDP(pdp=permit_pdp, client=TestClient(permit_pdp.app))

        def control_plane(request: httpx.Request) -> httpx.Response:
            started.backend_calls.append(request)
            return httpx.Response(status.HTTP_200_OK, json=CREATED_USER)

        facts_client = FactsClient()
        facts_client._client = httpx.AsyncClient(
            base_url="http://control-plane", transport=httpx.MockTransport(control_plane)
        )
        permit_pdp.app.dependency_overrides[get_facts_client] = lambda: facts_client
        return started

    yield start

    get_opal_data_base_url.cache_clear()
    get_opal_data_topic.cache_clear()


def _records_at(level: str) -> Iterator[list["Record"]]:
    records: list[Record] = []
    sink_id = logger.add(lambda message: records.append(message.record), level=level)
    yield records
    logger.remove(sink_id)


@pytest.fixture
def logged_warnings() -> Iterator[list["Record"]]:
    yield from _records_at("WARNING")


@pytest.fixture
def logged_debug() -> Iterator[list["Record"]]:
    yield from _records_at("DEBUG")


def _create_user(started: StartedPDP, headers: dict[str, str]) -> httpx.Response:
    return started.client.post("/facts/users", headers={**AUTH, **headers}, json={"key": CREATED_USER["key"]})


def _disabled_updater_warnings(records: list["Record"]) -> list[str]:
    return [record["message"] for record in records if "data updater is disabled" in record["message"]]


def test_the_pdp_starts_without_the_data_updater_and_says_so_once(start_pdp, logged_warnings):
    started = start_pdp(data_updater_enabled=False)

    assert started.pdp._opal.data_updater is None
    (warning,) = _disabled_updater_warnings(logged_warnings)
    assert "OPAL_DATA_UPDATER_ENABLED=false" in warning
    assert "facts writes are forwarded to the control plane without waiting for them to apply" in warning


def test_the_pdp_with_the_data_updater_does_not_say_it_is_disabled(start_pdp, logged_warnings):
    started = start_pdp(data_updater_enabled=True)

    assert started.pdp._opal.data_updater is not None
    assert _disabled_updater_warnings(logged_warnings) == []


@pytest.mark.parametrize(
    "headers",
    [{}, {"X-Wait-timeout": "5"}, {"X-Wait-timeout": "5", "X-Timeout-Policy": "fail"}],
    ids=["no-wait-header", "wait-header", "wait-header-fail-policy"],
)
def test_a_facts_write_without_the_data_updater_returns_the_backend_response(start_pdp, headers):
    """The write is forwarded as a plain one, so the control plane sends the update to the PDPs that
    have a data updater, and the backend's answer comes back without a wait."""
    started = start_pdp(data_updater_enabled=False)

    response = _create_user(started, headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == CREATED_USER
    (backend_call,) = started.backend_calls
    assert backend_call.url.path.endswith("/users")
    assert CONSISTENT_UPDATE_HEADER not in backend_call.headers


def test_a_facts_unassign_without_the_data_updater_still_sends_return_deleted(start_pdp):
    started = start_pdp(data_updater_enabled=False)

    response = started.client.request(
        "DELETE",
        "/facts/role_assignments?return_deleted=false",
        headers=AUTH,
        json={"user": "user-1", "role": "viewer", "tenant": "t1"},
    )

    assert response.status_code == status.HTTP_200_OK
    (backend_call,) = started.backend_calls
    assert backend_call.url.params.get_list("return_deleted") == ["true"]


@pytest.mark.parametrize(
    ("headers", "ignored"),
    [({"X-Wait-timeout": "5"}, 1), ({}, 0)],
    ids=["wait-header", "no-wait-header"],
)
def test_x_wait_timeout_without_the_data_updater_is_ignored_with_a_debug_log(start_pdp, logged_debug, headers, ignored):
    started = start_pdp(data_updater_enabled=False)

    _create_user(started, headers)

    ignoring = [
        record
        for record in logged_debug
        if record["message"].startswith("Ignoring X-Wait-timeout: OPAL's data updater")
    ]
    assert len(ignoring) == ignored
    assert all(record["level"].name == "DEBUG" for record in ignoring)


@pytest.mark.parametrize("route", ["/update_policy_data", "/data-updater/trigger"])
def test_data_reload_routes_without_the_data_updater_answer_503(start_pdp, route):
    started = start_pdp(data_updater_enabled=False)

    response = started.client.post(route, headers=AUTH, follow_redirects=False)

    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert response.json()["detail"] == DISABLED_DETAIL


class OpalPubSubStandIn:
    """OPAL's pub/sub client on a live connection to the OPAL server.

    With ``echo``, the server broadcasts each update back, and the PDP's data updater applies it and
    reports it. Without, the update never comes back.
    """

    def __init__(self, updater: DataUpdater, *, echo: bool):
        self._updater = updater
        self._echo = echo
        self.published: list[dict[str, Any]] = []

    async def publish(self, topics: list[str], data: dict[str, Any], **_kwargs: Any) -> bool:  # noqa: ARG002 - OPAL's signature
        self.published.append(data)
        if self._echo:
            report = DataUpdateReport(update_id=data["id"], reports=[])
            await self._updater.callbacks_reporter.report_update_results(report)
        return True


@pytest.mark.parametrize(
    ("echo", "wait", "expected_status"),
    [(True, "5", status.HTTP_200_OK), (False, "0.1", status.HTTP_424_FAILED_DEPENDENCY)],
    ids=["update-applied", "update-never-applied"],
)
def test_a_facts_write_with_the_data_updater_waits_for_this_pdp_to_apply_it(
    start_pdp, monkeypatch, echo, wait, expected_status
):
    started = start_pdp(data_updater_enabled=True)
    updater = started.pdp._opal.data_updater
    assert updater is not None
    # OPAL's own report, which posts to the data update callbacks over HTTP.
    opal_report = AsyncMock()
    monkeypatch.setattr(updater.callbacks_reporter, "report_update_results", opal_report)
    pubsub = OpalPubSubStandIn(updater, echo=echo)
    monkeypatch.setattr(updater, "_client", pubsub)

    response = _create_user(started, {"X-Wait-timeout": wait, "X-Timeout-Policy": "fail"})

    assert response.status_code == expected_status
    (backend_call,) = started.backend_calls
    assert backend_call.headers[CONSISTENT_UPDATE_HEADER] == "true"
    (published,) = pubsub.published
    assert published["id"]
    assert opal_report.await_count == (1 if echo else 0)
