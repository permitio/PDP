"""Integration tests proving the OPAL-mounted trigger routes are gated.

The app is built exactly like production via ``PermitPDP._configure_api_routes``, which
removes the two trigger routes OpalClient mounts before the PDP gets control and
re-registers PDP-owned, debounced replacements at the same paths (see
``_configure_trigger_routes`` / ``_remove_opal_trigger_routes``). These tests exercise the
``Depends(enforce_pdp_token)`` gate those replacement routes carry.

The TestClient is used WITHOUT a context manager, so the app lifespan never runs (no OPAL
policy/data fetch, no OPA process, no control-plane connection). ``raise_server_exceptions
=False`` means a request the auth dependency *allows* through but which then fails on real
offline I/O surfaces as a 500 response instead of raising - so an authenticated trigger
call asserts only that it is not blocked (status != 401), not that the handler succeeds.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from horizon.config import sidecar_config
from horizon.debounce import DebouncedTrigger
from horizon.enforcer.api import stats_manager
from horizon.pdp import PermitPDP, _warn_if_opal_verifier_disabled
from loguru import logger
from opal_client.client import OpalClient
from starlette import status

VALID_TOKEN = "mock_api_key"
TRIGGER_ROUTES = ["/policy-updater/trigger", "/data-updater/trigger"]


class MockPermitPDP(PermitPDP):
    def __init__(self):
        self._setup_temp_logger()
        self._opal = OpalClient()
        sidecar_config.API_KEY = VALID_TOKEN
        app: FastAPI = self._opal.app
        self._override_app_metadata(app)
        self._configure_api_routes(app)
        self._app: FastAPI = app


_sidecar = MockPermitPDP()


@pytest.fixture(autouse=True)
def _reset_trigger_debouncers() -> None:
    """Give every test in this module a clean debounce state.

    ``_sidecar`` is module-level because building an OpalClient per test is slow, and since
    PER-15248 a PermitPDP instance carries MUTABLE debounce state: a trigger that reaches the
    handler records a dispatch, and for the next ``TRIGGER_DEBOUNCE_SECONDS`` (default 10)
    every further trigger on that updater is coalesced into it and never touches the updater.

    That turns this shared instance into an order-dependent trap. The policy trigger below
    genuinely succeeds even offline (``trigger_update_policy`` is just a queue put), so a
    second policy-triggering test added to this module would be silently coalesced and fail
    with a baffling "Awaited 0 times" - or pass or fail depending on which test ran first.
    Swapping in fresh DebouncedTriggers is far cheaper than a fresh PDP and keeps every test
    here independent of the ones before it.
    """
    _sidecar._policy_trigger_debounce = DebouncedTrigger("policy")
    _sidecar._data_trigger_debounce = DebouncedTrigger("data")


@pytest.fixture
def client() -> TestClient:
    # No context manager -> lifespan/startup never runs -> no network.
    return TestClient(_sidecar._app, raise_server_exceptions=False)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("path", TRIGGER_ROUTES)
def test_trigger_route_without_token_is_401(client: TestClient, path: str):
    # The actual vulnerability: OPAL-mounted trigger routes were callable unauthenticated.
    resp = client.post(path)
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED
    assert resp.json()["detail"] == "Missing Authorization header"


@pytest.mark.parametrize("path", TRIGGER_ROUTES)
def test_trigger_route_with_valid_token_is_not_blocked(client: TestClient, path: str):
    # The dependency passes; the handler may 500 offline, but it must not be a 401.
    resp = client.post(path, headers=_auth(VALID_TOKEN))
    assert resp.status_code != status.HTTP_401_UNAUTHORIZED


def test_debounce_state_does_not_leak_between_tests():
    """Teeth for the autouse reset above - this test runs *after* the trigger tests.

    Without the reset, the policy trigger they just made would still be recorded here and the
    next test to call that route would be coalesced instead of reaching the updater.
    """
    assert _sidecar._policy_trigger_debounce._last_dispatched is None
    assert _sidecar._data_trigger_debounce._last_dispatched is None


@pytest.mark.parametrize("path", TRIGGER_ROUTES)
def test_trigger_route_with_wrong_token_is_401(client: TestClient, path: str):
    resp = client.post(path, headers=_auth("wrong-token"))
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED
    assert resp.json()["detail"] == "Invalid PDP token"


@pytest.mark.parametrize("path", TRIGGER_ROUTES)
@pytest.mark.parametrize("value", ["garbage", "Bearer", "Bearer ", "Bearer a b c"])
def test_trigger_route_malformed_header_is_401_not_500(client: TestClient, path: str, value: str):
    # Regression for the unguarded split(" ") -> ValueError -> 500 footgun.
    resp = client.post(path, headers={"Authorization": value})
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED


def test_health_is_public(client: TestClient, monkeypatch):
    # /health returns 503 when stats_manager reports a prior failure, and that manager is a
    # module-level singleton other test modules (test_enforcer_api) leave in a failed state.
    # This test is about /health being PUBLIC - reachable without a PDP token - not about
    # stats health, so pin the manager healthy to stay isolated from that leaked global state.
    async def _healthy() -> bool:
        return False

    monkeypatch.setattr(stats_manager, "status", _healthy)
    assert client.get("/health").status_code == status.HTTP_200_OK


def test_healthchecks_opa_prefix_is_gated(client: TestClient):
    # /health is public by EXACT match; the /healthchecks/opa/* proxy routes must not
    # inherit that (the startswith("/health") prefix trap).
    resp = client.get("/healthchecks/opa/ready")
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED


def test_version_is_gated(client: TestClient):
    assert client.get("/version").status_code == status.HTTP_401_UNAUTHORIZED


def test_exit_without_header_is_503_when_control_key_unset(client: TestClient):
    # Control key is unset in tests, so enforce_pdp_control_key short-circuits to 503
    # (before any header check) - now reachable because the header param defaults to None.
    assert client.post("/_exit").status_code == status.HTTP_503_SERVICE_UNAVAILABLE


def test_warn_if_opal_verifier_disabled_fires(capture_loguru):
    # The real MockPermitPDP OpalClient runs with no public key -> verifier disabled.
    _warn_if_opal_verifier_disabled(_sidecar._opal)
    assert any("OPAL JWT verifier is DISABLED" in record for record in capture_loguru)


def test_warn_if_opal_verifier_disabled_silent_when_enabled(capture_loguru):
    class _Verifier:
        enabled = True

    class _Opal:
        verifier = _Verifier()

    _warn_if_opal_verifier_disabled(_Opal())
    assert not any("OPAL JWT verifier is DISABLED" in record for record in capture_loguru)


@pytest.fixture
def capture_loguru():
    records: list[str] = []
    # loguru hands the sink a Message (a str subclass); str() pins the type so the list stays
    # list[str] and the substring checks below don't rely on Message being str-compatible.
    sink_id = logger.add(lambda message: records.append(str(message)), level="WARNING")
    yield records
    logger.remove(sink_id)
