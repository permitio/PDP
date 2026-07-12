"""Integration tests proving the OPAL-mounted trigger routes are now gated.

The app is built exactly like production via ``PermitPDP._configure_api_routes`` (which
runs ``_gate_opal_trigger_routes``), so these tests directly exercise the post-hoc
dependency injection on the two routes OpalClient mounts before the PDP gets control.

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
from horizon.enforcer.api import stats_manager
from horizon.pdp import PermitPDP, _warn_if_opal_verifier_disabled, _warn_if_operational_route_auth_disabled
from loguru import logger
from opal_client.client import OpalClient
from starlette import status

VALID_TOKEN = "mock_api_key"
TRIGGER_ROUTES = ["/policy-updater/trigger", "/data-updater/trigger"]
# The legacy SDK aliases of the two trigger routes; gated with the same operational wrapper.
LEGACY_TRIGGER_ROUTES = ["/update_policy", "/update_policy_data"]
OPERATIONAL_UPDATE_ROUTES = TRIGGER_ROUTES + LEGACY_TRIGGER_ROUTES


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


@pytest.fixture
def client() -> TestClient:
    # No context manager -> lifespan/startup never runs -> no network.
    return TestClient(_sidecar._app, raise_server_exceptions=False)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def enforce_on(monkeypatch):
    """Turn ENFORCE_OPERATIONAL_ROUTE_AUTH on (read per-request by the gate) so these routes reject."""
    monkeypatch.setattr(sidecar_config, "ENFORCE_OPERATIONAL_ROUTE_AUTH", True)


# The trigger-route enforcement tests below assert the reject behaviour, which is now opt-in
# (ENFORCE_OPERATIONAL_ROUTE_AUTH defaults to off for a safe fleet rollout), so they enable it.


@pytest.mark.parametrize("path", TRIGGER_ROUTES)
@pytest.mark.usefixtures("enforce_on")
def test_trigger_route_without_token_is_401(client: TestClient, path: str):
    # The actual vulnerability: OPAL-mounted trigger routes were callable unauthenticated.
    resp = client.post(path)
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED
    assert resp.json()["detail"] == "Missing Authorization header"


@pytest.mark.parametrize("path", TRIGGER_ROUTES)
def test_trigger_route_with_valid_token_is_not_blocked(client: TestClient, path: str):
    # The dependency passes; the handler may 500 offline, but it must not be a 401. True in both
    # enforcement modes, so left flag-agnostic.
    resp = client.post(path, headers=_auth(VALID_TOKEN))
    assert resp.status_code != status.HTTP_401_UNAUTHORIZED


@pytest.mark.parametrize("path", TRIGGER_ROUTES)
@pytest.mark.usefixtures("enforce_on")
def test_trigger_route_with_wrong_token_is_401(client: TestClient, path: str):
    resp = client.post(path, headers=_auth("wrong-token"))
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED
    assert resp.json()["detail"] == "Invalid PDP token"


@pytest.mark.parametrize("path", TRIGGER_ROUTES)
@pytest.mark.parametrize("value", ["garbage", "Bearer", "Bearer ", "Bearer a b c"])
@pytest.mark.usefixtures("enforce_on")
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


@pytest.mark.parametrize("path", OPERATIONAL_UPDATE_ROUTES)
@pytest.mark.usefixtures("enforce_on")
def test_update_route_without_token_is_401_when_enforced(client: TestClient, path: str):
    # With enforcement on, the update-trigger + legacy routes reject a tokenless call.
    assert client.post(path).status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.parametrize("path", OPERATIONAL_UPDATE_ROUTES)
def test_update_route_without_token_is_allowed_by_default(client: TestClient, path: str):
    # Rollout default (enforcement off, no flag set here): a tokenless call is not blocked. It may
    # 500 on real offline I/O once it reaches the handler, but it must not be the auth 401 - which
    # proves the gate allowed it through.
    assert client.post(path).status_code != status.HTTP_401_UNAUTHORIZED


@pytest.mark.parametrize("path", OPERATIONAL_UPDATE_ROUTES)
def test_update_route_wrong_token_is_allowed_by_default(client: TestClient, path: str):
    assert client.post(path, headers=_auth("wrong-token")).status_code != status.HTTP_401_UNAUTHORIZED


def test_default_permissive_logs_would_be_rejection(client: TestClient, capture_loguru):
    # The escape hatch is observable: each would-be rejection is logged so lagging callers surface.
    client.post("/policy-updater/trigger")
    assert any("ENFORCE_OPERATIONAL_ROUTE_AUTH is off" in record for record in capture_loguru)


def test_warn_if_operational_route_auth_disabled_fires_when_off(monkeypatch, capture_loguru):
    monkeypatch.setattr(sidecar_config, "ENFORCE_OPERATIONAL_ROUTE_AUTH", False)
    _warn_if_operational_route_auth_disabled()
    assert any("ENFORCE_OPERATIONAL_ROUTE_AUTH is OFF" in record for record in capture_loguru)


def test_warn_if_operational_route_auth_disabled_silent_when_on(monkeypatch, capture_loguru):
    monkeypatch.setattr(sidecar_config, "ENFORCE_OPERATIONAL_ROUTE_AUTH", True)
    _warn_if_operational_route_auth_disabled()
    assert not any("ENFORCE_OPERATIONAL_ROUTE_AUTH is OFF" in record for record in capture_loguru)


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
