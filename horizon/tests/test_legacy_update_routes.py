from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from horizon.config import sidecar_config

# Basename import (not horizon.tests.*): CI installs the package non-editably, so
# the wheel ships no tests/ package; pytest's prepend import mode puts this
# directory on sys.path and imports test modules by basename.
from test_enforcer_api import MALFORMED_AUTH_HEADERS, MockPermitPDP


@pytest.fixture
def pdp() -> MockPermitPDP:
    # Fresh instance per test: keeps these tests independent of the shared
    # module-level `sidecar` singleton in test_enforcer_api (cheap defensive
    # isolation; monkeypatch already reverts this file's mutations at teardown).
    return MockPermitPDP()


@pytest.fixture
def auth() -> dict[str, str]:
    return {"authorization": f"Bearer {sidecar_config.API_KEY}"}


def test_update_policy_triggers_updater(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    trigger = AsyncMock()
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", trigger)

    response = TestClient(pdp._app).post("/update_policy", headers=auth, follow_redirects=False)

    assert response.status_code == 200
    # `triggered` reports whether THIS call dispatched a reload; a fresh PDP has no recent
    # dispatch to coalesce into, so the first call always dispatches. The coalescing cases
    # (triggered=false) live in test_trigger_debounce.py.
    assert response.json() == {"status": "ok", "triggered": True}
    trigger.assert_awaited_once_with(force_full_update=True)


def test_update_policy_rejects_unauthenticated(pdp: MockPermitPDP, monkeypatch):
    trigger = AsyncMock()
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", trigger)
    client = TestClient(pdp._app)

    missing = client.post("/update_policy", follow_redirects=False)
    assert missing.status_code == 401
    assert missing.json()["detail"] == "Missing Authorization header"
    invalid = client.post("/update_policy", headers={"authorization": "Bearer wrong"}, follow_redirects=False)
    assert invalid.status_code == 401
    trigger.assert_not_awaited()


@pytest.mark.parametrize("value", MALFORMED_AUTH_HEADERS)
def test_update_policy_malformed_header_is_401_not_500(pdp: MockPermitPDP, monkeypatch, value: str):
    trigger = AsyncMock()
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", trigger)
    client = TestClient(pdp._app)

    response = client.post("/update_policy", headers={"authorization": value}, follow_redirects=False)

    assert response.status_code == 401
    trigger.assert_not_awaited()


def test_update_policy_data_triggers_updater(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    get_base = AsyncMock()
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)

    response = TestClient(pdp._app).post("/update_policy_data", headers=auth, follow_redirects=False)

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "triggered": True}
    get_base.assert_awaited_once_with(data_fetch_reason="request from sdk (legacy alias)")


def test_update_policy_data_returns_503_when_updater_disabled(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(pdp._opal, "data_updater", None)

    response = TestClient(pdp._app).post("/update_policy_data", headers=auth, follow_redirects=False)

    assert response.status_code == 503
    # Exact parity with the canonical data route (opal_client/data/api.py).
    assert response.json()["detail"] == "Data Updater is currently disabled. Dynamic data updates are not available."


def test_update_policy_data_rejects_unauthenticated(pdp: MockPermitPDP, monkeypatch):
    get_base = AsyncMock()
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)
    client = TestClient(pdp._app)

    missing = client.post("/update_policy_data", follow_redirects=False)
    assert missing.status_code == 401
    assert missing.json()["detail"] == "Missing Authorization header"
    invalid = client.post("/update_policy_data", headers={"authorization": "Bearer wrong"}, follow_redirects=False)
    assert invalid.status_code == 401
    get_base.assert_not_awaited()


@pytest.mark.parametrize("value", MALFORMED_AUTH_HEADERS)
def test_update_policy_data_malformed_header_is_401_not_500(pdp: MockPermitPDP, monkeypatch, value: str):
    get_base = AsyncMock()
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)
    client = TestClient(pdp._app)

    response = client.post("/update_policy_data", headers={"authorization": value}, follow_redirects=False)

    assert response.status_code == 401
    get_base.assert_not_awaited()


def test_legacy_routes_do_not_redirect(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    # Lock in the fix: the aliases must call the updaters directly, never redirect
    # to the canonical routes. Clients drop Authorization on redirects, and
    # httpx's is_redirect flags any 3xx — stronger than asserting != 307 alone.
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", AsyncMock())
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", AsyncMock())
    client = TestClient(pdp._app)

    assert not client.post("/update_policy", headers=auth, follow_redirects=False).is_redirect
    assert not client.post("/update_policy_data", headers=auth, follow_redirects=False).is_redirect
