from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from horizon.config import sidecar_config
from horizon.tests.test_enforcer_api import MockPermitPDP


@pytest.fixture
def pdp() -> MockPermitPDP:
    # Fresh instance per test so AsyncMock / None mutations don't leak across
    # modules via the shared `sidecar` singleton in test_enforcer_api.
    return MockPermitPDP()


@pytest.fixture
def auth() -> dict[str, str]:
    return {"authorization": f"Bearer {sidecar_config.API_KEY}"}


def test_update_policy_triggers_updater(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    trigger = AsyncMock()
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", trigger)

    response = TestClient(pdp._app).post("/update_policy", headers=auth, follow_redirects=False)

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    trigger.assert_awaited_once_with(force_full_update=True)


def test_update_policy_rejects_unauthenticated(pdp: MockPermitPDP, monkeypatch):
    trigger = AsyncMock()
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", trigger)
    client = TestClient(pdp._app)

    # A missing header is rejected by the required-header dependency (422); an
    # invalid token by enforce_pdp_token itself (401). Either way the updater
    # must never run for an unauthenticated caller.
    assert client.post("/update_policy", follow_redirects=False).status_code == 422
    invalid = client.post("/update_policy", headers={"authorization": "Bearer wrong"}, follow_redirects=False)
    assert invalid.status_code == 401
    trigger.assert_not_awaited()


def test_update_policy_data_triggers_updater(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    get_base = AsyncMock()
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)

    response = TestClient(pdp._app).post("/update_policy_data", headers=auth, follow_redirects=False)

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
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

    assert client.post("/update_policy_data", follow_redirects=False).status_code == 422
    invalid = client.post("/update_policy_data", headers={"authorization": "Bearer wrong"}, follow_redirects=False)
    assert invalid.status_code == 401
    get_base.assert_not_awaited()


def test_legacy_routes_do_not_redirect(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    # Lock in the fix: the aliases must call the updaters directly, never redirect
    # to the canonical routes. Clients drop Authorization on any redirect code
    # (301/302/303/307/308), so assert none is returned, not just != 307.
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", AsyncMock())
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", AsyncMock())
    client = TestClient(pdp._app)

    assert not client.post("/update_policy", headers=auth, follow_redirects=False).is_redirect
    assert not client.post("/update_policy_data", headers=auth, follow_redirects=False).is_redirect
