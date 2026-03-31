from unittest.mock import AsyncMock, PropertyMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from horizon.authentication import enforce_pdp_token
from horizon.connectivity.api import init_connectivity_router


def _noop_auth():
    pass


def _create_test_app(opal_client_mock):
    """Create a test FastAPI app with the connectivity router (no auth)."""
    app = FastAPI()
    router = init_connectivity_router(opal_client_mock)
    app.include_router(router)
    app.dependency_overrides[enforce_pdp_token] = _noop_auth
    return app


def _make_opal_mock(*, offline_mode_enabled=True, connectivity_disabled=False):
    mock = AsyncMock()
    type(mock).offline_mode_enabled = PropertyMock(return_value=offline_mode_enabled)
    type(mock).opal_server_connectivity_disabled = PropertyMock(return_value=connectivity_disabled)
    return mock


class TestGetConnectivityStatus:
    def test_returns_status(self):
        mock = _make_opal_mock(offline_mode_enabled=True, connectivity_disabled=True)
        client = TestClient(_create_test_app(mock))

        resp = client.get("/control-plane/connectivity")
        assert resp.status_code == 200
        data = resp.json()
        assert data["control_plane_connectivity_disabled"] is True
        assert data["offline_mode_enabled"] is True

    def test_returns_status_when_connected(self):
        mock = _make_opal_mock(offline_mode_enabled=True, connectivity_disabled=False)
        client = TestClient(_create_test_app(mock))

        resp = client.get("/control-plane/connectivity")
        assert resp.status_code == 200
        data = resp.json()
        assert data["control_plane_connectivity_disabled"] is False


class TestEnableConnectivity:
    def test_enable_success(self):
        mock = _make_opal_mock(offline_mode_enabled=True, connectivity_disabled=True)
        client = TestClient(_create_test_app(mock))

        resp = client.post("/control-plane/connectivity/enable")
        assert resp.status_code == 200
        assert resp.json()["status"] == "enabled"
        mock.enable_opal_server_connectivity.assert_awaited_once()

    def test_enable_already_enabled(self):
        mock = _make_opal_mock(offline_mode_enabled=True, connectivity_disabled=False)
        client = TestClient(_create_test_app(mock))

        resp = client.post("/control-plane/connectivity/enable")
        assert resp.status_code == 200
        assert resp.json()["status"] == "already_enabled"
        mock.enable_opal_server_connectivity.assert_not_awaited()

    def test_enable_returns_400_when_offline_mode_disabled(self):
        mock = _make_opal_mock(offline_mode_enabled=False)
        client = TestClient(_create_test_app(mock))

        resp = client.post("/control-plane/connectivity/enable")
        assert resp.status_code == 400

    def test_enable_returns_500_on_opal_error(self):
        mock = _make_opal_mock(offline_mode_enabled=True, connectivity_disabled=True)
        mock.enable_opal_server_connectivity.side_effect = RuntimeError("boom")
        client = TestClient(_create_test_app(mock))

        resp = client.post("/control-plane/connectivity/enable")
        assert resp.status_code == 500
        assert "Failed to enable" in resp.json()["detail"]


class TestDisableConnectivity:
    def test_disable_success(self):
        mock = _make_opal_mock(offline_mode_enabled=True, connectivity_disabled=False)
        client = TestClient(_create_test_app(mock))

        resp = client.post("/control-plane/connectivity/disable")
        assert resp.status_code == 200
        assert resp.json()["status"] == "disabled"
        mock.disable_opal_server_connectivity.assert_awaited_once()

    def test_disable_already_disabled(self):
        mock = _make_opal_mock(offline_mode_enabled=True, connectivity_disabled=True)
        client = TestClient(_create_test_app(mock))

        resp = client.post("/control-plane/connectivity/disable")
        assert resp.status_code == 200
        assert resp.json()["status"] == "already_disabled"
        mock.disable_opal_server_connectivity.assert_not_awaited()

    def test_disable_returns_400_when_offline_mode_disabled(self):
        mock = _make_opal_mock(offline_mode_enabled=False)
        client = TestClient(_create_test_app(mock))

        resp = client.post("/control-plane/connectivity/disable")
        assert resp.status_code == 400

    def test_disable_returns_500_on_opal_error(self):
        mock = _make_opal_mock(offline_mode_enabled=True, connectivity_disabled=False)
        mock.disable_opal_server_connectivity.side_effect = RuntimeError("boom")
        client = TestClient(_create_test_app(mock))

        resp = client.post("/control-plane/connectivity/disable")
        assert resp.status_code == 500
        assert "Failed to disable" in resp.json()["detail"]
