"""Behaviour tests for the debounced forced-reload trigger routes (PER-15248).

The PDP replaces OpalClient's ungated, un-damped ``POST /policy-updater/trigger`` and
``POST /data-updater/trigger`` handlers with its own gated, DEBOUNCED handlers, and routes
the legacy ``/update_policy`` / ``/update_policy_data`` aliases through the same per-updater
debouncers. These tests exercise the observable coalescing behaviour end-to-end through the
real app, mirroring the idiom of ``test_legacy_update_routes.py``: a fresh ``MockPermitPDP``
per test (so each gets its own debounce state), a ``TestClient``, and ``AsyncMock``s
monkeypatched onto the underlying updater methods.

The debounce window is read from ``sidecar_config.TRIGGER_DEBOUNCE_SECONDS`` at call time, so
each test sets it via ``monkeypatch.setattr`` (monkeypatch reverts it at teardown).
"""

import asyncio
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from horizon.config import sidecar_config
from httpx import ASGITransport, AsyncClient

# Basename import (not horizon.tests.*): CI installs the package non-editably, so the wheel
# ships no tests/ package; pytest's prepend import mode puts this directory on sys.path and
# imports test modules by basename. Same rationale as test_legacy_update_routes.py.
from test_enforcer_api import MockPermitPDP

WINDOW = 10.0


@pytest.fixture
def pdp() -> MockPermitPDP:
    # Fresh instance per test => fresh per-updater debounce state, so tests never coalesce
    # into each other (the debouncers live on the PermitPDP instance, not a module global).
    return MockPermitPDP()


@pytest.fixture
def auth() -> dict[str, str]:
    return {"authorization": f"Bearer {sidecar_config.API_KEY}"}


# --- case 1: triggers within the window coalesce into a single underlying reload ---------


def test_policy_triggers_within_window_coalesce(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    trigger = AsyncMock()
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", trigger)
    client = TestClient(pdp._app)

    first = client.post("/policy-updater/trigger", headers=auth, follow_redirects=False)
    second = client.post("/policy-updater/trigger", headers=auth, follow_redirects=False)

    assert first.status_code == 200 and first.json() == {"status": "ok"}
    assert second.status_code == 200 and second.json() == {"status": "ok"}
    # Second call coalesced: the updater was forced exactly once.
    trigger.assert_awaited_once_with(force_full_update=True)


def test_data_triggers_within_window_coalesce(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    get_base = AsyncMock()
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)
    client = TestClient(pdp._app)

    first = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    second = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)

    assert first.status_code == 200 and first.json() == {"status": "ok"}
    assert second.status_code == 200 and second.json() == {"status": "ok"}
    get_base.assert_awaited_once_with(data_fetch_reason="request from sdk")


def test_canonical_and_legacy_policy_share_one_debouncer(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    # Alternating canonical + legacy alias within the window must still collapse into one reload:
    # both routes hit the same policy debouncer instance.
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    trigger = AsyncMock()
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", trigger)
    client = TestClient(pdp._app)

    canonical = client.post("/policy-updater/trigger", headers=auth, follow_redirects=False)
    legacy = client.post("/update_policy", headers=auth, follow_redirects=False)

    assert canonical.status_code == 200 and legacy.status_code == 200
    trigger.assert_awaited_once_with(force_full_update=True)


def test_canonical_and_legacy_data_share_one_debouncer(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    get_base = AsyncMock()
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)
    client = TestClient(pdp._app)

    canonical = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    legacy = client.post("/update_policy_data", headers=auth, follow_redirects=False)

    assert canonical.status_code == 200 and legacy.status_code == 200
    # The canonical call fired first, so its reason string is the one that ran; the legacy
    # call coalesced and never invoked the updater with its own "(legacy alias)" reason.
    get_base.assert_awaited_once_with(data_fetch_reason="request from sdk")


# --- case 2: after the window elapses, the next trigger fires again ----------------------


def test_trigger_fires_again_after_window_elapses(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    trigger = AsyncMock()
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", trigger)
    client = TestClient(pdp._app)

    assert client.post("/policy-updater/trigger", headers=auth, follow_redirects=False).status_code == 200
    assert trigger.await_count == 1

    # Rewind the debouncer's last-fired past the window (no real sleep): the next trigger
    # now sees the window as elapsed and fires.
    pdp._policy_trigger_debounce._last_fired -= WINDOW + 1

    assert client.post("/policy-updater/trigger", headers=auth, follow_redirects=False).status_code == 200
    assert trigger.await_count == 2


# --- case 3: window == 0 disables debouncing (passthrough on every call) ------------------


def test_zero_window_passes_every_trigger_through(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", 0)
    trigger = AsyncMock()
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", trigger)
    client = TestClient(pdp._app)

    for _ in range(3):
        assert client.post("/policy-updater/trigger", headers=auth, follow_redirects=False).status_code == 200
    assert trigger.await_count == 3


# --- case 4: an in-flight reload coalesces later triggers regardless of the window --------


@pytest.mark.asyncio
async def test_in_flight_reload_coalesces_even_past_window(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)

    started = asyncio.Event()  # set once the reload is genuinely running
    release = asyncio.Event()  # keeps the reload in flight until the test releases it

    async def blocking(**_kwargs) -> None:
        started.set()
        await release.wait()

    get_base = AsyncMock(side_effect=blocking)
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)

    transport = ASGITransport(app=pdp._app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Fire the first trigger and let it block inside the underlying reload.
        first = asyncio.create_task(client.post("/data-updater/trigger", headers=auth))
        await asyncio.wait_for(started.wait(), timeout=2)

        # The window guard would admit this (last_fired is still None because the first pull
        # has not completed), but the in-flight guard must coalesce it: no second pull.
        second = await client.post("/data-updater/trigger", headers=auth)
        assert second.status_code == 200 and second.json() == {"status": "ok"}
        assert get_base.await_count == 1

        # Release the in-flight reload and confirm the first request completes cleanly.
        release.set()
        first_response = await first
        assert first_response.status_code == 200 and first_response.json() == {"status": "ok"}
        assert get_base.await_count == 1


# --- case 5: a failed reload does not burn the window (immediate retry still fires) -------


def test_failed_reload_does_not_burn_window(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    get_base = AsyncMock(side_effect=RuntimeError("boom"))
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)
    # raise_server_exceptions=False so the propagated error surfaces as a 500 response.
    client = TestClient(pdp._app, raise_server_exceptions=False)

    first = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    assert first.status_code == 500
    # Failure must not record last_fired...
    assert pdp._data_trigger_debounce._last_fired is None

    # ...so an immediate retry within the window still fires (is not coalesced).
    second = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    assert second.status_code == 500
    assert get_base.await_count == 2


# --- case 6: a disabled data updater 503s before the debouncer (window not consumed) -----


def test_disabled_data_updater_503s_before_debouncer(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    get_base = AsyncMock()
    original_updater = pdp._opal.data_updater
    monkeypatch.setattr(original_updater, "get_base_policy_data", get_base)

    # Disable the data updater -> exact OPAL 503 parity, raised BEFORE the debouncer.
    monkeypatch.setattr(pdp._opal, "data_updater", None)
    client = TestClient(pdp._app)
    disabled = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    assert disabled.status_code == 503
    assert disabled.json()["detail"] == "Data Updater is currently disabled. Dynamic data updates are not available."
    # The 503 must not have consumed the window.
    assert pdp._data_trigger_debounce._last_fired is None
    get_base.assert_not_awaited()

    # Re-enable: because the 503 never touched the debouncer, the next trigger fires.
    monkeypatch.setattr(pdp._opal, "data_updater", original_updater)
    enabled = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    assert enabled.status_code == 200
    get_base.assert_awaited_once_with(data_fetch_reason="request from sdk")


# --- case 7: policy and data debouncers are independent; state is per-instance -----------


def test_policy_and_data_debouncers_are_independent(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    policy_trigger = AsyncMock()
    data_get_base = AsyncMock()
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", policy_trigger)
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", data_get_base)
    client = TestClient(pdp._app)

    # Firing policy must not consume the data window: both fire within the same window.
    assert client.post("/policy-updater/trigger", headers=auth, follow_redirects=False).status_code == 200
    assert client.post("/data-updater/trigger", headers=auth, follow_redirects=False).status_code == 200
    policy_trigger.assert_awaited_once_with(force_full_update=True)
    data_get_base.assert_awaited_once_with(data_fetch_reason="request from sdk")


def test_debounce_state_is_per_pdp_instance(auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)

    pdp_a = MockPermitPDP()
    trigger_a = AsyncMock()
    monkeypatch.setattr(pdp_a._opal.policy_updater, "trigger_update_policy", trigger_a)
    resp_a = TestClient(pdp_a._app).post("/policy-updater/trigger", headers=auth, follow_redirects=False)
    assert resp_a.status_code == 200
    trigger_a.assert_awaited_once()

    # A brand-new instance carries its own debounce state, so its first trigger always fires,
    # even though pdp_a just fired within the window.
    pdp_b = MockPermitPDP()
    trigger_b = AsyncMock()
    monkeypatch.setattr(pdp_b._opal.policy_updater, "trigger_update_policy", trigger_b)
    resp_b = TestClient(pdp_b._app).post("/policy-updater/trigger", headers=auth, follow_redirects=False)
    assert resp_b.status_code == 200
    trigger_b.assert_awaited_once()


# --- case 8: auth is untouched by the replacement (sanity) -------------------------------


def test_replacement_route_still_rejects_missing_token(pdp: MockPermitPDP, monkeypatch):
    # The replacements carry the normal Depends(enforce_pdp_token) gate; the dedicated auth
    # tests live in test_opal_trigger_auth.py / test_route_auth_audit.py. This is a light guard
    # that debouncing did not accidentally open the route.
    trigger = AsyncMock()
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", trigger)

    resp = TestClient(pdp._app).post("/policy-updater/trigger", follow_redirects=False)
    assert resp.status_code == 401
    trigger.assert_not_awaited()
