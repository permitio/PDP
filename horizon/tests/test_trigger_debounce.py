"""Behaviour tests for the debounced forced-reload trigger routes (PER-15248).

The PDP replaces OpalClient's ungated, un-damped ``POST /policy-updater/trigger`` and
``POST /data-updater/trigger`` handlers with its own gated, DEBOUNCED handlers, and routes
the legacy ``/update_policy`` / ``/update_policy_data`` aliases through the same per-updater
debouncers. These tests exercise the observable coalescing behaviour end-to-end through the
real app, mirroring the idiom of ``test_legacy_update_routes.py``: a fresh ``MockPermitPDP``
per test (so each gets its own debounce state), a ``TestClient``, and ``AsyncMock``s
monkeypatched onto the underlying updater methods.

All four routes answer 200 ``{"status": "ok", "triggered": <bool>}``: ``triggered`` is true
when the call dispatched a reload and false when it was absorbed into a recent or in-flight
one. A coalesced call is a success, not an error - SDKs polling these routes must never
error-spiral - so the status code alone cannot distinguish the two and every assertion below
checks the body.

The debounce window is read from ``sidecar_config.TRIGGER_DEBOUNCE_SECONDS`` at call time, so
each test sets it via ``monkeypatch.setattr`` (monkeypatch reverts it at teardown). The unit
tests in ``test_debounce_unit.py`` cover the same state machine directly, with a fake clock.
"""

import asyncio
import time
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
# Bounds a hang rather than a real wait: on the happy path these resolve immediately.
TIMEOUT = 2.0

# The two possible bodies. Naming them keeps every assertion below about WHICH one came back.
DISPATCHED = {"status": "ok", "triggered": True}
COALESCED = {"status": "ok", "triggered": False}


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

    assert first.status_code == 200
    assert first.json() == DISPATCHED
    assert second.status_code == 200
    assert second.json() == COALESCED
    # Second call coalesced: the updater was forced exactly once.
    trigger.assert_awaited_once_with(force_full_update=True)


def test_data_triggers_within_window_coalesce(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    get_base = AsyncMock()
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)
    client = TestClient(pdp._app)

    first = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    second = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)

    assert first.status_code == 200
    assert first.json() == DISPATCHED
    assert second.status_code == 200
    assert second.json() == COALESCED
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

    assert canonical.status_code == 200
    assert canonical.json() == DISPATCHED
    assert legacy.status_code == 200
    assert legacy.json() == COALESCED
    trigger.assert_awaited_once_with(force_full_update=True)


def test_canonical_and_legacy_data_share_one_debouncer(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    get_base = AsyncMock()
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)
    client = TestClient(pdp._app)

    canonical = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    legacy = client.post("/update_policy_data", headers=auth, follow_redirects=False)

    assert canonical.status_code == 200
    assert canonical.json() == DISPATCHED
    assert legacy.status_code == 200
    assert legacy.json() == COALESCED
    # The canonical call fired first, so its reason string is the one that ran; the legacy
    # call coalesced and never invoked the updater with its own "(legacy alias)" reason.
    get_base.assert_awaited_once_with(data_fetch_reason="request from sdk")


# --- case 2: after the window elapses, the next trigger fires again ----------------------


def test_trigger_fires_again_after_window_elapses(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    trigger = AsyncMock()
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", trigger)
    client = TestClient(pdp._app)

    first = client.post("/policy-updater/trigger", headers=auth, follow_redirects=False)
    assert first.status_code == 200
    assert first.json() == DISPATCHED
    assert trigger.await_count == 1

    # Rewind the debouncer's last dispatch past the window (no real sleep): the next trigger
    # now sees the window as elapsed and fires.
    pdp._policy_trigger_debounce._last_dispatched -= WINDOW + 1

    second = client.post("/policy-updater/trigger", headers=auth, follow_redirects=False)
    assert second.status_code == 200
    assert second.json() == DISPATCHED
    assert trigger.await_count == 2


# --- case 3: window == 0 disables the TIME window (sequential triggers all pass through) --


def test_zero_window_passes_every_sequential_trigger_through(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    # Note the scope: 0 disables the time window only. Concurrent triggers are still collapsed
    # by the in-flight guard (test_in_flight_guard_applies_even_with_the_window_disabled in
    # test_debounce_unit.py); these calls are sequential, so each completes before the next.
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", 0)
    trigger = AsyncMock()
    monkeypatch.setattr(pdp._opal.policy_updater, "trigger_update_policy", trigger)
    client = TestClient(pdp._app)

    for _ in range(3):
        response = client.post("/policy-updater/trigger", headers=auth, follow_redirects=False)
        assert response.status_code == 200
        assert response.json() == DISPATCHED
    assert trigger.await_count == 3


# --- case 4: the in-flight guard is checked BEFORE the window, so it wins even when the ---
# --- window has fully elapsed ------------------------------------------------------------


@pytest.mark.asyncio
async def test_in_flight_guard_beats_an_elapsed_window(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    """Set both conditions at once: a reload in flight AND a window that has already elapsed.

    Getting there needs three triggers, because a dispatch records ``_last_dispatched`` only
    when it *returns* - so while the first reload is still in flight the window guard has
    nothing to compare against and would admit everything on its own. This test therefore lets
    one trigger complete, rewinds its timestamp past the window, and only then parks a second
    trigger in flight. The third trigger is the interesting one: the window guard would let it
    through, so anything that coalesces it must be the in-flight guard.
    """
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)

    started = asyncio.Event()  # set once the second reload is genuinely running
    release = asyncio.Event()  # keeps that reload in flight until the test releases it

    async def blocking(**_kwargs) -> None:
        started.set()
        await release.wait()

    get_base = AsyncMock()
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)
    debouncer = pdp._data_trigger_debounce

    transport = ASGITransport(app=pdp._app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. A first, non-blocking trigger completes and records a dispatch timestamp...
        first = await client.post("/data-updater/trigger", headers=auth)
        assert first.json() == DISPATCHED
        # ...which we rewind past the window, so from here the window guard would ADMIT.
        debouncer._last_dispatched -= WINDOW + 1

        # 2. A second trigger parks inside the reload. It cannot refresh the timestamp while
        #    it is in flight, so the window stays elapsed underneath it.
        get_base.side_effect = blocking
        second = asyncio.create_task(client.post("/data-updater/trigger", headers=auth))
        try:
            await asyncio.wait_for(started.wait(), timeout=TIMEOUT)
            assert debouncer._in_flight is True
            assert time.monotonic() - debouncer._last_dispatched > WINDOW, (
                "the window must be elapsed, otherwise the window guard could be doing the coalescing"
            )

            # 3. The third trigger: only the in-flight guard can account for this coalesce.
            #    Bounded by wait_for because that bound is part of the contract - a coalesced
            #    trigger returns immediately and never awaits the reload it collapsed into. It
            #    also keeps a regression here failing rather than HANGING: a third call that
            #    wrongly dispatched would park on `release`, which nothing has set yet, and
            #    this repo has no pytest-timeout plugin to rescue the run.
            third = await asyncio.wait_for(client.post("/data-updater/trigger", headers=auth), timeout=TIMEOUT)
            assert third.status_code == 200
            assert third.json() == COALESCED
            assert get_base.await_count == 2

            release.set()
            second_response = await asyncio.wait_for(second, timeout=TIMEOUT)
        finally:
            # An assertion above failing must not leave the request task parked in `run`.
            release.set()
            if not second.done():
                second.cancel()

        assert second_response.status_code == 200
        assert second_response.json() == DISPATCHED
        # The coalesced third trigger armed the trailing edge, so the in-flight dispatch re-ran
        # exactly once after completing rather than dropping that trigger on the floor.
        assert get_base.await_count == 3


# --- case 5: a dispatch that RAISES propagates and does not consume the window ------------


def test_raising_dispatch_500s_and_does_not_consume_the_window(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    """The narrow, honest version of the deleted "a failed pull does not burn the window" claim.

    ``_last_dispatched`` is assigned only after ``await run()`` RETURNS, so an exception raised
    out of the dispatch skips it and an immediate retry still fires. But note how little that
    covers: both updaters are fire-and-forget underneath (a queue put for policy; a config GET
    plus a task hand-off for data), so a reload that is dispatched and then fails in the
    background returns normally here and DOES consume the window. See
    ``test_window_is_consumed_by_the_dispatch_not_by_the_reload_succeeding`` in
    test_debounce_unit.py for that half of the contract.
    """
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    get_base = AsyncMock(side_effect=RuntimeError("boom"))
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)
    # raise_server_exceptions=False so the propagated error surfaces as a 500 response.
    client = TestClient(pdp._app, raise_server_exceptions=False)

    first = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    assert first.status_code == 500
    assert pdp._data_trigger_debounce._last_dispatched is None
    # The `finally` still clears the in-flight flag, so a raise cannot wedge the debouncer into
    # coalescing every future trigger.
    assert pdp._data_trigger_debounce._in_flight is False

    # ...so an immediate retry within the window is not coalesced: it dispatches (and 500s again).
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
    assert pdp._data_trigger_debounce._last_dispatched is None
    get_base.assert_not_awaited()

    # Re-enable: because the 503 never touched the debouncer, the next trigger fires.
    monkeypatch.setattr(pdp._opal, "data_updater", original_updater)
    enabled = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    assert enabled.status_code == 200
    assert enabled.json() == DISPATCHED
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
    policy = client.post("/policy-updater/trigger", headers=auth, follow_redirects=False)
    data = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    assert policy.json() == DISPATCHED
    assert data.json() == DISPATCHED
    policy_trigger.assert_awaited_once_with(force_full_update=True)
    data_get_base.assert_awaited_once_with(data_fetch_reason="request from sdk")


def test_debounce_state_is_per_pdp_instance(auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)

    pdp_a = MockPermitPDP()
    trigger_a = AsyncMock()
    monkeypatch.setattr(pdp_a._opal.policy_updater, "trigger_update_policy", trigger_a)
    resp_a = TestClient(pdp_a._app).post("/policy-updater/trigger", headers=auth, follow_redirects=False)
    assert resp_a.status_code == 200
    assert resp_a.json() == DISPATCHED
    trigger_a.assert_awaited_once()

    # A brand-new instance carries its own debounce state, so its first trigger always fires,
    # even though pdp_a just fired within the window.
    pdp_b = MockPermitPDP()
    trigger_b = AsyncMock()
    monkeypatch.setattr(pdp_b._opal.policy_updater, "trigger_update_policy", trigger_b)
    resp_b = TestClient(pdp_b._app).post("/policy-updater/trigger", headers=auth, follow_redirects=False)
    assert resp_b.status_code == 200
    assert resp_b.json() == DISPATCHED
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
