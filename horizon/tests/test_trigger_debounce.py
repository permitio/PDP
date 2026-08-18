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

import aiohttp
import pytest
from fastapi.testclient import TestClient
from horizon import debounce
from horizon.config import sidecar_config
from horizon.debounce import DebouncedTrigger
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


async def _no_wait(_seconds: float) -> None:
    """Patched over ``debounce._sleep``: fire the trailing run now instead of at window expiry.

    Still yields, so the trailing run stays a genuinely separate scheduling step rather than
    collapsing into its caller and hiding an ordering bug.
    """
    await asyncio.sleep(0)


async def drain_trailing(trigger: DebouncedTrigger) -> None:
    """Run every armed (and chained) trailing task to completion, bounded by ``TIMEOUT``."""
    while (task := trigger._trailing_task) is not None:
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), timeout=TIMEOUT)


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
    # Second call coalesced: the updater was forced exactly once *during these requests*.
    trigger.assert_awaited_once_with(force_full_update=True)
    # The coalesced trigger was deferred rather than dropped - it armed a trailing reload - but
    # that is deliberately NOT asserted here. A TestClient used without `with` runs each request
    # on its own event loop and tears it down afterwards, so the background task is cancelled
    # with the loop and the handle is cleared on a schedule this test cannot pin down. That is a
    # property of the harness, not of the debouncer. The trailing edge is driven for real where
    # a single loop spans the whole test: test_in_flight_guard_beats_an_elapsed_window below,
    # and the trailing-edge tests in test_debounce_unit.py.


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
    # The trailing run waits out the remainder of the window before firing. Skip the wait
    # (without skipping the scheduling) so the test does not park on ten real seconds.
    monkeypatch.setattr(debounce, "_sleep", _no_wait)

    # One gate per blocking reload: index 0 is the dispatch parked in flight, index 1 is the
    # trailing run it arms. Keeping them separate is what lets the test prove the dispatching
    # REQUEST was answered while the trailing run was still going.
    started = [asyncio.Event(), asyncio.Event()]
    release = [asyncio.Event(), asyncio.Event()]
    blocking_calls = 0

    async def blocking(**_kwargs) -> None:
        nonlocal blocking_calls
        index = blocking_calls
        blocking_calls += 1
        started[index].set()
        await release[index].wait()

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
            await asyncio.wait_for(started[0].wait(), timeout=TIMEOUT)
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

            release[0].set()
            second_response = await asyncio.wait_for(second, timeout=TIMEOUT)
            assert second_response.status_code == 200
            assert second_response.json() == DISPATCHED

            # 4. The trailing run that serves the third trigger is parked on release[1], which
            #    nothing has set - and the dispatching REQUEST has already been answered above.
            #    That is the proof it runs off the request path: inline, this caller would still
            #    be blocked here, paying for a second full reload it never asked for (against
            #    the 60s client timeout of the Rust server that fronts this app).
            await asyncio.wait_for(started[1].wait(), timeout=TIMEOUT)
            assert debouncer._trailing_task is not None
            assert get_base.await_count == 3

            release[1].set()
            await drain_trailing(debouncer)
        finally:
            # An assertion above failing must not leave a request task or a trailing run parked.
            for gate in release:
                gate.set()
            if not second.done():
                second.cancel()

        # The coalesced third trigger was served, not dropped - exactly once.
        assert get_base.await_count == 3
        assert debouncer._trailing_task is None


# --- case 5: a dispatch that RAISES consumes the window and answers with a gateway error ---


def test_control_plane_failure_502s_and_consumes_the_window(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    """A FAILING control plane must be damped harder than a healthy one, not left unthrottled.

    ``get_policy_data_config`` raises ``ClientError`` on any non-200 from the control plane, so
    a window consumed only by SUCCESSES would switch the mitigation off in exactly the degraded
    conditions it exists for. ``_last_dispatched`` therefore records the ATTEMPT.

    The status matters too: this used to escape as a bare 500 - the one code every SDK and
    service mesh retries - so the failure mode recruited clients into a retry storm against an
    already-struggling control plane. 502 attributes the failure upstream (matching
    horizon/enforcer/api.py) and carries a `Retry-After` telling the client when a retry could
    actually accomplish something.
    """
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    get_base = AsyncMock(side_effect=aiohttp.ClientError("control plane said 503"))
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)
    client = TestClient(pdp._app, raise_server_exceptions=False)

    first = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    assert first.status_code == 502
    # Never sooner than the window: the failed attempt just consumed it, so an earlier retry is
    # guaranteed to be coalesced and would be a provably useless call.
    assert first.headers["Retry-After"] == str(int(WINDOW))
    assert pdp._data_trigger_debounce._last_dispatched is not None
    # The `finally` still clears the in-flight flag, so a raise cannot wedge the debouncer into
    # coalescing every future trigger.
    assert pdp._data_trigger_debounce._in_flight is False

    # An immediate retry within the window is coalesced instead of opening a second connection
    # to the failing control plane - and it is not lost either: a trailing reload is armed.
    second = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    assert second.status_code == 200
    assert second.json() == COALESCED
    assert get_base.await_count == 1


def test_control_plane_timeout_504s(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    get_base = AsyncMock(side_effect=asyncio.TimeoutError())
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)
    client = TestClient(pdp._app, raise_server_exceptions=False)

    response = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    assert response.status_code == 504
    assert response.headers["Retry-After"] == str(int(WINDOW))


def test_an_unexpected_error_is_still_a_500(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    """Only *control-plane* failures are translated; a genuine bug must not be dressed up as one.

    A 502/504 tells the caller "upstream is unwell, retry later". Mapping an internal
    ``RuntimeError`` to that would send clients into a retry loop over a defect no amount of
    retrying can clear, and would hide the bug from PDP-side alerting.
    """
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    get_base = AsyncMock(side_effect=RuntimeError("boom"))
    monkeypatch.setattr(pdp._opal.data_updater, "get_base_policy_data", get_base)
    client = TestClient(pdp._app, raise_server_exceptions=False)

    response = client.post("/data-updater/trigger", headers=auth, follow_redirects=False)
    assert response.status_code == 500
    # Still consumed the window: the attempt was made regardless of how it failed.
    assert pdp._data_trigger_debounce._last_dispatched is not None


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


# --- case 9: the published contract actually describes the body clients are told to read ---


def test_openapi_declares_the_trigger_response_shape(pdp: MockPermitPDP):
    """`triggered` must exist in the SCHEMA, not just in the prose that tells clients to use it.

    The routes' customer-facing `description=` instructs integrators to branch on `triggered`.
    Without a `response_model` FastAPI publishes an empty 200 schema, so that instruction would
    reference a field no code generator or typed SDK can see.
    """
    spec = pdp._app.openapi()

    for path in ("/policy-updater/trigger", "/data-updater/trigger"):
        operation = spec["paths"][path]["post"]
        schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
        assert schema == {"$ref": "#/components/schemas/TriggerResponse"}, path

    trigger_response = spec["components"]["schemas"]["TriggerResponse"]
    assert set(trigger_response["properties"]) == {"status", "triggered"}
    assert trigger_response["properties"]["triggered"]["type"] == "boolean"

    # The data route's documented failure modes are declared too, so a client can tell the
    # permanent "updater disabled" 503 from the transient, Retry-After-carrying 502/504.
    assert {"502", "503", "504"} <= set(spec["paths"]["/data-updater/trigger"]["post"]["responses"])

    # The legacy aliases stay out of the published contract - they are compatibility shims.
    assert not [path for path in spec["paths"] if "update_policy" in path]


def test_disabled_data_updater_503_carries_no_retry_after(pdp: MockPermitPDP, auth: dict[str, str], monkeypatch):
    """A disabled updater is a configuration state: retrying cannot help, so promise nothing.

    This is why the control-plane failures map to 502/504 rather than joining this 503 - a
    client must be able to tell "back off and retry" from "stop, this will never work".
    """
    monkeypatch.setattr(sidecar_config, "TRIGGER_DEBOUNCE_SECONDS", WINDOW)
    monkeypatch.setattr(pdp._opal, "data_updater", None)

    response = TestClient(pdp._app).post("/data-updater/trigger", headers=auth, follow_redirects=False)
    assert response.status_code == 503
    assert "Retry-After" not in response.headers
