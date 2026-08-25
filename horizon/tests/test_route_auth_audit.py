"""Fail-closed route audit - the structural guarantee behind "default-deny".

Every other auth test proves a *specific* route behaves; this one proves the *whole app*
does. It builds the real app exactly like production (``PermitPDP._configure_api_routes``)
and asserts that every mounted route is either explicitly public (in
``horizon.authentication.PUBLIC_ROUTE_PATHS``) or carries a recognised auth gate. A new
router or a bare ``@app.get`` added anywhere without a dependency therefore fails *this
test* (i.e. CI) instead of silently shipping an unauthenticated endpoint - which is the
only thing that makes the allowlist a real fail-closed boundary rather than a convention
everyone has to remember. This is the test ``PUBLIC_ROUTE_PATHS`` is documented as feeding.

Recognised gates, detected by the presence of the dependency (not by path, so an OPAL
version bump that renames a route can't quietly slip past):
  * ``enforce_pdp_token``        - PDP API key (tier-1 protected: the PDP's own routes)
  * ``enforce_pdp_control_key``  - PDP container-control key (``/_exit``)
  * ``JWTAuthenticator`` / ``require_listener_token`` - OPAL's own auth on the routes it
    mounts (tier-2: ``/policy-store``, ``/callbacks``, ``/opal-server``). This audit checks
    that a gate is *attached*; whether OPAL's verifier is enabled at runtime is a separate
    concern (see ``_warn_if_opal_verifier_disabled`` in horizon/pdp.py).
"""

from typing import Annotated

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.dependencies.utils import get_flat_dependant
from fastapi.routing import APIRoute
from horizon.authentication import PUBLIC_ROUTE_PATHS, enforce_pdp_token
from horizon.config import sidecar_config
from horizon.pdp import OPAL_TRIGGER_ROUTE_PATHS, PermitPDP, _remove_opal_trigger_routes
from horizon.system.consts import GUNICORN_EXIT_APP
from opal_client.client import OpalClient
from starlette.routing import Route

# Dependency callables that count as authenticating a route. Matched by name so detection
# survives an OPAL path rename; kept deliberately small so an *unrecognised* auth mechanism
# also fails the audit and gets a human's attention.
AUTH_GATE_CALLABLES: frozenset[str] = frozenset(
    {
        "enforce_pdp_token",
        "enforce_pdp_control_key",
        "JWTAuthenticator",
        "require_listener_token",
    }
)


class MockPermitPDP(PermitPDP):
    """Build the app through the real route-configuration path, without lifespan/network."""

    def __init__(self):
        self._setup_temp_logger()
        self._opal = OpalClient()
        sidecar_config.API_KEY = "mock_api_key"
        app: FastAPI = self._opal.app
        self._override_app_metadata(app)
        self._configure_api_routes(app)
        self._app: FastAPI = app


_sidecar = MockPermitPDP()


def _callable_name(call) -> str:
    return getattr(call, "__name__", None) or type(call).__name__


def _route_auth_gates(route: APIRoute) -> set[str]:
    """Names of every dependency callable on a route, flattened across sub-dependencies."""
    flat = get_flat_dependant(route.dependant)
    return {_callable_name(dep.call) for dep in flat.dependencies if dep.call is not None}


def _find_unprotected_routes(app: FastAPI) -> list[str]:
    """Return a human-readable description of every route missing an auth gate ([] == good)."""
    unprotected: list[str] = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            if route.path in PUBLIC_ROUTE_PATHS:
                continue  # explicitly public
            if _route_auth_gates(route) & AUTH_GATE_CALLABLES:
                continue  # carries a recognised gate
            unprotected.append(f"{sorted(route.methods or [])} {route.path}")
        elif isinstance(route, Route):
            # Framework routes (Swagger/OpenAPI/redoc) have no dependant, so they can only
            # be justified by the public allowlist.
            if route.path not in PUBLIC_ROUTE_PATHS:
                unprotected.append(f"{sorted(route.methods or [])} {route.path} (no dependant)")
        else:
            # Mounts / sub-apps can't be gated by a route-level dependency at all - a new
            # one must be reviewed explicitly rather than pass through unnoticed.
            unprotected.append(f"{type(route).__name__} {getattr(route, 'path', '?')} (un-gateable mount)")
    return unprotected


def test_no_route_is_unprotected():
    """The load-bearing guarantee: no non-public route ships without an auth gate."""
    unprotected = _find_unprotected_routes(_sidecar._app)
    assert unprotected == [], (
        "Route(s) reachable without authentication. Add Depends(enforce_pdp_token) (or, if "
        "genuinely public, add the exact path to horizon.authentication.PUBLIC_ROUTE_PATHS):\n  "
        + "\n  ".join(unprotected)
    )


@pytest.mark.parametrize("path", sorted(OPAL_TRIGGER_ROUTE_PATHS))
def test_opal_trigger_route_is_pdp_gated(path: str):
    """Regression guard for the actual fix: the OPAL-mounted trigger routes require the PDP token."""
    # Collect ALL routes at this path rather than a dict keyed by path: a dict is last-wins and
    # would happily hide a surviving OPAL duplicate behind the PDP replacement, which is the one
    # failure mode this test exists to catch.
    matches = [route for route in _sidecar._app.routes if isinstance(route, APIRoute) and route.path == path]
    assert matches, (
        f"{path} is no longer mounted (OPAL rename?) - _remove_opal_trigger_routes / "
        "_configure_trigger_routes must be updated"
    )
    # Exactly one, because Starlette matches first-wins: a leftover OPAL route at the same path
    # would SHADOW the replacement and stay ungated and un-debounced - the removal silently
    # failing open is indistinguishable from success by any per-route assertion.
    assert len(matches) == 1, f"{len(matches)} routes mounted at {path}; _remove_opal_trigger_routes missed one"

    route = matches[0]
    # ...and the survivor is the PDP's handler, not OPAL's (opal_client.policy.api /
    # opal_client.data.api), so "gated" cannot be satisfied by an OPAL route that merely
    # happens to carry a dependency.
    assert route.endpoint.__module__ == "horizon.pdp", (
        f"{path} is served by {route.endpoint.__module__}.{route.endpoint.__name__}, not horizon.pdp"
    )
    assert "enforce_pdp_token" in _route_auth_gates(route)


@pytest.mark.parametrize("present", [(), ("/policy-updater/trigger",), ("/data-updater/trigger",)])
def test_remove_opal_trigger_routes_exits_when_a_path_is_missing(present: tuple[str, ...]):
    """Fail loud, never fail open: a trigger route the PDP cannot find must stop the process.

    If OPAL renames or drops one of these paths, the removal silently no-ops and the caller
    re-registers only its replacement - leaving OPAL's original ungated, un-debounced handler
    mounted under the new name. That reopens exactly the auth + amplification hole this
    replacement closes, so ``_remove_opal_trigger_routes`` exits instead (gunicorn's
    "don't restart me" code, so the container fails rather than crash-loops silently).
    """

    async def _stub() -> dict:
        return {}

    app = FastAPI()
    for path in present:
        app.post(path)(_stub)

    with pytest.raises(SystemExit) as exit_info:
        _remove_opal_trigger_routes(app)
    assert exit_info.value.code == GUNICORN_EXIT_APP


def test_audit_detects_a_bare_ungated_route():
    """The audit must have teeth: an unguarded route is flagged (guards against a vacuous pass)."""
    app = FastAPI()

    @app.get("/oops-unprotected")
    async def _oops():
        return {}

    assert any("/oops-unprotected" in row for row in _find_unprotected_routes(app))


def test_audit_accepts_a_gated_route():
    app = FastAPI()

    @app.get("/guarded", dependencies=[Depends(enforce_pdp_token)])
    async def _guarded():
        return {}

    assert _find_unprotected_routes(app) == []


def test_audit_flags_a_mounted_subapp():
    """A mounted sub-app bypasses route-level dependencies entirely and must not pass silently."""
    app = FastAPI()
    app.mount("/sub", FastAPI())
    assert any("/sub" in row for row in _find_unprotected_routes(app))


def test_allowlist_has_no_dead_entries():
    """Every PUBLIC_ROUTE_PATHS entry must match a mounted route - no exemptions.

    A dead allowlist entry is a pre-authorised hole: it exempts a path from the audit today
    and silently waves through whatever route later claims that path. Matching by set
    membership over ``getattr(route, "path", ...)`` covers the framework Swagger/OpenAPI
    routes (plain starlette ``Route``s, not ``APIRoute``s) and paths shared across methods.

    This check is only total because ``_configure_api_routes`` mounts *every* route,
    ``/scalar`` included. If a route is ever registered outside it again, the honest fix is to
    move that registration back in - not to re-introduce an exemption set here, which would
    reopen the blind spot for the next route added beside it.
    """
    mounted = {getattr(route, "path", None) for route in _sidecar._app.routes}
    dead = PUBLIC_ROUTE_PATHS - mounted
    assert dead == set(), (
        f"PUBLIC_ROUTE_PATHS entries that match no route on the audit-built app: {sorted(dead)}. "
        "Either the entry is dead (remove it, or fix the path if a route was renamed), or its "
        "route is registered outside PermitPDP._configure_api_routes - move the registration "
        "into that method so the audit can see it."
    )


def test_router_level_dependencies_surface_in_flat_dependant():
    """Empirical FastAPI contract the whole audit rests on (>=0.124.0; proven on 0.125.0).

    The floor is real, not decorative: ``get_flat_dependant`` only began propagating
    sub-dependants into ``flat_dependant.dependencies`` in 0.124.0, so requirements.txt pins
    ``fastapi>=0.124.0`` and this test is what that pin protects.

    The audit detects gates by walking ``get_flat_dependant(route.dependant)``. That only
    works if a dependency attached at ``include_router(dependencies=[...])`` propagates into
    each child route's dependant, and if nested sub-dependencies (e.g. OPAL's
    ``require_listener_token`` wrapping the authenticator) are flattened. If a future FastAPI
    bump changes that, router-gated routes would read as unprotected and every real run would
    fail for the wrong reason - so pin the assumption here, where the failure is legible.
    """

    def fake_gate():  # router-level gate
        pass

    def inner_gate():  # reachable ONLY as wrapper's sub-dependency - see the assertion below
        pass

    # Annotated-Depends (the repo's own convention, see horizon/authentication.py) keeps the
    # sub-dependency in the annotation rather than the argument default - idiomatic FastAPI and
    # B008-clean. inner_gate is nested one level under wrapper and attached nowhere else, so the
    # nested-gated assertion genuinely exercises get_flat_dependant's recursion instead of
    # passing on a directly-attached copy.
    def wrapper(_: Annotated[None, Depends(inner_gate)] = None):
        pass

    router = APIRouter()

    @router.get("/router-gated")
    async def _router_gated():
        return {}

    @router.get("/nested-gated", dependencies=[Depends(wrapper)])
    async def _nested_gated():
        return {}

    app = FastAPI()
    app.include_router(router, dependencies=[Depends(fake_gate)])
    by_path = {route.path: route for route in app.routes if isinstance(route, APIRoute)}

    assert "fake_gate" in _route_auth_gates(by_path["/router-gated"]), (
        "include_router(dependencies=...) no longer surfaces in get_flat_dependant - the "
        "route audit's gate detection is broken for router-level gates; review it before "
        "trusting a green run on this FastAPI version."
    )
    # inner_gate reaches this route ONLY through wrapper (wrapper is the route-level dep;
    # fake_gate is router-level). If get_flat_dependant stops recursing into sub-dependencies,
    # inner_gate drops out and this fails - the exact regression the assertion exists to pin.
    assert {"wrapper", "inner_gate"} <= _route_auth_gates(by_path["/nested-gated"]), (
        "nested Depends() is no longer flattened by get_flat_dependant - closure-wrapped "
        "gates (e.g. OPAL's require_listener_token) would go undetected by the audit."
    )
