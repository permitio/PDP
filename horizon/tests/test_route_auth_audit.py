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

import pytest
from fastapi import Depends, FastAPI
from fastapi.dependencies.utils import get_flat_dependant
from fastapi.routing import APIRoute
from horizon.authentication import PUBLIC_ROUTE_PATHS, enforce_pdp_token
from horizon.config import sidecar_config
from horizon.pdp import OPAL_TRIGGER_ROUTE_PATHS, PermitPDP
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
    by_path = {route.path: route for route in _sidecar._app.routes if isinstance(route, APIRoute)}
    assert path in by_path, (
        f"{path} is no longer mounted (OPAL rename?) - _remove_opal_trigger_routes / "
        "_configure_trigger_routes must be updated"
    )
    assert "enforce_pdp_token" in _route_auth_gates(by_path[path])


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
