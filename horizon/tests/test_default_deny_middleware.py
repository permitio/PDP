"""Tests for the default-deny authentication middleware (PER-15245).

These exercise the middleware against the *real* PDP app (built the same way as
``MockPermitPDP`` in ``test_enforcer_api.py``) so we cover the routes OPAL mounts
before the PDP takes over - the ``/policy-updater/trigger`` /
``/data-updater/trigger`` routers that were the actual vulnerability.
"""

import horizon.middleware.default_deny as default_deny
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from horizon.config import AuthEnforcement, sidecar_config
from horizon.middleware.default_deny import (
    _has_valid_pdp_token,
    _is_allowlisted,
    _normalize_path,
)
from horizon.pdp import PermitPDP
from loguru import logger
from opal_client.client import OpalClient

VALID_TOKEN = "test-pdp-token-do-not-log"


class MockPermitPDP(PermitPDP):
    """Builds the real PDP app without the full cloud-config bootstrap.

    Mirrors ``test_enforcer_api.MockPermitPDP``; ``_configure_api_routes`` installs
    the default-deny middleware, so the app under test is wired exactly as prod.
    """

    def __init__(self):
        self._setup_temp_logger()
        self._opal = OpalClient()
        sidecar_config.API_KEY = "mock_api_key"
        app: FastAPI = self._opal.app
        self._override_app_metadata(app)
        self._configure_api_routes(app)

        # A brand-new route with NO per-route auth dependency: proves the middleware
        # fails closed for routes that forget to gate themselves.
        @app.get("/synthetic_unprotected_route")
        async def _synthetic():  # pragma: no cover - only runs if middleware lets it through
            return {"ok": True}

        self._app = app


_sidecar = MockPermitPDP()


@pytest.fixture
def client() -> TestClient:
    # Plain TestClient (no context manager) so we don't run the OPAL lifespan /
    # OPA startup - the routes under test don't need them. raise_server_exceptions
    # is off so that a route which the middleware *allows through* but which then
    # fails on real network I/O offline surfaces as a 500 response (still != 401),
    # rather than bubbling the exception into the test.
    return TestClient(_sidecar._app, raise_server_exceptions=False)


@pytest.fixture
def enforce(monkeypatch):
    monkeypatch.setattr(sidecar_config, "AUTH_ENFORCEMENT", AuthEnforcement.ENFORCE)


@pytest.fixture
def audit(monkeypatch):
    monkeypatch.setattr(sidecar_config, "AUTH_ENFORCEMENT", AuthEnforcement.AUDIT)


@pytest.fixture
def valid_token(monkeypatch):
    monkeypatch.setattr(default_deny, "get_env_api_key", lambda: VALID_TOKEN)
    return VALID_TOKEN


@pytest.fixture
def audit_logs():
    """Capture WARNING-level loguru records emitted during a test."""
    records: list = []
    sink_id = logger.add(records.append, level="WARNING")
    yield records
    logger.remove(sink_id)


def _bearer(token: str) -> dict:
    return {"authorization": f"Bearer {token}"}


def _is_middleware_401(resp) -> bool:
    """True iff the response is the default-deny middleware's own 401.

    Lets tests assert "the middleware did/didn't block" without coupling to whatever
    status a deferred/downstream handler happens to return.
    """
    return (
        resp.status_code == 401
        and resp.headers.get("www-authenticate") == "Bearer"
        and resp.json() == {"detail": "Missing or invalid PDP token"}
    )


# --------------------------------------------------------------------------- #
# Pure-unit tests for the matching / token helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path, allowlisted",
    [
        # protected - must NOT be allowlisted
        ("/allowed", False),
        ("/kong", False),
        ("/policy-updater/trigger", False),
        ("/data-updater/trigger", False),
        ("/version", False),
        ("/healthchecks/opa/ready", False),  # gated proxy route - the /health prefix trap
        ("/callbacksfoo", False),  # tier-2 boundary trap
        # tier 1 - genuinely public (exact)
        ("/", True),
        ("/health", True),
        ("/health/", True),  # trailing slash normalized
        ("/healthcheck", True),
        ("/healthy", True),
        ("/ready", True),
        ("/docs", True),
        ("/docs/oauth2-redirect", True),
        ("/redoc", True),
        ("/scalar", True),
        ("/openapi.json", True),
        # tier 2 - defer to own auth (boundary-aware prefix)
        ("/policy-store/config", True),
        ("/callbacks", True),
        ("/callbacks/abc", True),
        ("/opal-server/connectivity", True),
        ("/_exit", True),
    ],
)
def test_is_allowlisted(path, allowlisted):
    assert _is_allowlisted(_normalize_path(path)) is allowlisted


def _http_scope(headers: dict) -> dict:
    return {
        "type": "http",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }


def test_has_valid_pdp_token(monkeypatch):
    monkeypatch.setattr(default_deny, "get_env_api_key", lambda: VALID_TOKEN)
    assert _has_valid_pdp_token(_http_scope({"authorization": f"Bearer {VALID_TOKEN}"})) is True
    assert _has_valid_pdp_token(_http_scope({"authorization": "Bearer wrong"})) is False
    assert _has_valid_pdp_token(_http_scope({})) is False  # missing
    assert _has_valid_pdp_token(_http_scope({"authorization": "garbage"})) is False  # malformed, no space
    assert _has_valid_pdp_token(_http_scope({"authorization": f"Basic {VALID_TOKEN}"})) is False  # wrong scheme
    # Non-ASCII token must return False, not raise (hmac.compare_digest TypeError on str).
    assert _has_valid_pdp_token(_http_scope({"authorization": "Bearer café"})) is False


# --------------------------------------------------------------------------- #
# Enforce mode
# --------------------------------------------------------------------------- #

PROTECTED_NO_OWN_AUTH = [
    ("post", "/policy-updater/trigger"),  # OPAL-inherited, the actual vuln
    ("post", "/data-updater/trigger"),  # OPAL-inherited, the actual vuln
    ("get", "/synthetic_unprotected_route"),  # fail-closed proof: brand-new ungated route
]


@pytest.mark.usefixtures("enforce")
@pytest.mark.parametrize("method, path", PROTECTED_NO_OWN_AUTH)
def test_enforce_blocks_unauthenticated(client, method, path):
    resp = getattr(client, method)(path)
    assert resp.status_code == 401
    assert resp.json() == {"detail": "Missing or invalid PDP token"}
    assert resp.headers.get("www-authenticate") == "Bearer"


@pytest.mark.usefixtures("enforce")
@pytest.mark.parametrize("method, path", PROTECTED_NO_OWN_AUTH)
def test_enforce_allows_valid_token(valid_token, client, method, path):
    resp = getattr(client, method)(path, headers=_bearer(valid_token))
    assert resp.status_code != 401


@pytest.mark.usefixtures("enforce")
@pytest.mark.parametrize("bad_header", ["garbage", "Bearer", "Bearer ", "", "Bearer a b c"])
def test_enforce_malformed_header_is_401_not_500(client, bad_header):
    # The route's own enforce_pdp_token does an unguarded split(" ") that would 500;
    # the middleware must reject malformed headers with 401 before the route runs.
    # (Non-ASCII tokens - which would make hmac.compare_digest raise TypeError - can't
    # be sent through httpx, so that regression is covered at the unit level in
    # test_has_valid_pdp_token, exercising the latin-1 scope uvicorn would produce.)
    resp = client.post("/policy-updater/trigger", headers={"authorization": bad_header})
    assert resp.status_code == 401


@pytest.mark.usefixtures("enforce", "valid_token")
def test_enforce_wrong_token_is_401(client):
    resp = client.post("/policy-updater/trigger", headers=_bearer("not-the-real-token"))
    assert resp.status_code == 401


@pytest.mark.usefixtures("enforce")
@pytest.mark.parametrize("path", ["/", "/health", "/healthy", "/docs", "/openapi.json"])
def test_enforce_public_routes_need_no_token(client, path):
    resp = client.get(path)
    assert resp.status_code != 401


@pytest.mark.usefixtures("enforce")
def test_enforce_public_route_trailing_slash(client):
    # /health/ -> normalized to /health (public); router then 307s to /health, which
    # the TestClient follows -> final 200, never a middleware 401.
    resp = client.get("/health/")
    assert resp.status_code != 401


@pytest.mark.usefixtures("enforce")
def test_enforce_healthchecks_prefix_is_not_public(client):
    # Regression: a naive startswith("/health") would wrongly expose this gated
    # proxy route. It must be blocked without a token.
    resp = client.get("/healthchecks/opa/ready")
    assert resp.status_code == 401


@pytest.mark.usefixtures("enforce")
def test_enforce_protected_non_tier2_route_blocked(client):
    # /version is gated by its own enforce_pdp_token but is NOT allowlisted;
    # the middleware blocks it first.
    resp = client.get("/version")
    assert resp.status_code == 401
    assert resp.json() == {"detail": "Missing or invalid PDP token"}


@pytest.mark.usefixtures("enforce")
def test_enforce_tier2_defers_to_own_auth_policy_store(client):
    # Middleware steps aside; the route's own dependency handles it. What we assert is
    # only that the middleware did NOT emit *its* 401 - the request reached the route's
    # own auth. We avoid asserting a specific downstream status so the test is not
    # coupled to OPAL's current (no-verifier) policy-store behavior.
    resp = client.get("/policy-store/config")
    assert not _is_middleware_401(resp)


@pytest.mark.usefixtures("enforce")
def test_enforce_tier2_defers_to_own_auth_exit(client):
    # /_exit defers to enforce_pdp_control_key, whose own required-header validation
    # returns 422 - proof the request reached its own dependency, not the middleware.
    resp = client.post("/_exit")
    assert resp.status_code == 422


@pytest.mark.usefixtures("enforce")
def test_enforce_cors_preflight_bypassed(client):
    # A genuine CORS preflight (carries Access-Control-Request-Method) is never blocked,
    # so the browser handshake to a protected route still works.
    resp = client.options(
        "/policy-updater/trigger",
        headers={"Origin": "https://example.com", "Access-Control-Request-Method": "POST"},
    )
    assert not _is_middleware_401(resp)


@pytest.mark.usefixtures("enforce")
def test_enforce_non_preflight_options_is_gated(client):
    # A bare OPTIONS (not a CORS preflight) to a protected route is still subject to the
    # default-deny check, so a future custom OPTIONS handler cannot be reached unauthed.
    resp = client.options("/policy-updater/trigger")
    assert _is_middleware_401(resp)


# --------------------------------------------------------------------------- #
# Audit mode
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures("audit")
def test_audit_allows_and_logs_would_block(client, audit_logs):
    resp = client.post("/policy-updater/trigger")
    assert not _is_middleware_401(resp)  # allowed through (not blocked) in audit mode

    blocked = [str(r) for r in audit_logs if "default-deny audit" in str(r)]
    assert len(blocked) == 1
    line = blocked[0]
    assert "path=/policy-updater/trigger" in line
    assert "method=POST" in line
    assert "has_valid_pdp_token=false" in line


@pytest.mark.usefixtures("audit")
def test_audit_valid_token_does_not_log(valid_token, client, audit_logs):
    resp = client.post("/policy-updater/trigger", headers=_bearer(valid_token))
    assert not _is_middleware_401(resp)
    assert not [r for r in audit_logs if "default-deny audit" in str(r)]


@pytest.mark.usefixtures("audit", "valid_token")
def test_audit_never_logs_token_material(client, audit_logs):
    secret = "super-secret-invalid-token-value"
    resp = client.post("/policy-updater/trigger", headers=_bearer(secret))
    assert not _is_middleware_401(resp)
    combined = "".join(str(r) for r in audit_logs)
    assert "default-deny audit" in combined  # it WAS a would-block
    assert secret not in combined  # ...but the token value was never logged


@pytest.mark.usefixtures("audit")
def test_audit_hostile_user_agent_does_not_drop_log(client, audit_logs):
    # A user-agent containing loguru template braces must not break formatting and
    # silently drop the audit line (it is passed as a positional arg, never f-strung).
    resp = client.post(
        "/policy-updater/trigger",
        headers={"user-agent": "{oops} {0} {malformed"},
    )
    assert not _is_middleware_401(resp)
    blocked = [str(r) for r in audit_logs if "default-deny audit" in str(r)]
    assert len(blocked) == 1
    assert "user_agent={oops} {0} {malformed" in blocked[0]
