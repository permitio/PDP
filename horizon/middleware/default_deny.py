"""Default-deny authentication middleware.

The PDP uses an *allowlist-of-protected* model: every route has to individually
remember ``Depends(enforce_pdp_token)``. That is fragile - the OPAL trigger
routers (``/policy-updater/trigger`` / ``/data-updater/trigger``) are mounted by
``OpalClient`` before the PDP wrapper gets control, so they were never gated, and
any new route that forgets the dependency fails *open*.

This ASGI middleware inverts the model to *default-deny*: every request must
carry a valid PDP token unless its path is explicitly allowlisted. Because it is
a global middleware it also sees the routes OPAL mounted before the PDP took
over, which a custom ``APIRoute``/``APIRouter`` subclass could not.

Design notes (see ``.claude/per-15245-implementation-plan.md``):

* Pure ASGI (not ``BaseHTTPMiddleware``) to avoid per-request task-group overhead
  on the hot ``/allowed`` path and streaming/background-task pitfalls.
* It runs *outside* Starlette's ``ExceptionMiddleware`` (user middleware always
  does), so it must never ``raise HTTPException`` - it builds and sends the 401
  response itself. It also parses the ``Authorization`` header defensively so a
  malformed header yields 401, never a 500.
* It sits *outside* ``CORSMiddleware`` (OPAL registers CORS before routes, and
  ``add_middleware`` prepends), so a genuine CORS preflight (``OPTIONS`` carrying
  ``Access-Control-Request-Method``) is bypassed; any other ``OPTIONS`` is gated.
"""

import hmac

from fastapi import FastAPI
from loguru import logger
from starlette import status
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from horizon.config import AuthEnforcement, sidecar_config
from horizon.startup.api_keys import get_env_api_key
from horizon.system.consts import GUNICORN_EXIT_APP

# Tier 1 - genuinely public. EXACT match only, never a prefix: e.g. a
# ``startswith("/health")`` shortcut would wrongly expose the gated
# ``/healthchecks/opa/*`` proxy routes. ``/docs/oauth2-redirect`` is registered
# by FastAPI by default and is needed for the Swagger "Authorize" flow.
PUBLIC_EXACT_PATHS: frozenset[str] = frozenset(
    {
        "/",
        "/health",
        "/healthcheck",
        "/healthy",
        "/ready",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
        "/scalar",
        "/openapi.json",
    }
)

# Tier 2 - authenticated by a DIFFERENT mechanism (OPAL listener JWT for the
# OPAL routers, the container control key for ``/_exit``). The middleware steps
# aside for these; their own route-level dependencies still enforce auth. This
# is "public to the PDP-token middleware", NOT unauthenticated.
DEFER_AUTH_PREFIXES: tuple[str, ...] = (
    "/policy-store",
    "/callbacks",
    "/opal-server",
    "/_exit",
)


def _normalize_path(path: str) -> str:
    """Strip trailing slashes for allowlist comparison (``/`` maps to itself).

    Starlette's ``redirect_slashes`` runs at the router, i.e. *after* this
    middleware, so we see the raw ``/health/`` here. Normalizing keeps a
    trailing-slash liveness probe from spuriously getting 401 while staying
    consistent with (never more permissive than) the router's matching -
    stripping trailing slashes can only make an already-public path match or
    produce a router 404, never turn a protected path into an allowlisted one.
    """
    return path.rstrip("/") or "/"


def _is_allowlisted(path: str) -> bool:
    if path in PUBLIC_EXACT_PATHS:
        return True
    # Boundary-aware prefix check: ``/callbacksfoo`` must NOT match ``/callbacks``.
    return any(path == prefix or path.startswith(prefix + "/") for prefix in DEFER_AUTH_PREFIXES)


def _has_valid_pdp_token(scope: Scope) -> bool:
    authorization = Headers(scope=scope).get("authorization")
    if authorization is None:
        return False
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return False
    schema, token = parts
    if schema.strip().lower() != "bearer":
        return False
    try:
        # Constant-time compare. The operands are pre-encoded to bytes, which is what
        # keeps a non-ASCII token (e.g. "Bearer café", possible because header values
        # are latin-1 decoded) safe: hmac.compare_digest raises TypeError on non-ASCII
        # *str* inputs, but never on bytes. Do NOT drop the .encode() - the except below
        # is a last-resort net for genuinely unexpected errors, not the non-ASCII guard.
        # Any such error is treated as an invalid token (401), never surfaced as a 500,
        # since this middleware runs outside Starlette's ExceptionMiddleware. (A
        # SystemExit from get_env_api_key on a fatally-misconfigured PDP is a
        # BaseException, deliberately not caught here, matching enforce_pdp_token.)
        return hmac.compare_digest(token.strip().encode("utf-8"), get_env_api_key().encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - fail closed on any comparison error
        # Log the error class only (never the token) so an unexpected failure is not silent.
        logger.error(
            "default-deny: unexpected error validating PDP token ({}); treating as invalid", type(exc).__name__
        )
        return False


def _client_ip(scope: Scope) -> str:
    client = scope.get("client")
    return client[0] if client else "unknown"


def _is_cors_preflight(scope: Scope) -> bool:
    """True only for a genuine CORS preflight request.

    Starlette's CORSMiddleware treats an ``OPTIONS`` request as a preflight only when
    it carries ``Access-Control-Request-Method``. We bypass exactly those, so a future
    route that registers its own (non-preflight) ``OPTIONS`` handler stays subject to
    the default-deny check instead of being silently unauthenticated.
    """
    return Headers(scope=scope).get("access-control-request-method") is not None


def _log_would_block(scope: Scope, path: str, method: str) -> None:
    """Emit the audit-mode WARN for a request that *would* have been rejected.

    Every attacker-controlled value (user-agent, forwarded-for) is passed as a
    positional argument, never f-string-interpolated into the message: loguru
    re-parses ``{}`` in the message template, so a user-agent like ``"{oops}"``
    would raise and silently drop this very log line. The raw ``Authorization``
    header / token is never logged.
    """
    headers = Headers(scope=scope)
    # has_valid_pdp_token is always false here: this is only reached on a would-block.
    logger.warning(
        "default-deny audit: would block unauthenticated request "
        "path={} method={} has_valid_pdp_token=false client_ip={} forwarded_for={} user_agent={}",
        path,
        method,
        _client_ip(scope),
        headers.get("x-forwarded-for", ""),
        headers.get("user-agent", ""),
    )


class DefaultDenyAuthMiddleware:
    """ASGI middleware enforcing a default-deny PDP-token policy on every route."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Only HTTP requests are gated. Passing ``lifespan`` (and any ``websocket``)
        # scopes straight through is mandatory - swallowing lifespan would break
        # OPAL/PDP startup and shutdown.
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method: str = scope["method"]
        path = _normalize_path(scope["path"])

        # Bypass genuine CORS preflight and allowlisted (public / defer-to-own-auth)
        # routes. Only real preflight OPTIONS are bypassed, not every OPTIONS, so a
        # future custom OPTIONS handler is not left unauthenticated.
        if (method == "OPTIONS" and _is_cors_preflight(scope)) or _is_allowlisted(path):
            await self.app(scope, receive, send)
            return

        if _has_valid_pdp_token(scope):
            await self.app(scope, receive, send)
            return

        # Unauthenticated request to a protected route.
        if sidecar_config.AUTH_ENFORCEMENT == AuthEnforcement.ENFORCE:
            response = JSONResponse(
                {"detail": "Missing or invalid PDP token"},
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        # Audit mode (rollout default): record what we *would* have blocked, then
        # allow the request through so nothing breaks while we instrument the fleet.
        _log_would_block(scope, path, method)
        await self.app(scope, receive, send)


def _warn_if_opal_verifier_disabled(app: FastAPI) -> None:
    """Warn (loudly) if tier-2 routes defer to an OPAL verifier that is turned off.

    The middleware steps aside for ``/policy-store`` / ``/callbacks`` / ``/opal-server``,
    trusting OPAL's own JWT auth. But OPAL's ``verify_logged_in`` allows every request
    through when the verifier is disabled (``OPAL_AUTH_PUBLIC_KEY`` unset), which would
    leave those routes fully unauthenticated. A managed PDP always has the verifier
    enabled; local/dev PDPs legitimately run without it - so this is a high-signal WARN
    (alert on it in prod), not a hard failure that would break dev.

    Accessed defensively: ``app.state.opal_client`` is only set by the real
    ``PermitPDP.__init__``; test fixtures don't set it, so an unknown state stays silent.
    """
    enabled = getattr(getattr(getattr(app.state, "opal_client", None), "verifier", None), "enabled", None)
    if enabled is False:
        logger.warning(
            "Default-deny middleware: the OPAL JWT verifier is DISABLED, but the tier-2 "
            "routes /policy-store, /callbacks and /opal-server defer to it for auth - those "
            "routes are effectively UNAUTHENTICATED. Expected in local/dev; this must never "
            "appear in a managed PDP (set OPAL_AUTH_PUBLIC_KEY)."
        )


def install_default_deny(app: FastAPI) -> None:
    """Install the default-deny middleware on the app.

    Called at the end of ``PermitPDP._configure_api_routes`` so that both the
    production app and the ``MockPermitPDP`` test fixture pick it up. Safe to call
    during construction: the middleware stack is built lazily on the first request.
    """
    # Resolve the PDP token once, here, so the per-request check is a guaranteed O(1)
    # cache hit and can never degrade to on-loop blocking network I/O or a per-request
    # SystemExit on a cold cache. get_env_api_key() caches only truthy values and the
    # ENVIRONMENT path returns PDP_API_KEY verbatim with no non-empty guard, so also
    # fail loud here on an empty/unresolved key rather than silently re-resolving forever.
    if not get_env_api_key():
        logger.critical(
            "Default-deny middleware: the PDP API key is empty/unresolved; refusing to start. Set a valid PDP_API_KEY."
        )
        raise SystemExit(GUNICORN_EXIT_APP)

    _warn_if_opal_verifier_disabled(app)

    app.add_middleware(DefaultDenyAuthMiddleware)

    if sidecar_config.AUTH_ENFORCEMENT == AuthEnforcement.ENFORCE:
        logger.info("Default-deny authentication middleware installed in ENFORCE mode.")
    else:
        # Loud, greppable banner: a fleet member left in audit mode is not enforcing.
        logger.warning(
            "Default-deny authentication middleware installed in AUDIT MODE - unauthenticated "
            "requests to protected routes will be logged but ALLOWED through. Set "
            "PDP_AUTH_ENFORCEMENT=enforce to reject them once the fleet rollout is verified."
        )
