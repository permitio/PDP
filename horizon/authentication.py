import hmac
import threading
import time
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger

from horizon.config import MOCK_API_KEY, sidecar_config
from horizon.startup.api_keys import get_env_api_key

# Routes that are genuinely public - EXACT path match only, never a prefix. This is the
# single source of truth for "no PDP token required", imported by the route-audit test
# (horizon/tests/test_route_auth_audit.py) and the upcoming PER-15249 CI guard.
#
# It must stay exact-match: a naive startswith("/health") check would wrongly expose the
# gated "/healthchecks/opa/*" OPA proxy routes. "/docs/oauth2-redirect" is registered by
# FastAPI by default and is needed for the Swagger "Authorize" flow. "/scalar" is
# registered in PermitPDP.__init__ (after route configuration), so it is absent from the
# app the audit builds - listing it here is harmless and keeps the set accurate for prod.
PUBLIC_ROUTE_PATHS: frozenset[str] = frozenset(
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


# FastAPI's standard bearer-token security scheme parses "Authorization: Bearer <token>"
# for us and registers itself in the OpenAPI schema (so the Swagger "Authorize" button
# works). auto_error=False makes it return None - rather than raise its own 403 - for a
# missing, malformed, or non-bearer header, which lets us:
#   * return the PDP's documented 401 (not HTTPBearer's default 403), and
#   * let enforce_pdp_control_key's "control API disabled" 503 take precedence over the
#     header check (the security dependency runs before the function body).
_pdp_bearer = HTTPBearer(auto_error=False, scheme_name="PDP token", description="PDP API key as a bearer token")

PdpCredentials = Annotated[HTTPAuthorizationCredentials | None, Depends(_pdp_bearer)]


def _token_matches(credentials: HTTPAuthorizationCredentials | None, expected_token: str) -> bool:
    """Constant-time compare of the presented bearer token against the expected secret.

    HTTPBearer already parsed and validated the header; the only thing left that FastAPI
    can't do for us is compare the token to our shared secret. Return False for a
    missing/malformed header (credentials is None). Both operands are byte-encoded, which
    is what keeps a non-ASCII token safe: ``hmac.compare_digest`` raises TypeError on
    non-ASCII *str* inputs (header values are latin-1 decoded) but never on bytes.
    """
    if credentials is None:
        return False
    return hmac.compare_digest(credentials.credentials.encode("utf-8"), expected_token.encode("utf-8"))


def enforce_pdp_token(credentials: PdpCredentials = None):
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")
    if not _token_matches(credentials, get_env_api_key()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid PDP token")


# Rate-limit for the warn-and-allow path of enforce_pdp_token_operational. While
# ENFORCE_OPERATIONAL_ROUTE_AUTH is off, every unauthenticated request to a governed route would
# otherwise emit one WARNING - which on the high-QPS /kong decision endpoint floods the synchronous
# stdout log sink (and adds a blocking write to the request path). Instead we coalesce to one line
# per route per interval that reports how many would-be rejections were allowed and the real span
# they cover; that count is also the rollout signal - watch it fall to zero, then flip the flag on.
# The gate runs in a threadpool (it is a sync dependency), so the shared counters are guarded by a
# plain threading.Lock. A path's coalesced tail is flushed lazily - only by the next request that
# arrives past the interval - so between flushes the live count is best-effort; a route that falls
# idle mid-window strands its tail until the next request or process exit. flush_operational_warn_residuals()
# (wired into app shutdown in horizon/pdp.py) surfaces that residual on a graceful drain, but a
# long-lived worker with an idle route still under-reports until traffic resumes, and the count is
# per-process (N gunicorn workers = N streams) - so treat "the logs went quiet" as best-effort, not
# proof every caller migrated.
_OPERATIONAL_WARN_INTERVAL_SECONDS = 60.0
_operational_warn_lock = threading.Lock()
# path -> (would-be rejections accumulated since the last emitted line, monotonic time of that emit)
_operational_warn_state: dict[str, tuple[int, float]] = {}


def reset_operational_warn_throttle() -> None:
    """Clear the process-global throttle state.

    Used by tests so an asserted warning is not suppressed by a warning already logged for the same
    path in a prior test - the throttle state outlives a single test. Wired as an autouse fixture in
    the test conftest.
    """
    with _operational_warn_lock:
        _operational_warn_state.clear()


def _operational_warn_should_emit(path: str) -> tuple[bool, int, float]:
    """Decide whether to emit the warn-and-allow line for ``path`` now, coalescing bursts.

    Returns ``(emit_now, count, window_seconds)``. Every call counts as one would-be rejection. A
    line is emitted on the first hit for a path and then at most once per
    ``_OPERATIONAL_WARN_INTERVAL_SECONDS``; ``count`` is the number of rejections coalesced into the
    emitted line and ``window_seconds`` is the real span they cover (``now - last_emit``, which can
    exceed the interval when a route is sparse), so the caller reports the true window rather than a
    fixed one.
    """
    now = time.monotonic()
    with _operational_warn_lock:
        state = _operational_warn_state.get(path)
        if state is None:
            _operational_warn_state[path] = (0, now)
            return True, 1, 0.0
        pending, last_emit = state
        pending += 1
        window = now - last_emit
        if window >= _OPERATIONAL_WARN_INTERVAL_SECONDS:
            _operational_warn_state[path] = (0, now)
            return True, pending, window
        _operational_warn_state[path] = (pending, last_emit)
        return False, pending, window


def flush_operational_warn_residuals() -> None:
    """Emit any coalesced would-be-rejection counts still pending, so an idle route drops no tail.

    The warn-and-allow throttle only flushes a path's coalesced count when a *later* request arrives
    past the interval (see ``_operational_warn_should_emit``). A route that goes quiet mid-window
    would otherwise never report the requests coalesced since its last emitted line - and that count
    is the rollout signal operators watch fall to zero, so it under-reports exactly when traffic is
    sparse. Wired into app shutdown (``horizon/pdp.py``) so a draining worker surfaces its residual
    before exit; safe to call at any time and a no-op when nothing is pending.

    Best-effort, not a completeness guarantee: only a *graceful* drain runs this. An ungraceful exit
    (SIGKILL from the watchdog, ``/_exit``'s ``os._exit``) skips it, and a long-lived healthy worker
    with an idle route still strands its tail until traffic resumes. Confirm a rollout is complete by
    the emitted count trending to zero across an interval of live traffic - not by silence.
    """
    now = time.monotonic()
    with _operational_warn_lock:
        residuals = []
        for path, (pending, last_emit) in list(_operational_warn_state.items()):
            if pending > 0:
                residuals.append((path, pending, now - last_emit))
                _operational_warn_state[path] = (0, now)
    for path, pending, window in residuals:
        logger.warning(
            "ENFORCE_OPERATIONAL_ROUTE_AUTH is off: flushing {count} further request(s) without a valid "
            "PDP token (missing or invalid) to {path}, coalesced over the last ~{window}s since the last "
            "reported line and flushed on shutdown (add to any 'allowed N' line already logged for this "
            "route to get the true total). Set ENFORCE_OPERATIONAL_ROUTE_AUTH=true to enforce the PDP "
            "token on this route.",
            count=pending,
            path=path,
            window=round(window),
        )


def enforce_pdp_token_operational(request: Request, credentials: PdpCredentials = None):
    """PDP-token gate for the operational routes hardened by PER-15244/PER-15245, with a rollout default.

    Governed by ``ENFORCE_OPERATIONAL_ROUTE_AUTH``. When it is true this is exactly ``enforce_pdp_token``.
    When it is false - the default, for a safe fleet rollout - a request that would be rejected is allowed
    through but logged, so callers that don't yet send the PDP token keep working while the logs surface
    them before enforcement is switched on.

    The flag is read per-request (never captured at import) so a cloud control-plane override takes
    effect and tests can toggle it. Kept as a distinct, named module-level function because the
    fail-closed route audit recognises auth gates by callable name - a bare ``enforce_pdp_token`` here
    could not carry the conditional behaviour, and an inline lambda would be invisible to the audit.
    """
    # Reuse enforce_pdp_token's exact reject logic in one place. When the flag is on, a rejection is
    # honoured (re-raised). When it is off - the rollout default - the rejection is downgraded to
    # warn-and-allow so no caller breaks; every would-be rejection is still counted, and surfaced in a
    # per-route coalesced warning (see _operational_warn_should_emit) rather than one line per request.
    try:
        enforce_pdp_token(credentials)
    except HTTPException as exc:
        if sidecar_config.ENFORCE_OPERATIONAL_ROUTE_AUTH:
            raise
        emit, coalesced, window = _operational_warn_should_emit(request.url.path)
        if emit:
            logger.warning(
                "ENFORCE_OPERATIONAL_ROUTE_AUTH is off: allowed {count} request(s) without a valid PDP token "
                "(missing or invalid) to {method} {path} in the last ~{window}s that would otherwise be "
                "rejected (e.g. {detail}). Set ENFORCE_OPERATIONAL_ROUTE_AUTH=true to enforce the PDP token "
                "on this route.",
                count=coalesced,
                method=request.method,
                path=request.url.path,
                window=round(window),
                detail=exc.detail,
            )


def enforce_pdp_control_key(credentials: PdpCredentials = None):
    if sidecar_config.CONTAINER_CONTROL_KEY == MOCK_API_KEY:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Control API disabled. Set a PDP_CONTAINER_CONTROL_KEY variable to enable.",
        )

    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")
    if not _token_matches(credentials, sidecar_config.CONTAINER_CONTROL_KEY):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid PDP token")
