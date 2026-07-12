import hmac
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from opal_client.logger import logger

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
    if sidecar_config.ENFORCE_OPERATIONAL_ROUTE_AUTH:
        enforce_pdp_token(credentials)
        return
    # Permissive rollout default: reuse enforce_pdp_token's exact reject logic, but downgrade a
    # rejection to warn-and-allow so no caller breaks while every would-be rejection is still flagged.
    try:
        enforce_pdp_token(credentials)
    except HTTPException as exc:
        logger.warning(
            "ENFORCE_OPERATIONAL_ROUTE_AUTH is off: allowing {method} {path} unauthenticated - it would "
            "otherwise be rejected ({detail}). Set ENFORCE_OPERATIONAL_ROUTE_AUTH=true to enforce the PDP "
            "token on this route.",
            method=request.method,
            path=request.url.path,
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
