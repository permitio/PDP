import hmac
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from horizon.config import MOCK_API_KEY, sidecar_config
from horizon.startup.api_keys import get_env_api_key

# Routes that are genuinely public - EXACT path match only, never a prefix. This is the
# single source of truth for "no PDP token required", imported by the route-audit test
# (horizon/tests/test_route_auth_audit.py) and the upcoming PER-15249 CI guard.
#
# It must stay exact-match: a naive startswith("/health") check would wrongly expose the
# gated "/healthchecks/opa/*" OPA proxy routes. "/docs/oauth2-redirect" is registered by
# FastAPI by default and is needed for the Swagger "Authorize" flow. "/scalar" is the
# API explorer, registered in _configure_api_routes like every other route so the audit
# sees it - every entry here must match a route the audit-built app actually mounts.
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
