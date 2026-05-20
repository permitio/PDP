from typing import Annotated

from fastapi import Header, HTTPException, Request, status

from horizon.config import MOCK_API_KEY, sidecar_config
from horizon.startup.api_keys import get_env_api_key


def _parse_bearer_token(authorization: str | None, header_name: str) -> str:
    if authorization is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=f"Missing {header_name} header")
    parts = authorization.split(" ")
    if len(parts) != 2:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=f"bad authz header: {authorization}")
    schema, token = parts

    if schema.strip().lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid PDP token")
    return token.strip()


def extract_pdp_api_key(request: Request) -> str:
    header_name = sidecar_config.AUTH_HEADER or "Authorization"
    return _parse_bearer_token(request.headers.get(header_name), header_name)


def get_pdp_authorization_header(request: Request) -> str:
    return f"Bearer {extract_pdp_api_key(request)}"


def enforce_pdp_token(request: Request):
    if extract_pdp_api_key(request) != get_env_api_key():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid PDP token")


def enforce_pdp_control_key(authorization: Annotated[str | None, Header()]):
    if sidecar_config.CONTAINER_CONTROL_KEY == MOCK_API_KEY:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Control API disabled. Set a PDP_CONTAINER_CONTROL_KEY variable to enable.",
        )

    if authorization is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")
    token = _parse_bearer_token(authorization, "Authorization")

    if token != sidecar_config.CONTAINER_CONTROL_KEY:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid PDP token")
