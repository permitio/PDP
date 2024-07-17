from fastapi import Header, HTTPException, status

from horizon.config import MOCK_API_KEY, sidecar_config
from horizon.startup.api_keys import get_env_api_key


def enforce_pdp_token(authorization=Header(None)):
    if authorization is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header"
        )
    schema, token = authorization.split(" ")

    if schema.strip().lower() != "bearer" or token.strip() != get_env_api_key():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid PDP token")


def enforce_pdp_control_key(authorization=Header(None)):
    if sidecar_config.CONTAINER_CONTROL_KEY == MOCK_API_KEY:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Control API disabled. Set a PDP_CONTAINER_CONTROL_KEY variable to enable.",
        )

    if authorization is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header"
        )
    schema, token = authorization.split(" ")

    if (
        schema.strip().lower() != "bearer"
        or token.strip() != sidecar_config.CONTAINER_CONTROL_KEY
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid PDP token")
