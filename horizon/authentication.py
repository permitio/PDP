from fastapi import Header, HTTPException, status

from horizon.config import sidecar_config


def enforce_pdp_token(authorization=Header(None)):
    if authorization is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header"
        )
    schema, token = authorization.split(" ")

    if schema.strip().lower() != "bearer" or token.strip() != sidecar_config.API_KEY:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid PDP token")
