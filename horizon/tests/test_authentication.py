from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from horizon.authentication import enforce_pdp_token, get_pdp_authorization_header
from horizon.config import sidecar_config


def test_pdp_auth_uses_configured_header() -> None:
    previous_api_key = sidecar_config.API_KEY
    previous_auth_header = sidecar_config.AUTH_HEADER
    sidecar_config.API_KEY = "mock_api_key"
    sidecar_config.AUTH_HEADER = "X-API-Key"

    app = FastAPI()

    @app.get("/protected", dependencies=[Depends(enforce_pdp_token)])
    def protected(request: Request):
        return {"authorization": get_pdp_authorization_header(request)}

    try:
        client = TestClient(app)

        response = client.get("/protected", headers={"X-API-Key": "Bearer mock_api_key"})

        assert response.status_code == 200
        assert response.json() == {"authorization": "Bearer mock_api_key"}

        response = client.get("/protected", headers={"Authorization": "Bearer mock_api_key"})

        assert response.status_code == 401
    finally:
        sidecar_config.API_KEY = previous_api_key
        sidecar_config.AUTH_HEADER = previous_auth_header
