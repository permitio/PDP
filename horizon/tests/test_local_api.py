import asyncio
import random
from contextlib import asynccontextmanager

import aiohttp
import pytest
from aioresponses import aioresponses
from fastapi import FastAPI
from fastapi.testclient import TestClient
from opal_client.client import OpalClient
from opal_client.config import opal_client_config
from starlette import status

from horizon.config import sidecar_config
from horizon.enforcer.api import stats_manager
from horizon.enforcer.schemas import *
from horizon.pdp import PermitPDP


class MockPermitPDP(PermitPDP):
    def __init__(self):
        self._setup_temp_logger()

        # sidecar_config.OPA_BEARER_TOKEN_REQUIRED = False
        # self._configure_inline_opa_config()
        self._opal = OpalClient()

        sidecar_config.API_KEY = "mock_api_key"
        app: FastAPI = self._opal.app
        self._override_app_metadata(app)
        self._configure_api_routes(app)
        self._app: FastAPI = app


sidecar = MockPermitPDP()


@pytest.mark.asyncio
async def test_list_role_assignments() -> None:
    _client = TestClient(sidecar._app)
    with aioresponses() as m:
        # 'http://localhost:8181/v1/data/permit/api/role_assignments/list_role_assignments'
        opa_url = f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/api/role_assignments/list_role_assignments"

        # Test valid response from OPA
        m.post(
            opa_url,
            status=200,
            repeat=True,
            payload={
                "result": [
                    {
                        "user": "user1",
                        "role": "role1",
                        "tenant": "tenant1",
                        "resource_instance": "resource_instance1",
                    }
                ]
            },
        )

        response = _client.get(
            "/local/role_assignments",
            headers={"authorization": f"Bearer {sidecar_config.API_KEY}"},
        )

        assert response.status_code == 200
        res_json = response.json()
        assert len(res_json) == 1
        assert res_json[0] == {
            "user": "user1",
            "role": "role1",
            "tenant": "tenant1",
            "resource_instance": "resource_instance1",
        }
