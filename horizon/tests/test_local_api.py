from pathlib import Path

import pytest
from aioresponses import aioresponses
from fastapi import FastAPI
from fastapi.testclient import TestClient
from horizon.config import sidecar_config
from horizon.factdb.client import FactDBClient
from horizon.pdp import PermitPDP
from loguru import logger
from opal_client.client import OpalClient
from opal_client.config import opal_client_config


class MockPermitPDP(PermitPDP):
    def __init__(self, opal: OpalClient | None = None):
        self._setup_temp_logger()

        # sidecar_config.OPA_BEARER_TOKEN_REQUIRED = False
        # self._configure_inline_opa_config()
        self._opal = opal or OpalClient()

        sidecar_config.API_KEY = "mock_api_key"
        app: FastAPI = self._opal.app
        self._override_app_metadata(app)
        self._configure_api_routes(app)
        self._app: FastAPI = app


class MockFactDBPermitPDP(MockPermitPDP):
    def __init__(self):
        super().__init__(opal=FactDBClient(shard_id=sidecar_config.SHARD_ID, data_topics=self._fix_data_topics()))


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

        m.assert_called_once()
        assert response.status_code == 200
        res_json = response.json()
        assert len(res_json) == 1
        assert res_json[0] == {
            "user": "user1",
            "role": "role1",
            "tenant": "tenant1",
            "resource_instance": "resource_instance1",
        }


@pytest.mark.asyncio
async def test_list_role_assignments_wrong_factdb_config() -> None:
    _sidecar = MockFactDBPermitPDP()
    # the FACTDB_ENABLED is set to True after the PDP was created
    # this causes the PDP to be without the FactDBPolicyStoreClient - it is a uniquely rare case
    # that will probably never happen as this config is managed either by a remote config or env var
    sidecar_config.FACTDB_ENABLED = True
    _client = TestClient(_sidecar._app)
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

        m.assert_called_once()
        assert response.status_code == 200
        res_json = response.json()
        assert len(res_json) == 1
        assert res_json[0] == {
            "user": "user1",
            "role": "role1",
            "tenant": "tenant1",
            "resource_instance": "resource_instance1",
        }


@pytest.mark.asyncio
async def test_list_role_assignments_factdb(tmp_path: Path) -> None:
    sidecar_config.FACTDB_ENABLED = True
    sidecar_config.OFFLINE_MODE_BACKUP_DIR = tmp_path / "backup"
    _sidecar = MockFactDBPermitPDP()
    _client = TestClient(_sidecar._app)
    with aioresponses() as m:
        # The policy store client of the FactDB has base url configured, this means that the url
        # we need to mock is '/v1/facts/role_assignments' - without the base url server
        factdb_url = "/v1/facts/role_assignments?page=1&per_page=30"
        logger.info("mocking FactDB url: {}", factdb_url)
        # Test valid response from OPA
        m.get(
            factdb_url,
            status=200,
            repeat=True,
            payload=[
                {
                    "type": "role_assignment",
                    "attributes": {
                        "actor": "user:user1",
                        "role": "role1",
                        "tenant": "tenant1",
                        "resource": "resource_instance1",
                        "id": "user:user1-role1-resource_instance1",
                    },
                }
            ],
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
    sidecar_config.FACTDB_ENABLED = False
