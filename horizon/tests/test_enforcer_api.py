import pytest
import random
import time
import asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient
from aioresponses import aioresponses, CallbackResult
import aiohttp

from horizon.pdp import PermitPDP
from horizon.enforcer.schemas import *
from horizon.config import sidecar_config
from opal_client.config import opal_client_config
from opal_client.client import OpalClient


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
api_client = TestClient(sidecar.app)

ALLOWED_ENDPOINTS = [
    (
        "/allowed",
        "permit/root",
        AuthorizationQuery(
            user=User(key="user1"),
            action="read",
            resource=Resource(type="resource1"),
        ),
        {"result": {"allow": True}},
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="DELETE",
            url="https://some.url/important_resource",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "https://some.url/important_resource",
                        "http_method": "delete",
                        "action": "delete",
                        "resource": "resource1",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/user-permissions",
        "permit/user_permissions",
        UserPermissionsQuery(
            user=User(key="user1"), resource_types=["resource1", "resource2"]
        ),
        {
            "result": {
                "permissions": {
                    "user1": {
                        "resource": {
                            "key": "resource_x",
                            "attributes": {},
                            "type": "resource1",
                        },
                        "permissions": ["read:read"],
                    }
                }
            }
        },
        {
            "user1": {
                "resource": {
                    "key": "resource_x",
                    "attributes": {},
                    "type": "resource1",
                },
                "permissions": ["read:read"],
            }
        },
    ),
    (
        "/allowed/all-tenants",
        "permit/any_tenant",
        AuthorizationQuery(
            user=User(key="user1"),
            action="read",
            resource=Resource(type="resource1"),
        ),
        {
            "result": {
                "allowed_tenants": [
                    {
                        "tenant": {"key": "default", "attributes": {}},
                        "allow": True,
                        "result": True,
                    }
                ]
            }
        },
        {
            "allowed_tenants": [
                {
                    "tenant": {"key": "default", "attributes": {}},
                    "allow": True,
                    "result": True,
                }
            ]
        },
    ),
    (
        "/allowed/bulk",
        "permit/bulk",
        [
            AuthorizationQuery(
                user=User(key="user1"),
                action="read",
                resource=Resource(type="resource1"),
            )
        ],
        {"result": {"allow": [{"allow": True, "result": True}]}},
        {"allow": [{"allow": True, "result": True}]},
    ),
    # TODO: Add Kong
]


@pytest.mark.parametrize(
    "endpoint, opa_endpoint, query, opa_response, expected_response", ALLOWED_ENDPOINTS
)
def test_enforce_endpoint(
    endpoint, opa_endpoint, query, opa_response, expected_response
):
    def post_endpoint():
        return api_client.post(
            endpoint,
            headers={"authorization": f"Bearer {sidecar_config.API_KEY}"},
            json=query.dict()
            if not isinstance(query, list)
            else [q.dict() for q in query],
        )

    with aioresponses() as m:
        opa_url = f"{opal_client_config.POLICY_STORE_URL}/v1/data/{opa_endpoint}"

        if endpoint == "/allowed_url":
            # allowed_url gonna first call the mapping rules endpoint then the normal OPA allow endpoint
            m.post(
                url=f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/root",
                status=200,
                payload={"result": {"allow": True}},
                repeat=True,
            )

        # Test valid response from OPA
        m.post(
            opa_url,
            status=200,
            payload=opa_response,
        )

        response = post_endpoint()
        assert response.status_code == 200
        print(response.json())
        for k, v in expected_response.items():
            assert response.json()[k] == v

        # Test bad status from OPA
        bad_status = random.choice([401, 404, 400, 500, 503])
        m.post(
            opa_url,
            status=bad_status,
            payload=opa_response,
        )
        response = post_endpoint()
        assert response.status_code == 502
        assert "OPA request failed" in response.text
        assert f"status: {bad_status}" in response.text

        # Test connection error
        m.post(
            opa_url,
            exception=aiohttp.ClientConnectionError("don't want to connect"),
        )
        response = post_endpoint()
        assert response.status_code == 502
        assert "OPA request failed" in response.text
        assert "don't want to connect" in response.text

        # Test timeout - not working yet
        m.post(
            opa_url,
            exception=asyncio.exceptions.TimeoutError(),
        )
        response = post_endpoint()
        assert response.status_code == 504
        assert "OPA request timed out" in response.text
