import asyncio
import random
from contextlib import asynccontextmanager

import aiohttp
import pytest
from aioresponses import aioresponses
from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
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


@asynccontextmanager
async def pdp_api_client() -> TestClient:
    _client = TestClient(sidecar._app)
    await stats_manager.run()
    yield _client
    await stats_manager.stop()


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
    (
        "/user-tenants",
        "permit/user_permissions/tenants",
        UserTenantsQuery(
            user=User(key="user1"),
        ),
        {"result": [{"attributes": {}, "key": "tenant-1"}]},
        [{"attributes": {}, "key": "tenant-1"}],
    )
    # TODO: Add Kong
]

ALLOWED_ENDPOINTS_DATASYNC = [
    (
        "/allowed",
        "/check",
        AuthorizationQuery(
            user=User(key="user1"),
            action="read",
            resource=Resource(type="resource1"),
        ),
        None,
        {"allow": True},
        {"allow": True},
    ),
    (
        "/allowed_url",
        "/check",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="DELETE",
            url="https://some.url/important_resource",
            tenant="default",
        ),
        None,
        {"allow": True},
        {"allow": True},
    ),
    (
        "/nginx_allowed",
        "/check",
        None,
        {
            "permit-user-key": "user1",
            "permit-tenant-id": "default",
            "permit-action": "read",
            "permit-resource-type": "resource1",
        },
        {"allow": True},
        {"allow": True},
    ),
    (
        "/allowed/all-tenants",
        "/check/all-tenants",
        AuthorizationQuery(
            user=User(key="user1"),
            action="read",
            resource=Resource(type="resource1"),
        ),
        None,
        {
            "allowed_tenants": [
                {
                    "tenant": {"key": "default", "attributes": {}},
                    "allow": True,
                    "result": True,
                }
            ]
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
        "/check/bulk",
        [
            AuthorizationQuery(
                user=User(key="user1"),
                action="read",
                resource=Resource(type="resource1"),
            )
        ],
        None,
        {"allow": [{"allow": True, "result": True}]},
        {"allow": [{"allow": True, "result": True}]},
    ),
    (
        "/user-tenants",
        "/users/user1/tenants",
        UserTenantsQuery(
            user=User(key="user1"),
        ),
        None,
        [{"key": "default-2", "attributes": {}}, {"key": "default", "attributes": {}}],
        [{"key": "default-2", "attributes": {}}, {"key": "default", "attributes": {}}],
    ),
    (
        "/user-permissions",
        "/user-permissions",
        UserPermissionsQuery(
            user=User(key="user1"),
        ),
        None,
        {
            "user1": {
                "resource": {
                    "key": "resource_x",
                    "attributes": {},
                    "type": "resource1",
                },
                "tenant": {"key": "default", "attributes": {}},
                "permissions": ["read:read"],
                "roles": ["admin"],
            }
        },
        {
            "user1": {
                "resource": {
                    "key": "resource_x",
                    "attributes": {},
                    "type": "resource1",
                },
                "tenant": {"key": "default", "attributes": {}},
                "permissions": ["read:read"],
                "roles": ["admin"],
            }
        },
    ),
]


@pytest.mark.parametrize(
    "endpoint, opa_endpoint, query, opa_response, expected_response",
    list(
        filter(lambda p: not isinstance(p[2], UrlAuthorizationQuery), ALLOWED_ENDPOINTS)
    ),
)
@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_enforce_endpoint_statistics(
    endpoint: str,
    opa_endpoint: str,
    query: AuthorizationQuery | list[AuthorizationQuery],
    opa_response: dict,
    expected_response: dict,
) -> None:
    async with pdp_api_client() as client:

        def post_endpoint():
            return client.post(
                endpoint,
                headers={"authorization": f"Bearer {sidecar_config.API_KEY}"},
                json=query.dict()
                if not isinstance(query, list)
                else [q.dict() for q in query],
            )

        with aioresponses() as m:
            opa_url = f"{opal_client_config.POLICY_STORE_URL}/v1/data/{opa_endpoint}"

            # Test valid response from OPA
            m.post(
                opa_url,
                status=200,
                payload=opa_response,
            )

            response = post_endpoint()

            assert response.status_code == 200
            print(response.json())
            if isinstance(expected_response, list):
                assert response.json() == expected_response
            elif isinstance(expected_response, dict):
                for k, v in expected_response.items():
                    assert response.json()[k] == v
            else:
                raise TypeError(
                    f"Unexpected expected response type, expected one of list, dict and got {type(expected_response)}"
                )

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
            await asyncio.sleep(2)
            current_rate = await stats_manager.current_rate()
            assert current_rate == (3.0 / 4.0)
            assert (
                client.get("/health").status_code == status.HTTP_503_SERVICE_UNAVAILABLE
            )
            await stats_manager.reset_stats()
            current_rate = await stats_manager.current_rate()
            assert current_rate == 0
            assert (
                client.get("/health").status_code == status.HTTP_503_SERVICE_UNAVAILABLE
            )


@pytest.mark.parametrize(
    "endpoint, opa_endpoint, query, opa_response, expected_response", ALLOWED_ENDPOINTS
)
def test_enforce_endpoint(
    endpoint,
    opa_endpoint,
    query,
    opa_response,
    expected_response,
):
    _client = TestClient(sidecar._app)

    def post_endpoint():
        return _client.post(
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
        if isinstance(expected_response, list):
            assert response.json() == expected_response
        elif isinstance(expected_response, dict):
            for k, v in expected_response.items():
                assert response.json()[k] == v
        else:
            raise TypeError(
                f"Unexpected expected response type, expected one of list, dict and got {type(expected_response)}"
            )

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


@pytest.mark.parametrize(
    (
        "endpoint",
        "datasync_endpoint",
        "query",
        "headers",
        "datasync_response",
        "expected_response",
    ),
    ALLOWED_ENDPOINTS_DATASYNC,
)
def test_enforce_endpoint_datasync(
    endpoint: str,
    datasync_endpoint: str,
    query: list[BaseModel] | BaseModel | None,
    headers: dict | None,
    datasync_response: dict,
    expected_response: dict,
):
    sidecar_config.ENABLE_EXTERNAL_DATA_MANAGER = True
    _client = TestClient(sidecar._app)

    def post_endpoint():
        return _client.post(
            endpoint,
            headers={"authorization": f"Bearer {sidecar_config.API_KEY}"}
            | (headers or {}),
            json=jsonable_encoder(query) if query else None,
        )

    with aioresponses() as m:
        datasync_url = (
            f"{sidecar_config.DATA_MANAGER_SERVICE_URL}/v1/authz{datasync_endpoint}"
        )

        method = "POST"

        match endpoint:
            case "/allowed_url":
                # allowed_url gonna first call the mapping rules endpoint then the normal OPA allow endpoint
                m.post(
                    url=f"{opal_client_config.POLICY_STORE_URL}/v1/data/mapping_rules",
                    status=200,
                    payload={
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
                    repeat=True,
                )
            case "/user-tenants":
                method = "GET"

        # Test valid response from OPA
        m.add(
            datasync_url,
            method=method,
            status=200,
            payload=datasync_response,
        )

        response = post_endpoint()
        assert response.status_code == 200
        print(response.json())
        if isinstance(expected_response, list):
            assert response.json() == expected_response
        elif isinstance(expected_response, dict):
            for k, v in expected_response.items():
                try:
                    assert (
                        response.json()[k] == v
                    ), f"Expected {k} to be {v} but got {response.json()[k]}"
                except KeyError:
                    pytest.fail(
                        f"response missing key {k} from expected response:\n,{response.json()}"
                    )
        else:
            raise TypeError(
                f"Unexpected expected response type, expected one of list, dict and got {type(expected_response)}"
            )

        # Test bad status from OPA
        bad_status = random.choice([401, 404, 400, 500, 503])
        m.add(
            datasync_url,
            method=method,
            status=bad_status,
            payload=datasync_response,
        )
        response = post_endpoint()
        assert response.status_code == 502
        assert "Data Manager request failed" in response.text
        assert f"status: {bad_status}" in response.text

        # Test connection error
        m.add(
            datasync_url,
            method=method,
            exception=aiohttp.ClientConnectionError("don't want to connect"),
        )
        response = post_endpoint()
        assert response.status_code == 502
        assert "Data Manager request failed" in response.text
        assert "don't want to connect" in response.text

        # Test timeout - not working yet
        m.add(
            datasync_url,
            method=method,
            exception=asyncio.exceptions.TimeoutError(),
        )
        response = post_endpoint()
        assert response.status_code == 504
        assert "Data Manager request timed out" in response.text
