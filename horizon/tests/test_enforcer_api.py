import asyncio
import random
from contextlib import asynccontextmanager

import aiohttp
import pytest
from aioresponses import aioresponses
from fastapi import FastAPI
from fastapi.testclient import TestClient
from horizon.config import sidecar_config
from horizon.enforcer.api import stats_manager
from horizon.enforcer.schemas import (
    AuthorizationQuery,
    Resource,
    UrlAuthorizationQuery,
    User,
    UserPermissionsQuery,
    UserTenantsQuery,
)
from horizon.pdp import PermitPDP
from loguru import logger
from opal_client.client import OpalClient
from opal_client.config import opal_client_config
from starlette import status


class MockPermitPDP(PermitPDP):
    def __init__(self):
        self._setup_temp_logger()

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


PROTECTED_ENFORCER_ENDPOINTS = [
    "/allowed",
    "/allowed/bulk",
    "/allowed/all-tenants",
    "/allowed_url",
    "/user-permissions",
    "/user-tenants",
    "/authorized_users",
    "/nginx_allowed",
    "/kong",
]

KONG_QUERY = {
    "input": {
        "request": {
            "http": {
                "host": "api.example.com",
                "port": 80,
                "tls": {},
                "method": "GET",
                "scheme": "http",
                "path": "/resource1/some-id",
                "querystring": {},
                "headers": {},
            }
        },
        "client_ip": "127.0.0.1",
        "consumer": {"id": "b1b2ac9e-a1b6-4c68-b447-a03d13c0e3e3", "username": "user1"},
    }
}


@pytest.mark.parametrize("endpoint", PROTECTED_ENFORCER_ENDPOINTS)
def test_enforcer_endpoint_missing_token_returns_401(endpoint):
    client = TestClient(sidecar._app)
    response = client.post(endpoint, json={})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Missing Authorization header"


@pytest.mark.parametrize("endpoint", PROTECTED_ENFORCER_ENDPOINTS)
def test_enforcer_endpoint_invalid_token_returns_401(endpoint):
    client = TestClient(sidecar._app)
    response = client.post(endpoint, headers={"authorization": "Bearer wrong_token"}, json={})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Invalid PDP token"


@pytest.mark.parametrize("endpoint", PROTECTED_ENFORCER_ENDPOINTS)
@pytest.mark.parametrize("value", ["garbage", "Bearer", "Bearer ", "Bearer a b c"])
def test_enforcer_endpoint_malformed_header_is_401_not_500(endpoint, value):
    client = TestClient(sidecar._app)
    response = client.post(endpoint, headers={"authorization": value}, json={})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_health_endpoint_is_public(monkeypatch):
    monkeypatch.setattr(stats_manager, "_had_failure", False)
    client = TestClient(sidecar._app)
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"status": "ok"}


def test_kong_endpoint_valid_token_integration_disabled_returns_503():
    client = TestClient(sidecar._app)
    response = client.post(
        "/kong",
        headers={"authorization": f"Bearer {sidecar_config.API_KEY}"},
        json=KONG_QUERY,
    )
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


def test_kong_endpoint_enabled_integration_allowed_flow(tmp_path, monkeypatch):
    routes_file = tmp_path / "kong_routes.json"
    routes_file.write_text('[["^/resource1/.*$", "resource1"]]')
    monkeypatch.setattr("horizon.enforcer.api.KONG_ROUTES_TABLE_FILE", str(routes_file))
    monkeypatch.setattr(sidecar_config, "KONG_INTEGRATION", True)

    class FakeStateHandler:
        async def seen_sdk(self, _sdk: str) -> None:
            return None

    monkeypatch.setattr("horizon.state.PersistentStateHandler._instance", FakeStateHandler())
    # isolate the shared stats queue so this test's OPA calls don't leak into the statistics tests
    monkeypatch.setattr(stats_manager, "_messages", asyncio.Queue())

    kong_sidecar = MockPermitPDP()
    client = TestClient(kong_sidecar._app)

    response = client.post("/kong", json=KONG_QUERY)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    with aioresponses() as m:
        m.post(
            f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/root",
            status=200,
            payload={"result": {"allow": True}},
        )
        response = client.post(
            "/kong",
            headers={"authorization": f"Bearer {sidecar_config.API_KEY}"},
            json=KONG_QUERY,
        )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"result": True}


def test_authorized_users_endpoint_valid_token_allowed_flow(monkeypatch):
    monkeypatch.setattr(stats_manager, "_messages", asyncio.Queue())
    client = TestClient(sidecar._app)
    with aioresponses() as m:
        m.post(
            f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/authorized_users/authorized_users",
            status=200,
            payload={"result": {"result": {"resource": "resource1:*", "tenant": "default", "users": {}}}},
        )
        response = client.post(
            "/authorized_users",
            headers={"authorization": f"Bearer {sidecar_config.API_KEY}"},
            json={"action": "read", "resource": {"type": "resource1"}},
        )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["resource"] == "resource1:*"


def test_nginx_allowed_endpoint_valid_token_allowed_flow(monkeypatch):
    monkeypatch.setattr(stats_manager, "_messages", asyncio.Queue())
    client = TestClient(sidecar._app)
    with aioresponses() as m:
        m.post(
            f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/root",
            status=200,
            payload={"result": {"allow": True}},
        )
        response = client.post(
            "/nginx_allowed",
            headers={
                "authorization": f"Bearer {sidecar_config.API_KEY}",
                "permit-user-key": "user1",
                "permit-tenant-id": "default",
                "permit-action": "read",
                "permit-resource-type": "resource1",
            },
        )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["allow"] is True


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
        UserPermissionsQuery(user=User(key="user1"), resource_types=["resource1", "resource2"]),
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
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/api/v1/users/123/profile",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/api/v1/users/(?P<user_id>[0-9]+)/profile$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/api/v1/users/abc/profile",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/api/v1/users/(?P<user_id>[0-9]+)/profile$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": False},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="POST",
            url="https://api.example.com/v2/organizations/org123/users/456/settings",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/v2/organizations/(?P<org_id>[\\w-]+)/users/(?P<user_id>[0-9]+)/settings$",
                        "http_method": "post",
                        "action": "update",
                        "resource": "user_settings",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/api/users",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/api/users(?:/(?P<user_id>[0-9]+))?$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/api/v1/users/123/profile?include=details",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/api/v1/users/(?P<user_id>[0-9]+)/profile(?:\\?(?P<query>.*))?$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="http://api.example.com/api/v1/users/123",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https?://api\\.example\\.com/api/v1/users/(?P<user_id>[0-9]+)$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://subdomain.example.com/api/v1/users/123",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://[\\w-]+\\.example\\.com/api/v1/users/(?P<user_id>[0-9]+)$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/api/v1/users/123/profile/../../../sensitive",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/api/v1/users/(?P<user_id>[0-9]+)/profile$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": False},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/api/v1/users/123/profile",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "[invalid regex",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": False},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/api/v1/users/123/profile!@#$%",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/api/v1/users/(?P<user_id>[0-9]+)/profile[!@#$%]+$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    # Non-regex URL pattern test cases
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/users/123/profile",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "https://api.example.com/users/{user_id}/profile",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "default",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/orgs/org123/repos/repo456",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "https://api.example.com/orgs/{org_id}/repos/{repo_id}",
                        "http_method": "get",
                        "action": "read",
                        "resource": "repositories",
                        "url_type": "default",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/search?q=test&page=1",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "https://api.example.com/search?q={query}&page={page_num}",
                        "http_method": "get",
                        "action": "read",
                        "resource": "search",
                        "url_type": "default",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/users/123/settings/notifications",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "https://api.example.com/users/{user_id}/settings/{setting_type}",
                        "http_method": "get",
                        "action": "read",
                        "resource": "user_settings",
                        "url_type": "default",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/users/invalid/profile",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "https://api.example.com/users/{user_id}/profile",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "default",
                    }
                ]
            }
        },
        {"allow": True},  # Should allow since {user_id} matches any string
    ),
    # URL Encoding/Decoding Tests
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/users/123/profile%20space",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/users/(?P<user_id>[0-9]+)/profile%20space$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/users/123/profile%E2%98%BA",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/users/(?P<user_id>[0-9]+)/profile%E2%98%BA$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    # Complex URL Pattern Tests
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/search?q=test&page=1&sort=desc",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/search\\?(?=.*q=(?P<query>[^&]+))(?=.*page=(?P<page>[0-9]+))(?=.*sort=(?P<sort>asc|desc)).*$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "search",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {
            "allow": True
            # TODO: change to False when we switch to re2 regex engine
        },  # RE2 regex engine doesn't support lookaheads, system correctly denies access for invalid patterns
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/filter?ids=[1,2,3]",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/filter\\?ids=\\[(?P<ids>[0-9,]+)\\]$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "filter",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    # Edge Cases
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/users//profile",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/users/(?P<user_id>[0-9]*)/profile$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/users/123/profile/",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/users/(?P<user_id>[0-9]+)/profile/?$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": True},
    ),
    (
        "/allowed_url",
        "mapping_rules",
        UrlAuthorizationQuery(
            user=User(key="user1"),
            http_method="GET",
            url="https://api.example.com/users/123/profile/",
            tenant="default",
        ),
        {
            "result": {
                "all": [
                    {
                        "url": "^https://api\\.example\\.com/users/(?P<user_id>[0-9]+)/profile/?$",
                        "http_method": "get",
                        "action": "read",
                        "resource": "users",
                        "url_type": "regex",
                    }
                ]
            }
        },
        {"allow": True},
    ),
]


@pytest.mark.parametrize(
    "endpoint, opa_endpoint, query, opa_response, expected_response",
    list(filter(lambda p: not isinstance(p[2], UrlAuthorizationQuery), ALLOWED_ENDPOINTS)),
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
                json=query.dict() if not isinstance(query, list) else [q.dict() for q in query],
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
            logger.info(response.json())
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
            assert client.get("/health").status_code == status.HTTP_503_SERVICE_UNAVAILABLE
            await stats_manager.reset_stats()
            current_rate = await stats_manager.current_rate()
            assert current_rate == 0
            assert client.get("/health").status_code == status.HTTP_503_SERVICE_UNAVAILABLE


@pytest.mark.parametrize("endpoint, opa_endpoint, query, opa_response, expected_response", ALLOWED_ENDPOINTS)
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
            json=query.dict() if not isinstance(query, list) else [q.dict() for q in query],
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
        logger.info(response.json())
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
