import pytest
from aioresponses import aioresponses
from fastapi.testclient import TestClient
from fastapi_cache import FastAPICache
from horizon.config import sidecar_config
from horizon.enforcer.schemas import User, UserPermissionsQuery
from opal_client.config import opal_client_config
from test_enforcer_api import MockPermitPDP


@pytest.fixture
def sidecar_with_cache():
    orig_config = sidecar_config.PDP_CACHE_ENABLED
    orig_ttl = sidecar_config.PDP_CACHE_TTL_SEC
    # Enable caching for this test
    sidecar_config.PDP_CACHE_ENABLED = True
    sidecar_config.PDP_CACHE_TTL_SEC = 3600
    yield MockPermitPDP()
    # Restore the original config
    sidecar_config.PDP_CACHE_ENABLED = orig_config
    sidecar_config.PDP_CACHE_TTL_SEC = orig_ttl


@pytest.fixture
def sidecar_without_cache():
    orig_config = sidecar_config.PDP_CACHE_ENABLED
    # Disable caching for this test
    sidecar_config.PDP_CACHE_ENABLED = False
    yield MockPermitPDP()
    # Restore the original config
    sidecar_config.PDP_CACHE_ENABLED = orig_config


@pytest.fixture
def mocked_api():
    with aioresponses() as mocked_api:
        yield mocked_api


@pytest.fixture
def client_with_cache(sidecar_with_cache: MockPermitPDP):
    with TestClient(sidecar_with_cache.app) as c:
        yield c


@pytest.fixture
def client_without_cache(sidecar_without_cache: MockPermitPDP):
    with TestClient(sidecar_without_cache.app) as c:
        yield c


@pytest.mark.asyncio
async def test_user_permissions_cache(mocked_api: aioresponses, client_with_cache: TestClient):
    await FastAPICache.clear()
    """Test that user permissions are cached when caching is enabled"""
    client = client_with_cache

    query = UserPermissionsQuery(user=User(key="test_user"), resource_types=["resource1"])

    opa_response = {
        "result": {
            "permissions": {
                "test_user": {
                    "resource": {
                        "key": "resource_x",
                        "attributes": {},
                        "type": "resource1",
                    },
                    "permissions": ["read:read"],
                }
            }
        }
    }

    expected_response = {
        "test_user": {
            "resource": {
                "key": "resource_x",
                "attributes": {},
                "type": "resource1",
            },
            "permissions": ["read:read"],
        }
    }

    # Mock the OPA response
    mocked_api.post(
        f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/user_permissions",
        status=200,
        payload=opa_response,
        # we mock only once because on the second request the cache will be hit
        # and we want to make sure it's working
        repeat=False,
    )

    # First request should hit the API
    response = client.post(
        "/user-permissions", json=query.dict(), headers={"Authorization": f"Bearer {sidecar_config.API_KEY}"}
    )
    assert response.status_code == 200
    assert response.json() == expected_response

    # Second request should be served from cache
    response = client.post(
        "/user-permissions", json=query.dict(), headers={"Authorization": f"Bearer {sidecar_config.API_KEY}"}
    )
    assert response.status_code == 200
    assert response.json() == expected_response

    assert len(mocked_api.requests) == 1
    assert len(next(iter(mocked_api.requests.values()))) == 1


@pytest.mark.asyncio
async def test_user_permissions_no_cache(mocked_api: aioresponses, client_without_cache: TestClient):
    """Test that user permissions are not cached when caching is disabled"""
    # Disable caching for this test
    client = client_without_cache

    query = UserPermissionsQuery(user=User(key="test_user"), resource_types=["resource1"])

    opa_response = {
        "result": {
            "permissions": {
                "test_user": {
                    "resource": {
                        "key": "resource_x",
                        "attributes": {},
                        "type": "resource1",
                    },
                    "permissions": ["read:read"],
                }
            }
        }
    }

    expected_response = {
        "test_user": {
            "resource": {
                "key": "resource_x",
                "attributes": {},
                "type": "resource1",
            },
            "permissions": ["read:read"],
        }
    }

    # Mock the OPA response
    mocked_api.post(
        f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/user_permissions",
        status=200,
        payload=opa_response,
        repeat=True,
    )

    # First request should hit the API
    response = client.post(
        "/user-permissions", json=query.dict(), headers={"Authorization": f"Bearer {sidecar_config.API_KEY}"}
    )
    assert response.status_code == 200
    assert response.json() == expected_response

    # Second request should also hit the API (no caching)
    response = client.post(
        "/user-permissions", json=query.dict(), headers={"Authorization": f"Bearer {sidecar_config.API_KEY}"}
    )
    assert response.status_code == 200
    assert response.json() == expected_response

    assert len(mocked_api.requests) == 1
    assert len(next(iter(mocked_api.requests.values()))) == 2


@pytest.mark.asyncio
async def test_user_permissions_cache_different_users(mocked_api: aioresponses, client_with_cache: TestClient):
    await FastAPICache.clear()
    """Test that different users get different cache entries"""
    client = client_with_cache

    query1 = UserPermissionsQuery(user=User(key="user1"), resource_types=["resource1"])

    query2 = UserPermissionsQuery(user=User(key="user2"), resource_types=["resource1"])

    opa_response1 = {
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
    }

    opa_response2 = {
        "result": {
            "permissions": {
                "user2": {
                    "resource": {
                        "key": "resource_x",
                        "attributes": {},
                        "type": "resource1",
                    },
                    "permissions": ["write:write"],
                }
            }
        }
    }

    expected_response1 = {
        "user1": {
            "resource": {
                "key": "resource_x",
                "attributes": {},
                "type": "resource1",
            },
            "permissions": ["read:read"],
        }
    }

    expected_response2 = {
        "user2": {
            "resource": {
                "key": "resource_x",
                "attributes": {},
                "type": "resource1",
            },
            "permissions": ["write:write"],
        }
    }

    # Mock the OPA responses for both users
    mocked_api.post(
        f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/user_permissions",
        status=200,
        payload=opa_response1,
        # we mock only once because on the second request the cache will be hit
        # and we want to make sure it's working
        repeat=False,
    )

    # First request for user1 should hit the API
    response = client.post(
        "/user-permissions", json=query1.dict(), headers={"Authorization": f"Bearer {sidecar_config.API_KEY}"}
    )
    assert response.status_code == 200
    assert response.json() == expected_response1

    assert len(mocked_api.requests) == 1
    assert len(next(iter(mocked_api.requests.values()))) == 1
    # Second request for user1 should be served from cache
    response = client.post(
        "/user-permissions", json=query1.dict(), headers={"Authorization": f"Bearer {sidecar_config.API_KEY}"}
    )
    assert response.status_code == 200
    assert response.json() == expected_response1

    assert len(mocked_api.requests) == 1
    assert len(next(iter(mocked_api.requests.values()))) == 1

    # Clear the mock and set up response for user2
    mocked_api.post(
        f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/user_permissions",
        status=200,
        payload=opa_response2,
        # we mock only once because on the second request the cache will be hit
        # and we want to make sure it's working
        repeat=False,
    )

    # First request for user2 should hit the API
    response = client.post(
        "/user-permissions", json=query2.dict(), headers={"Authorization": f"Bearer {sidecar_config.API_KEY}"}
    )
    assert response.status_code == 200
    assert response.json() == expected_response2
    assert len(mocked_api.requests) == 1
    assert len(next(iter(mocked_api.requests.values()))) == 2

    # Second request for user2 should be served from cache
    response = client.post(
        "/user-permissions", json=query2.dict(), headers={"Authorization": f"Bearer {sidecar_config.API_KEY}"}
    )
    assert response.status_code == 200
    assert response.json() == expected_response2
    assert len(mocked_api.requests) == 1
    assert len(next(iter(mocked_api.requests.values()))) == 2


@pytest.mark.asyncio
async def test_user_permissions_cache_no_store(mocked_api: aioresponses, client_with_cache: TestClient):
    """Test that Cache-Control: no-store header prevents caching"""
    await FastAPICache.clear()
    client = client_with_cache
    query = UserPermissionsQuery(user=User(key="test_user"), resource_types=["resource1"])

    opa_response = {
        "result": {
            "permissions": {
                "test_user": {
                    "resource": {
                        "key": "resource_x",
                        "attributes": {},
                        "type": "resource1",
                    },
                    "permissions": ["read:read"],
                }
            }
        }
    }

    expected_response = {
        "test_user": {
            "resource": {
                "key": "resource_x",
                "attributes": {},
                "type": "resource1",
            },
            "permissions": ["read:read"],
        }
    }

    # Mock the OPA response
    mocked_api.post(
        f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/user_permissions",
        status=200,
        payload=opa_response,
        repeat=True,  # Need to repeat since cache should be bypassed
    )

    # First request with no-store header
    response = client.post(
        "/user-permissions",
        json=query.dict(),
        headers={"Authorization": f"Bearer {sidecar_config.API_KEY}", "Cache-Control": "no-store"},
    )
    assert response.status_code == 200
    assert response.json() == expected_response

    # Second request with no-store header should also hit the API
    response = client.post(
        "/user-permissions",
        json=query.dict(),
        headers={
            "Authorization": f"Bearer {sidecar_config.API_KEY}",
        },
    )
    assert response.status_code == 200
    assert response.json() == expected_response

    # Verify that both requests hit the API
    assert len(mocked_api.requests) == 1
    assert len(next(iter(mocked_api.requests.values()))) == 2


@pytest.mark.asyncio
async def test_user_permissions_cache_no_cache(mocked_api: aioresponses, client_with_cache: TestClient):
    await FastAPICache.clear()
    """Test that Cache-Control: no-cache header forces revalidation"""
    client = client_with_cache

    query = UserPermissionsQuery(user=User(key="test_user"), resource_types=["resource1"])

    opa_response = {
        "result": {
            "permissions": {
                "test_user": {
                    "resource": {
                        "key": "resource_x",
                        "attributes": {},
                        "type": "resource1",
                    },
                    "permissions": ["read:read"],
                }
            }
        }
    }

    expected_response = {
        "test_user": {
            "resource": {
                "key": "resource_x",
                "attributes": {},
                "type": "resource1",
            },
            "permissions": ["read:read"],
        }
    }

    # Mock the OPA response
    mocked_api.post(
        f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/user_permissions",
        status=200,
        payload=opa_response,
        repeat=True,  # Need to repeat since cache should be revalidated
    )

    # First request with no-cache header
    response = client.post(
        "/user-permissions",
        json=query.dict(),
        headers={
            "Authorization": f"Bearer {sidecar_config.API_KEY}",
        },
    )
    assert response.status_code == 200
    assert response.json() == expected_response

    # Verify that both requests hit the API
    assert len(mocked_api.requests) == 1
    assert len(next(iter(mocked_api.requests.values()))) == 1

    # First request with no-cache header
    response = client.post(
        "/user-permissions",
        json=query.dict(),
        headers={
            "Authorization": f"Bearer {sidecar_config.API_KEY}",
        },
    )
    assert response.status_code == 200
    assert response.json() == expected_response

    # Verify that both requests hit the API
    assert len(mocked_api.requests) == 1
    assert len(next(iter(mocked_api.requests.values()))) == 1

    # Second request with no-cache header should revalidate
    response = client.post(
        "/user-permissions",
        json=query.dict(),
        headers={"Authorization": f"Bearer {sidecar_config.API_KEY}", "Cache-Control": "no-cache"},
    )
    assert response.status_code == 200
    assert response.json() == expected_response

    # Verify that both requests hit the API
    assert len(mocked_api.requests) == 1
    assert len(next(iter(mocked_api.requests.values()))) == 2
