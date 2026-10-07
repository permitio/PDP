import asyncio
import json
import random
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import aiohttp
import httpx
import pytest
from aioresponses import aioresponses
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient
from loguru import logger
from opal_client.client import OpalClient
from opal_client.config import opal_client_config
from starlette import status

from horizon.config import sidecar_config
from horizon.enforcer.api import log_query_result, log_query_result_kong, stats_manager
from horizon.enforcer.schemas import (
    AuthorizationQuery,
    Resource,
    UrlAuthorizationQuery,
    User,
    UserPermissionsQuery,
    UserTenantsQuery,
)
from horizon.enforcer.schemas_kong import KongAuthorizationInput
from horizon.pdp import PermitPDP

if TYPE_CHECKING:
    from loguru import Record


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
async def pdp_api_client() -> AsyncIterator[TestClient]:
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

# The malformed-Authorization matrix, shared by every gated router's parametrized 401 test
# (this file, test_legacy_update_routes.py x2, test_opal_trigger_auth.py). Kept in one place
# so a new variant lands once instead of four times and cannot silently diverge between
# routers; the other modules pull it in by basename, same convention as MockPermitPDP.
#
# The two non-bearer entries carry the REAL API key, so they 401 *only* because HTTPBearer
# rejects the scheme (horizon/authentication.py:37-38). Neuter that scheme comparison and
# these are the entries that go red - the rest still 401 on an empty/wrong credential.
# Interpolated below `sidecar = MockPermitPDP()`, which is what sets sidecar_config.API_KEY.
MALFORMED_AUTH_HEADERS = [
    "garbage",  # no scheme/credential split at all
    "Bearer",  # scheme, no credential
    "Bearer ",  # scheme, empty credential
    "Bearer a b c",  # bearer scheme, credential containing spaces
    f"Basic {sidecar_config.API_KEY}",  # right secret, wrong scheme -> must still 401
    f"basic {sidecar_config.API_KEY}",  # ... and lowercasing the scheme must not help either
]

# Nested deeper than json.loads can decode: it raises RecursionError, which is not a ValueError. Kept
# under aiohttp's 128 KiB stream buffer, which a larger body mocked by aioresponses overflows.
DEEPLY_NESTED_OPA_BODY = '{"result": ' + "[" * 30_000 + "]" * 30_000 + "}"

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
@pytest.mark.parametrize("value", MALFORMED_AUTH_HEADERS)
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


@pytest.fixture
def kong_client(tmp_path, monkeypatch) -> TestClient:
    """A PDP app built with the Kong integration on, routing /resource1/* to resource1."""
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

    return TestClient(MockPermitPDP()._app)


def test_kong_endpoint_enabled_integration_allowed_flow(kong_client):
    response = kong_client.post("/kong", json=KONG_QUERY)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    with aioresponses() as m:
        m.post(
            f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/root",
            status=200,
            payload={"result": {"allow": True}},
        )
        response = kong_client.post(
            "/kong",
            headers={"authorization": f"Bearer {sidecar_config.API_KEY}"},
            json=KONG_QUERY,
        )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"result": True}


@pytest.mark.parametrize(
    "opa_response",
    [
        {"payload": {"result": []}},
        {"payload": {"result": None}},
        {"body": "not json"},
        {"body": DEEPLY_NESTED_OPA_BODY},
    ],
    ids=["result-is-a-list", "result-is-null", "body-is-not-json", "body-is-nested-too-deeply"],
)
def test_kong_endpoint_undecodable_opa_result_denies_with_200(kong_client, opa_response):
    """An OPA answer the decision log cannot read sends it to its fallback branch, which
    must log and return; the endpoint then denies instead of failing the request."""
    with aioresponses() as m:
        m.post(f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/root", status=200, **opa_response)
        response = kong_client.post(
            "/kong",
            headers={"authorization": f"Bearer {sidecar_config.API_KEY}"},
            json=KONG_QUERY,
        )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"result": False}


def test_kong_decision_log_names_a_missing_consumer_instead_of_raising():
    without_consumer = KongAuthorizationInput.parse_obj(
        {key: value for key, value in KONG_QUERY["input"].items() if key != "consumer"}
    )
    messages: list[str] = []
    sink_id = logger.add(lambda message: messages.append(message.record["message"]), level="INFO")
    try:
        log_query_result_kong(without_consumer, Response(content=b'{"result": {"allow": false}}'))
    finally:
        logger.remove(sink_id)

    assert any("(None, GET, /resource1/some-id)" in message for message in messages)


@pytest.fixture
def logged_records() -> Iterator[list["Record"]]:
    """Every loguru record at INFO or above emitted during the test."""
    records: list[Record] = []
    sink_id = logger.add(lambda message: records.append(message.record), level="INFO")
    yield records
    logger.remove(sink_id)


DECISION_QUERY = AuthorizationQuery(user=User(key="user1"), action="read", resource=Resource(type="doc"))


def test_decision_log_shows_an_allow_decision(logged_records: list["Record"]):
    log_query_result(DECISION_QUERY, Response(content=b'{"result": {"allow": true}}'))

    [record] = logged_records
    assert "is allowed = True" in record["message"]
    assert record["exception"] is None


@pytest.mark.parametrize(
    "body",
    [
        b'{"result": {"permissions": {"tenant:t1": {"permissions": ["doc:read"]}}}}',
        b'{"result": {"tenants": []}}',
        b'{"result": [1]}',
        b"not json",
        DEEPLY_NESTED_OPA_BODY.encode(),
    ],
    ids=["user-permissions", "user-tenants", "result-is-a-list", "body-is-not-json", "body-is-nested-too-deeply"],
)
def test_decision_log_logs_a_result_without_a_decision_raw_in_one_line(logged_records: list["Record"], body: bytes):
    """Routine for /user-permissions, /user-tenants and /authorized_users, whose results carry no
    "allow" or "allowed_tenants": one INFO line with the body, no warning and no traceback."""
    log_query_result(DECISION_QUERY, Response(content=body))

    [record] = logged_records
    assert record["level"].name == "INFO"
    assert record["message"] == "is allowed"
    assert record["extra"]["response_body"] == body.decode()
    assert record["exception"] is None


@pytest.mark.parametrize(
    "body",
    [b'{"result": {"allow": [1]}}', b'{"result": {"allowed_tenants": [1]}}'],
    ids=["bulk", "all-tenants"],
)
def test_decision_log_that_fails_to_format_a_decision_logs_the_traceback(logged_records: list["Record"], body: bytes):
    """A result with a decision that the log line cannot format points to a bug, so it is logged with
    its traceback, and the decision is still logged raw."""
    log_query_result(DECISION_QUERY, Response(content=body))

    warning, raw = logged_records
    assert warning["level"].name == "WARNING"
    assert warning["exception"] is not None
    assert warning["exception"].type is AttributeError
    assert raw["message"] == "is allowed"
    assert raw["extra"]["response_body"] == body.decode()


def test_allowed_with_an_opa_body_nested_too_deeply_to_decode_denies_with_200(monkeypatch):
    """The decision log must not fail the request on a body the endpoint's own fallback answers."""
    with pytest.raises(RecursionError):
        json.loads(DEEPLY_NESTED_OPA_BODY)
    monkeypatch.setattr(stats_manager, "_messages", asyncio.Queue())
    client = TestClient(sidecar._app)
    with aioresponses() as m:
        m.post(f"{opal_client_config.POLICY_STORE_URL}/v1/data/permit/root", status=200, body=DEEPLY_NESTED_OPA_BODY)
        response = client.post(
            "/allowed",
            headers={"authorization": f"Bearer {sidecar_config.API_KEY}"},
            json=DECISION_QUERY.dict(),
        )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"allow": False, "result": False}


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


@pytest.mark.parametrize("missing", ["permit-user-key", "permit-action", "permit-resource-type"])
def test_nginx_allowed_without_a_required_header_is_422_and_never_asks_opa(monkeypatch, missing: str):
    monkeypatch.setattr(stats_manager, "_messages", asyncio.Queue())
    headers = {
        "authorization": f"Bearer {sidecar_config.API_KEY}",
        "permit-user-key": "user1",
        "permit-action": "read",
        "permit-resource-type": "resource1",
    }
    del headers[missing]
    with aioresponses() as m:
        response = TestClient(sidecar._app).post("/nginx_allowed", headers=headers)
        assert not m.requests
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert [error["loc"] for error in response.json()["detail"]] == [["header", missing]]


DOCUMENTS_URL = "https://api.example.com/documents"
DOC_ID_RULE = {"url": DOCUMENTS_URL + "?id={doc_id}", "http_method": "get", "action": "read", "resource": "document"}
DOC_7_RULE_OVER_CATCH_ALL = [
    {"url": DOCUMENTS_URL + "?id=7", "http_method": "get", "action": "edit", "resource": "document", "priority": 10},
    {"url": DOCUMENTS_URL, "http_method": "get", "action": "read", "resource": "document", "priority": 1},
]


def _post_allowed_url(monkeypatch, url: str, mapping_rules: list[dict]) -> tuple[httpx.Response, list[dict]]:
    """POST /allowed_url for ``url`` with OPA holding ``mapping_rules`` and allowing every check.

    Returns the response and the input of each check the PDP asked OPA to decide.
    """
    monkeypatch.setattr(stats_manager, "_messages", asyncio.Queue())
    opa_data_url = f"{opal_client_config.POLICY_STORE_URL}/v1/data"
    query = UrlAuthorizationQuery(user=User(key="user1"), http_method="GET", url=url, tenant="default")
    with aioresponses() as m:
        m.post(f"{opa_data_url}/mapping_rules", payload={"result": {"all": mapping_rules}})
        m.post(f"{opa_data_url}/permit/root", payload={"result": {"allow": True}}, repeat=True)
        response = TestClient(sidecar._app).post(
            "/allowed_url", headers={"authorization": f"Bearer {sidecar_config.API_KEY}"}, json=query.dict()
        )
    checks = [
        json.loads(call.kwargs["data"])["input"]
        for (_, requested_url), calls in m.requests.items()
        if requested_url.path.endswith("/permit/root")
        for call in calls
    ]
    return response, checks


@pytest.mark.parametrize("query_string", ["?id=7", "?id=7&id=7"], ids=["single", "repeated-same-value"])
def test_allowed_url_checks_the_value_of_the_query_parameter_the_rule_reads(monkeypatch, query_string: str):
    response, checks = _post_allowed_url(monkeypatch, DOCUMENTS_URL + query_string, [DOC_ID_RULE])

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["allow"] is True
    (check,) = checks
    assert check["resource"]["attributes"] == {"doc_id": "7"}


@pytest.mark.parametrize("query_string", ["?id=7&id=8", "?id=8&id=7"], ids=["rule-value-first", "rule-value-last"])
@pytest.mark.parametrize(
    "mapping_rules", [[DOC_ID_RULE], DOC_7_RULE_OVER_CATCH_ALL], ids=["attribute-rule", "literal-rule-over-catch-all"]
)
def test_allowed_url_with_conflicting_values_for_a_rule_query_parameter_is_not_allowed(
    monkeypatch, query_string: str, mapping_rules: list[dict]
):
    """The app behind the URL may read either value, so no single check covers the request."""
    response, checks = _post_allowed_url(monkeypatch, DOCUMENTS_URL + query_string, mapping_rules)

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["allow"] is False
    assert body["result"] is False
    assert body["debug"] == {"reason": "Query parameter 'id' has more than one distinct value in the requested URL"}
    assert checks == []


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
    ("endpoint", "opa_endpoint", "query", "opa_response", "expected_response"),
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


@pytest.mark.parametrize(("endpoint", "opa_endpoint", "query", "opa_response", "expected_response"), ALLOWED_ENDPOINTS)
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
