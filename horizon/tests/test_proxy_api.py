"""Query parameters the /cloud and /sdk proxy routes forward to the backend."""

import re

import pytest
from aioresponses import aioresponses
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette import status
from yarl import URL

from horizon.config import sidecar_config
from horizon.proxy.api import router

CLOUD_BACKEND = "http://backend.test/cloud-api"
LEGACY_BACKEND = "http://backend.test/legacy-api"
AUTH = {"Authorization": "Bearer proxy-test-token"}


@pytest.fixture
def proxy_client(monkeypatch) -> TestClient:
    """The proxy routes alone, pointed at a backend that aioresponses answers."""
    monkeypatch.setattr(sidecar_config, "BACKEND_SERVICE_URL", CLOUD_BACKEND)
    monkeypatch.setattr(sidecar_config, "BACKEND_LEGACY_URL", LEGACY_BACKEND)
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


@pytest.mark.parametrize(("route", "backend"), [("/cloud", CLOUD_BACKEND), ("/sdk", LEGACY_BACKEND)])
@pytest.mark.parametrize(
    ("query_string", "expected"),
    [
        ("", []),
        ("?user=u1", [("user", "u1")]),
        (
            "?user=u2&tenant=t1&user=u1&search=b%26c&search=a",
            [("user", "u2"), ("tenant", "t1"), ("user", "u1"), ("search", "b&c"), ("search", "a")],
        ),
    ],
    ids=["none", "single", "repeated"],
)
def test_proxy_forwards_every_query_parameter_value_in_order(
    proxy_client: TestClient, route: str, backend: str, query_string: str, expected: list[tuple[str, str]]
):
    with aioresponses() as backend_mock:
        backend_mock.get(re.compile(rf"^{re.escape(backend)}/v2/role_assignments"), payload=[])

        response = proxy_client.get(f"{route}/v2/role_assignments{query_string}", headers=AUTH)

        assert response.status_code == status.HTTP_200_OK
        ((_, recorded_url), calls) = next(iter(backend_mock.requests.items()))
        # aioresponses records the URL with its query sorted, so it shows that no value was dropped.
        # aiohttp builds the query it sends from the params it was given, which show the order.
        assert sorted(recorded_url.query.items()) == sorted(expected)
        sent_query = URL(backend).with_query(calls[0].kwargs["params"]).query
        assert list(sent_query.items()) == expected
