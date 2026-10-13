"""The PDP keeps request credentials out of aiohttp error reprs (horizon/aiohttp_redaction.py).

opal-client 0.9.6 logs repr() of the aiohttp errors its policy fetcher hits (policy/fetcher.py, once
per attempt and once when the retries run out) and stores it as the policy transaction error
(policy/updater.py), which the policy store logs at ERROR and writes into OPA's health-check policy.
A ClientResponseError's repr embeds its RequestInfo, and with it every request header; a connector
error on a proxied TLS connection embeds the proxy's BasicAuth.

The end-to-end tests drive that OPAL code against a real local server, so the RequestInfo under test
is the one aiohttp's ClientRequest builds in production. aioresponses builds its own from the
caller's headers through the public constructor, so a test using it can pass while a real request
leaks.
"""

import json
import os
import ssl
from collections.abc import AsyncIterator, Iterator, Mapping
from importlib.resources import files
from typing import NamedTuple

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import test_utils, web
from loguru import logger
from multidict import CIMultiDict, CIMultiDictProxy
from opal_client.config import ConnRetryOptions, opal_client_config
from opal_client.policy.fetcher import PolicyFetcher
from opal_client.policy.updater import PolicyUpdater
from opal_client.policy_store.opa_client import OpaClient
from yarl import URL

# Importing the PDP is what installs the redaction: nothing in this module calls install().
import horizon.pdp  # noqa: F401
from horizon import aiohttp_redaction

TOKEN = "sentinel-opal-client-jwt-7f3a9c"
ATTEMPTS = 2

# Each makes opal-client's bundle fetch raise ContentTypeError: throw_if_bad_status_code calls
# .json() on the 502 and 409 bodies, and the fetcher itself calls it on the 200 one.
NON_JSON_RESPONSES = {
    "502-html": (502, "text/html", "<html>502 Bad Gateway</html>"),
    "409-text": (409, "text/plain", "policy branch could not be resolved"),
    "200-html": (200, "text/html", "<html>maintenance</html>"),
}


class OpalServer(NamedTuple):
    url: str
    status: int
    seen: list[str]  # the Authorization header of every request received


class CapturedLogs(NamedTuple):
    text: list[str]
    serialized: list[str]

    @property
    def records(self) -> list[dict]:
        return [json.loads(line)["record"] for line in self.serialized]

    @property
    def everything(self) -> str:
        return "".join(self.text + self.serialized)


def _all_subclasses(cls: type) -> list[type]:
    return [cls, *(sub for direct in cls.__subclasses__() for sub in _all_subclasses(direct))]


class _RaisingHeaders(Mapping[str, str]):
    """A mapping that fails on iteration, to prove the repr falls back instead of raising."""

    def __getitem__(self, key: str) -> str:
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("cannot iterate")

    def __len__(self) -> int:
        return 1

    def __repr__(self) -> str:
        return f"<{TOKEN}>"  # so a fallback to any other rendering of the headers leaks


@pytest.fixture(autouse=True)
def _fast_policy_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    # PolicyFetcher uses trust_env=True: keep a developer's proxy settings (a lowercase no_proxy beats
    # NO_PROXY) and ~/.netrc (it overwrites the Authorization header) away from 127.0.0.1.
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "*")
    monkeypatch.setenv("NETRC", os.devnull)
    monkeypatch.setattr(
        opal_client_config, "POLICY_UPDATER_CONN_RETRY", ConnRetryOptions(wait_time=0, attempts=ATTEMPTS)
    )


@pytest.fixture
def logs() -> Iterator[CapturedLogs]:
    """A text sink that also renders extra, and a serialize=True sink like the central log one.

    Both run with diagnose=False like the image (OPAL_LOG_DIAGNOSE=false): with it on, a logged
    traceback dumps the test's own locals, and opal_server.seen holds the token.
    """
    captured = CapturedLogs(text=[], serialized=[])
    sinks = [
        logger.add(
            captured.text.append, level="DEBUG", colorize=False, format="{level} {message} {extra}", diagnose=False
        ),
        logger.add(captured.serialized.append, level="DEBUG", serialize=True, diagnose=False),
    ]
    yield captured
    for sink in sinks:
        logger.remove(sink)


@pytest_asyncio.fixture(params=list(NON_JSON_RESPONSES.values()), ids=list(NON_JSON_RESPONSES))
async def opal_server(request: pytest.FixtureRequest) -> AsyncIterator[OpalServer]:
    """A real server answering every request with a non-JSON body."""
    status, content_type, body = request.param
    seen: list[str] = []

    async def respond(incoming: web.Request) -> web.Response:
        seen.append(incoming.headers.get("Authorization", ""))
        return web.Response(status=status, text=body, content_type=content_type)

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", respond)
    async with test_utils.TestServer(app, host="127.0.0.1") as server:
        yield OpalServer(str(server.make_url("")).rstrip("/"), status, seen)


def test_importing_the_pdp_installs_the_redaction() -> None:
    assert vars(aiohttp.RequestInfo).get("__repr__") is aiohttp_redaction.redacted_request_info_repr
    assert vars(aiohttp.BasicAuth).get("__repr__") is aiohttp_redaction.redacted_basic_auth_repr


def test_aiohttp_shape_guard() -> None:
    """Fails when an aiohttp upgrade changes what the redaction relies on: re-review it, then update this."""
    assert [cls.__name__ for cls in aiohttp.RequestInfo.__mro__] == ["RequestInfo", "_RequestInfo", "tuple", "object"]
    assert aiohttp.RequestInfo._fields == ("url", "method", "headers", "real_url")
    assert aiohttp.BasicAuth._fields == ("login", "password", "encoding")


@pytest.mark.parametrize("error_type", _all_subclasses(aiohttp.ClientResponseError), ids=lambda t: t.__name__)
def test_client_response_errors_mask_credentials(error_type: type[aiohttp.ClientResponseError]) -> None:
    headers = {
        "Host": "opal",
        "Authorization": f"Bearer {TOKEN}",
        "X-Api-Key": TOKEN,
        "Cookie": f"s={TOKEN}; theme=dark",  # only a known auth scheme may stay in front of the mask
        "X-Custom": TOKEN,  # an allowlist, not a denylist: data-source configs can add any name
    }
    url = URL("https://opal.example/policy?path=.")
    info = aiohttp.RequestInfo(url, "GET", CIMultiDictProxy(CIMultiDict(headers)), url)
    error = error_type(info, (), status=502, message="Bad Gateway")

    # repr() is what OPAL logs; str(args) and str(info) reach logs through other formatting paths.
    assert TOKEN not in f"{error!r} {error} {error.args} {info}"
    # Header names, safe values, the auth scheme, the URL and the status all stay readable.
    rendered = repr(error)
    masked = "'Host': 'opal', 'Authorization': 'Bearer ***', 'X-Api-Key': '***', 'Cookie': '***', 'X-Custom': '***'"
    assert masked in rendered
    assert "url=URL('https://opal.example/policy?path=.')" in rendered
    assert "status=502" in rendered


def test_proxy_credentials_are_masked_in_connector_errors() -> None:
    """With an authenticated HTTPS_PROXY, a TLS failure through the tunnel raises a connector error whose
    args hold the request's ConnectionKey, proxy_auth included (aiohttp's _wrap_existing_connection)."""
    from aiohttp.client_reqrep import ConnectionKey  # noqa: PLC0415 - internal; a rename fails only this test

    assert "proxy_auth" in ConnectionKey._fields
    proxy_auth = aiohttp.BasicAuth("proxy-user", TOKEN)
    key = ConnectionKey(
        host="opal.example",
        port=443,
        is_ssl=True,
        ssl=True,
        proxy=URL("http://proxy.example:3128"),
        proxy_auth=proxy_auth,
        proxy_headers_hash=None,
    )
    error = aiohttp.ClientConnectorCertificateError(key, ssl.SSLCertVerificationError("certificate verify failed"))

    assert TOKEN not in f"{error!r} {error} {error.args} {proxy_auth}"
    assert "BasicAuth(login='proxy-user', password='***', encoding='latin1')" in repr(error)


@pytest.mark.parametrize(
    "headers",
    [
        None,
        {},
        {"Authorization": TOKEN},
        {b"Authorization": TOKEN.encode()},
        [("Authorization", f"Bearer {TOKEN}")],
        f"Authorization: Bearer {TOKEN}",
        _RaisingHeaders(),
    ],
    ids=["none", "empty", "plain-dict", "bytes", "pairs", "string", "raising-mapping"],
)
def test_odd_headers_neither_raise_nor_leak(headers: object) -> None:
    """OPAL calls repr() inside its except blocks, where an exception would replace the error it reports.
    Headers that are not a mapping cannot be masked value by value, so they are masked whole."""
    info = aiohttp.RequestInfo(URL("http://opal.example/"), "GET", headers)  # ty: ignore[invalid-argument-type]  # odd input on purpose

    rendered = repr(info)

    assert rendered.startswith("RequestInfo(")
    assert TOKEN not in rendered


@pytest.mark.asyncio
async def test_policy_fetch_failure_logs_carry_no_token(opal_server: OpalServer, logs: CapturedLogs) -> None:
    fetcher = PolicyFetcher(backend_url=opal_server.url, token=TOKEN)

    with pytest.raises(aiohttp.ContentTypeError):
        await fetcher.fetch_policy_bundle()

    assert opal_server.seen == [f"Bearer {TOKEN}"] * ATTEMPTS  # the token went out, so it could have been logged
    per_attempt = [r for r in logs.records if r["message"].startswith("server connection error: ")]
    final = [r for r in logs.records if r["message"].startswith("Failed all attempts to fetch bundle")]
    assert len(per_attempt) == ATTEMPTS
    assert len(final) == 1
    for record in [*per_attempt, *final]:
        # What an operator needs to debug the failure is still there.
        for needed in (
            "ContentTypeError(",
            f"status={opal_server.status}",
            fetcher.policy_endpoint_url,
            "'Bearer ***'",
        ):
            assert needed in record["message"]
    assert TOKEN not in logs.everything


@pytest.mark.asyncio
async def test_policy_update_failure_keeps_token_out_of_logs_and_opa(
    opal_server: OpalServer, logs: CapturedLogs, monkeypatch: pytest.MonkeyPatch
) -> None:
    # PolicyUpdater builds its fetcher from these, not from its own token argument.
    monkeypatch.setattr(opal_client_config, "SERVER_URL", opal_server.url)
    monkeypatch.setattr(opal_client_config, "CLIENT_TOKEN", TOKEN)
    # The OPA client as OPAL_OPA_HEALTH_CHECK_POLICY_ENABLED sets it up, with its writes to OPA
    # captured instead of sent.
    store = OpaClient(opa_server_url="http://127.0.0.1:9")
    written: list[str] = []

    async def capture_policy(**kwargs: str) -> None:
        written.append(kwargs["policy_code"])

    monkeypatch.setattr(store, "set_policy", capture_policy)
    template = (files("opal_client") / opal_client_config.OPA_HEALTH_CHECK_POLICY_PATH).read_text()
    await store.init_healthcheck_policy("opal_healthcheck", template)

    await PolicyUpdater(policy_store=store).update_policy(directories=["."], force_full_update=True)

    assert opal_server.seen == [f"Bearer {TOKEN}"] * ATTEMPTS  # the token went out, so it could have been logged
    errors = [r for r in logs.records if r["level"]["name"] == "ERROR"]
    assert [r["function"] for r in errors] == ["end_transcation"]
    # The failure reached the ERROR log and the health-check policy, so a leak there would show.
    assert "ContentTypeError(" in errors[0]["message"]
    assert "ContentTypeError(" in written[-1]
    assert TOKEN not in logs.everything + "".join(written)


@pytest.mark.asyncio
async def test_canary_unredacted_repr_leaks(
    opal_server: OpalServer, logs: CapturedLogs, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shows the tests above can fail. If this one fails after an OPAL or aiohttp upgrade, the leak is
    gone upstream: re-evaluate whether horizon/aiohttp_redaction.py is still needed."""
    native_repr = aiohttp.RequestInfo.__mro__[1].__repr__  # the NamedTuple base's: aiohttp's own
    monkeypatch.setattr(aiohttp.RequestInfo, "__repr__", native_repr)

    with pytest.raises(aiohttp.ContentTypeError):
        await PolicyFetcher(backend_url=opal_server.url, token=TOKEN).fetch_policy_bundle()

    assert TOKEN in "".join(logs.text)
    assert TOKEN in "".join(logs.serialized)
