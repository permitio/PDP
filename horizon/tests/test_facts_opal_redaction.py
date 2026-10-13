"""A facts write forwarded to OPAL keeps the caller's key out of the logs and the callback reports.

horizon/facts/opal_forwarder.py builds the data update with the caller's Authorization header, so
OPAL fetches the written object with the caller's key. Here that fetch fails, and the test follows
the update the way the PDP handles it: DataUpdateSubscriber publishes it, the OPAL server (faked)
broadcasts it back, the data updater fetches the entry and reports the failure to the callbacks the
PDP registers - the control plane's default callback and PDP_DATA_UPDATE_CALLBACKS. The control
plane and the callback receivers are faked at the HTTP boundary. Every key is fake.
"""

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from aioresponses import aioresponses
from aioresponses.core import RequestCall
from loguru import logger
from opal_client.callbacks.register import CallbacksRegister
from opal_client.config import ConnRetryOptions, opal_client_config, opal_common_config
from opal_client.data.fetcher import DataFetcher
from opal_client.data.updater import DataUpdater
from opal_client.policy_store.mock_policy_store_client import MockPolicyStoreClient
from opal_common.logger import configure_logs
from opal_common.schemas.data import CallbackEntry, DataUpdate, UpdateCallback
from yarl import URL

from horizon.config import sidecar_config
from horizon.facts.opal_forwarder import (
    create_data_source_entry,
    create_data_update_entry,
    get_opal_data_base_url,
    get_opal_data_topic,
)
from horizon.facts.update_subscriber import DataUpdateSubscriber
from horizon.pdp import PermitPDP
from horizon.startup.schemas import RemoteConfig
from horizon.state import PersistentStateHandler

FAKE_CALLER_KEY = "permit_key_FakeCallerKey0123456789"
FAKE_CALLBACK_BEARER = "FakeControlPlaneCallbackBearer0123"
FAKE_OPAL_CLIENT_TOKEN = "fake-opal-client-token-0123456"
DELTAS_API = "http://control-plane.example.invalid/"
CONTROL_PLANE_CALLBACK = "https://control-plane.example.invalid/v2/pdps/me/opal_data_callback"
DATA_CALLBACK = "http://callback.example.invalid/data"

# OPAL's policy store transactions call datetime.utcnow(), which Python 3.12+ deprecates. It is
# OPAL's code (opal_client/policy_store/base_policy_store_client.py), not fixable here.
pytestmark = pytest.mark.filterwarnings(
    "ignore:datetime.datetime.utcnow:DeprecationWarning:opal_client.policy_store.base_policy_store_client"
)


class OpalServerEcho:
    """The OPAL server's part: it broadcasts a published update back to this PDP's data updater."""

    def __init__(self, updater: DataUpdater):
        self._updater = updater

    async def publish(self, *, data: dict, **_kwargs: Any) -> bool:
        await self._updater.trigger_data_update(DataUpdate.parse_obj(data))
        return True


@dataclass
class Logged:
    loguru: list[str] = field(default_factory=list)
    caplog: pytest.LogCaptureFixture | None = None

    @property
    def text(self) -> str:
        """loguru records as plain text and as serialized JSON, extras included, and OPAL's stdlib logs."""
        return "\n".join([*self.loguru, self.caplog.text if self.caplog else ""])


@pytest.fixture
def logged(caplog: pytest.LogCaptureFixture) -> Iterator[Logged]:
    """Everything logged during the test. diagnose is off, as in the image (OPAL_LOG_DIAGNOSE)."""
    captured = Logged(caplog=caplog)
    logger.add(captured.loguru.append, format="{message} | {extra}", level="DEBUG", diagnose=False)
    logger.add(captured.loguru.append, serialize=True, level="DEBUG", diagnose=False)
    caplog.set_level(logging.DEBUG, logger="opal")
    # Another test's OpalClient may have installed OPAL's record patcher, which masks some
    # credentials for every sink: without it, what is captured is what each call site emits.
    logger.configure(patcher=lambda _record: None)
    yield captured
    # Leave logging the way an OpalClient leaves it, as the other tests found it.
    configure_logs()


@dataclass
class FactsPath:
    updater: DataUpdater
    fetcher: DataFetcher
    subscriber: DataUpdateSubscriber
    register: CallbacksRegister
    pdp_state: PersistentStateHandler


@pytest.fixture
def facts_path(monkeypatch, tmp_path: Path) -> Iterator[FactsPath]:
    """OPAL's data updater wired as the PDP wires it, with one fetch attempt that times out fast."""
    remote_config = RemoteConfig(context={"org_id": "org", "project_id": "proj", "env_id": "env", "client_id": "pdp"})
    monkeypatch.setattr("horizon.startup.remote_config._remote_config", remote_config)
    monkeypatch.setattr(sidecar_config, "CONTROL_PLANE_PDP_DELTAS_API", DELTAS_API)
    monkeypatch.setattr(opal_client_config, "DATA_UPDATER_CONN_RETRY", ConnRetryOptions(wait_time=0, attempts=1))
    # A failed fetch reaches the data updater as a timeout of the fetch callback.
    monkeypatch.setattr(opal_common_config, "FETCHING_CALLBACK_TIMEOUT", 1)
    # Both are @cache'd off the remote config: start clean and leave nothing built from this fake.
    get_opal_data_base_url.cache_clear()
    get_opal_data_topic.cache_clear()

    # The callbacks the PDP registers: the control plane's default report callback (OpalClient
    # registers DEFAULT_UPDATE_CALLBACKS), then PDP_DATA_UPDATE_CALLBACKS.
    control_plane_callbacks = UpdateCallback.parse_obj(
        {
            "callbacks": [
                [
                    CONTROL_PLANE_CALLBACK,
                    {
                        "method": "post",
                        "headers": {
                            "content-type": "application/json",
                            "authorization": f"Bearer {FAKE_CALLBACK_BEARER}",
                        },
                        "process_data": False,
                    },
                ]
            ]
        }
    )
    register = CallbacksRegister(control_plane_callbacks.callbacks)
    monkeypatch.setattr(sidecar_config, "DATA_UPDATE_CALLBACKS", [CallbackEntry(url=DATA_CALLBACK)])
    PermitPDP._inject_extra_callbacks(SimpleNamespace(_opal=SimpleNamespace(_callbacks_register=register)))  # ty: ignore[invalid-argument-type]  # needs only _opal

    fetcher = DataFetcher()
    updater = DataUpdater(
        token=FAKE_OPAL_CLIENT_TOKEN,
        pubsub_url="ws://opal-server.invalid/ws",
        data_sources_config_url="http://opal-server.invalid/data/config",
        policy_store=MockPolicyStoreClient(),
        data_fetcher=fetcher,
        data_topics=[get_opal_data_topic()],
        callbacks_register=register,
    )
    pdp_state = PersistentStateHandler(str(tmp_path / "persistent_state.json"), "fake-env-api-key")
    monkeypatch.setattr(PersistentStateHandler, "_instance", pdp_state)
    updater.callbacks_reporter.set_user_data_handler(pdp_state.reporter_user_data_handler)
    subscriber = DataUpdateSubscriber(updater)
    monkeypatch.setattr(updater, "_client", OpalServerEcho(updater))

    yield FactsPath(updater=updater, fetcher=fetcher, subscriber=subscriber, register=register, pdp_state=pdp_state)

    get_opal_data_base_url.cache_clear()
    get_opal_data_topic.cache_clear()


@dataclass
class Forwarded:
    update: DataUpdate
    #: The GET OPAL sent to fetch the written object.
    fetch: RequestCall
    #: The POST each callback received, by URL.
    reports: dict[str, RequestCall]


def _requests(http: aioresponses, method: str, url: str) -> list[RequestCall]:
    return http.requests.get((method, URL(url)), [])


@pytest_asyncio.fixture
async def forwarded(monkeypatch, facts_path: FactsPath, logged: Logged) -> AsyncIterator[Forwarded]:  # noqa: ARG001 - captures the run
    """Publish the update the facts router forwards for a created user; its fetch fails with 502."""
    update_id = uuid4()
    entry = create_data_source_entry("users", str(uuid4()), "alice", f"Bearer {FAKE_CALLER_KEY}", update_id=update_id)
    update = create_data_update_entry([entry], update_id=update_id)
    reporter = facts_path.updater.callbacks_reporter
    # The report goes out in a background task; this tells when it has been sent to every callback.
    reported = asyncio.Event()
    report_update_results = reporter.report_update_results

    async def report_update_results_then_signal(*args: Any, **kwargs: Any) -> None:
        try:
            await report_update_results(*args, **kwargs)
        finally:
            reported.set()

    monkeypatch.setattr(reporter, "report_update_results", report_update_results_then_signal)
    callback_urls = (CONTROL_PLANE_CALLBACK, DATA_CALLBACK)
    with aioresponses() as http:
        http.get(entry.url, status=502, repeat=True)
        for url in callback_urls:
            http.post(url, status=204)
        await facts_path.fetcher.start()
        await reporter.start()
        try:
            assert await facts_path.subscriber.publish_and_wait(update, timeout=10)
            await asyncio.wait_for(reported.wait(), timeout=5)
        finally:
            await reporter.stop()
            await facts_path.fetcher.stop()
        yield Forwarded(
            update=update,
            fetch=_requests(http, "GET", entry.url)[0],
            reports={url: _requests(http, "POST", url)[0] for url in callback_urls},
        )


@pytest.mark.asyncio
async def test_a_failed_fetch_logs_no_caller_key(forwarded: Forwarded, logged: Logged):
    # The key was in play: OPAL fetched the written object with the caller's Authorization.
    assert forwarded.fetch.kwargs["headers"]["Authorization"] == f"Bearer {FAKE_CALLER_KEY}"

    assert "Failed to fetch data for entry" in logged.text
    assert FAKE_CALLER_KEY not in logged.text


@pytest.mark.asyncio
async def test_the_callback_reports_carry_no_entry_config_or_caller_key(forwarded: Forwarded, facts_path: FactsPath):
    for post in forwarded.reports.values():
        body = post.kwargs["data"]
        assert FAKE_CALLER_KEY not in body
        report = json.loads(body)
        assert report["update_id"] == forwarded.update.id
        assert report["user_data"] == {"pdp_instance_id": str(facts_path.pdp_state.get().pdp_instance_id)}
        [entry_report] = report["reports"]
        assert entry_report["fetched"] is False
        assert entry_report["entry"]["dst_path"] == forwarded.update.entries[0].dst_path
        assert "config" not in entry_report["entry"]
        assert "data" not in entry_report["entry"]
    # The control plane's callback still authenticates with its own bearer.
    control_plane_headers = forwarded.reports[CONTROL_PLANE_CALLBACK].kwargs["headers"]
    assert control_plane_headers["authorization"] == f"Bearer {FAKE_CALLBACK_BEARER}"


@pytest.mark.asyncio
@pytest.mark.usefixtures("forwarded")
async def test_reporting_leaves_the_registered_callback_configs_without_the_report(facts_path: FactsPath):
    # OPAL's GET /callbacks serves these configs, and PDP_DATA_UPDATE_CALLBACKS entries share one.
    assert [entry.config.data for entry in facts_path.register.all() if entry.config is not None] == [None, None]
