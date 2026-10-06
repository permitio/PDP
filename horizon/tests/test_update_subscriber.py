"""DataUpdateSubscriber against a stand-in for OPAL's DataUpdater (the boundary it wraps)."""

from collections.abc import Iterator
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest
from loguru import logger
from opal_common.schemas.data import DataSourceEntry, DataUpdate

from horizon.facts.update_subscriber import DataUpdateSubscriber

if TYPE_CHECKING:
    from loguru import Record


def _subscriber(client: AsyncMock | None) -> DataUpdateSubscriber:
    """A subscriber over an updater whose pub/sub client is ``client`` (None before the updater starts)."""
    reporter = SimpleNamespace(report_update_results=AsyncMock())
    updater = SimpleNamespace(_should_send_reports=False, callbacks_reporter=reporter, _client=client)
    return DataUpdateSubscriber(updater)  # ty: ignore[invalid-argument-type]  # stand-in for OPAL's DataUpdater


def _update(update_id: str | None) -> DataUpdate:
    entry = DataSourceEntry(url="http://control-plane/facts/users/u1", dst_path="users/u1", topics=["pdp:data"])
    return DataUpdate(id=update_id, entries=[entry], reason="test")


@pytest.fixture
def logged_warnings() -> Iterator[list["Record"]]:
    records: list[Record] = []
    sink_id = logger.add(lambda message: records.append(message.record), level="WARNING")
    yield records
    logger.remove(sink_id)


@pytest.mark.asyncio
async def test_publish_sends_the_update_on_the_updaters_client():
    client = AsyncMock()
    client.publish.return_value = True
    subscriber = _subscriber(client)

    assert await subscriber.publish(_update("u-1")) is True

    call = client.publish.await_args
    assert call is not None
    assert call.kwargs["topics"] == ["pdp:data"]
    assert call.kwargs["data"]["id"] == "u-1"


@pytest.mark.asyncio
async def test_publish_before_the_updater_has_a_client_fails_with_a_warning(logged_warnings: list["Record"]):
    subscriber = _subscriber(client=None)

    assert await subscriber.publish(_update("u-1")) is False

    assert any("no pub/sub client" in record["message"] for record in logged_warnings)


@pytest.mark.asyncio
async def test_publish_and_wait_refuses_an_update_without_an_id_before_publishing():
    client = AsyncMock()
    subscriber = _subscriber(client)

    with pytest.raises(ValueError, match="needs a DataUpdate with an id"):
        await subscriber.publish_and_wait(_update(None), timeout=0.05)

    client.publish.assert_not_awaited()
