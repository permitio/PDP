"""DataUpdateSubscriber against a stand-in for OPAL's DataUpdater (the boundary it wraps)."""

import asyncio
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi_websocket_rpc.rpc_channel import RpcChannelClosedException
from opal_common.schemas.data import DataSourceEntry, DataUpdate
from websockets.exceptions import ConnectionClosed, ConnectionClosedError, ConnectionClosedOK
from websockets.frames import Close

from horizon.facts.update_subscriber import DataUpdatePublishError, DataUpdateSubscriber


def _subscriber(client: AsyncMock | None) -> DataUpdateSubscriber:
    """A subscriber over an updater whose pub/sub client is ``client`` (None before the updater starts)."""
    reporter = SimpleNamespace(report_update_results=AsyncMock())
    updater = SimpleNamespace(_should_send_reports=False, callbacks_reporter=reporter, _client=client)
    return DataUpdateSubscriber(updater)  # ty: ignore[invalid-argument-type]  # stand-in for OPAL's DataUpdater


def _update(update_id: str | None) -> DataUpdate:
    entry = DataSourceEntry(url="http://control-plane/facts/users/u1", dst_path="users/u1", topics=["pdp:data"])
    return DataUpdate(id=update_id, entries=[entry], reason="test")


@pytest.mark.asyncio
async def test_publish_sends_the_update_on_the_updaters_client():
    client = AsyncMock()
    client.publish.return_value = True
    subscriber = _subscriber(client)

    await subscriber.publish(_update("u-1"))

    call = client.publish.await_args
    assert call is not None
    assert call.kwargs["topics"] == ["pdp:data"]
    assert call.kwargs["data"]["id"] == "u-1"


@pytest.mark.asyncio
async def test_publish_before_the_updater_has_a_client_raises_a_publish_error():
    subscriber = _subscriber(client=None)

    with pytest.raises(DataUpdatePublishError, match="no pub/sub client"):
        await subscriber.publish(_update("u-1"))


async def _pending_waits() -> list[asyncio.Task]:
    """The tasks besides this test's own that are still running, after one turn of the event loop."""
    await asyncio.sleep(0)
    return [task for task in asyncio.all_tasks() if task is not asyncio.current_task() and not task.done()]


@pytest.mark.asyncio
async def test_publish_and_wait_raises_without_waiting_when_the_updater_has_no_client():
    """Not published is not a timeout: the caller hears why, and no wait is left behind."""
    subscriber = _subscriber(client=None)

    with pytest.raises(DataUpdatePublishError, match="no pub/sub client"):
        await subscriber.publish_and_wait(_update("u-1"), timeout=None)

    assert await _pending_waits() == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("dropped", "reason"),
    [
        pytest.param(
            ConnectionClosedError(Close(1012, ""), Close(1012, ""), rcvd_then_sent=True),
            "ConnectionClosedError: received 1012 (service restart); then sent 1012 (service restart)",
            id="closed-by-the-server",
        ),
        pytest.param(
            ConnectionClosedOK(Close(1000, ""), Close(1000, ""), rcvd_then_sent=False),
            "ConnectionClosedOK: sent 1000 (OK); then received 1000 (OK)",
            id="closed-by-the-pdp",
        ),
    ],
)
async def test_publish_and_wait_reports_a_dropped_pubsub_connection_as_unpublished_and_ends_the_wait(
    dropped: ConnectionClosed, reason: str
):
    """OPAL's client keeps a closed connection until it reconnects, and publishing on it raises. The
    server may have closed it, or the PDP itself: OPAL's DataUpdater.stop(), run by
    /connectivity/disable, disconnects the client but keeps it, so the next publish raises
    ConnectionClosedOK. A wait without a timeout for an update that was not published would never
    end, so it is cancelled, and the caller hears that the update was not published."""
    client = AsyncMock()
    client.publish.side_effect = dropped
    subscriber = _subscriber(client)

    with pytest.raises(DataUpdatePublishError, match=re.escape(reason)) as excinfo:
        await subscriber.publish_and_wait(_update("u-1"), timeout=None)

    assert excinfo.value.__cause__ is dropped
    assert await _pending_waits() == []


@pytest.mark.asyncio
async def test_publish_and_wait_reports_a_publish_the_server_did_not_confirm_as_possibly_published():
    """The update went out, but the connection closed before the OPAL server's reply. With sync=False
    the server starts the broadcast before it replies, so other subscribers may have the update: the
    caller hears that it may have been published, not that there was no connection, and the wait is
    cancelled."""
    unconfirmed = RpcChannelClosedException("Channel Closed before RPC response for c-1 could be received")
    client = AsyncMock()
    client.publish.side_effect = unconfirmed
    subscriber = _subscriber(client)

    with pytest.raises(DataUpdatePublishError) as excinfo:
        await subscriber.publish_and_wait(_update("u-1"), timeout=None)

    message = str(excinfo.value)
    assert "closed before the server confirmed the publish, so the update may have been published" in message
    assert "RpcChannelClosedException: Channel Closed before RPC response for c-1" in message
    assert "no live connection" not in message
    assert excinfo.value.__cause__ is unconfirmed
    assert await _pending_waits() == []


@pytest.mark.asyncio
async def test_publish_and_wait_passes_on_any_other_publish_failure_and_ends_the_wait():
    """Only a missing or closed connection leaves a publish unconfirmed; anything else is a bug the
    caller must see."""
    client = AsyncMock()
    client.publish.side_effect = TypeError("Object of type Decimal is not JSON serializable")
    subscriber = _subscriber(client)

    with pytest.raises(TypeError, match="not JSON serializable"):
        await subscriber.publish_and_wait(_update("u-1"), timeout=None)

    assert await _pending_waits() == []


@pytest.mark.asyncio
async def test_publish_without_a_wait_reports_the_update_as_published():
    client = AsyncMock()
    subscriber = _subscriber(client)

    assert await subscriber.publish_and_wait(_update(None), timeout=0) is True

    client.publish.assert_awaited_once()


@pytest.mark.asyncio
async def test_publish_and_wait_refuses_an_update_without_an_id_before_publishing():
    client = AsyncMock()
    subscriber = _subscriber(client)

    with pytest.raises(ValueError, match="needs a DataUpdate with an id"):
        await subscriber.publish_and_wait(_update(None), timeout=0.05)

    client.publish.assert_not_awaited()
