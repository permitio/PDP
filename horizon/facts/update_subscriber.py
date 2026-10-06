import asyncio
from collections import defaultdict
from functools import wraps
from uuid import uuid4

from fastapi_websocket_pubsub.exceptions import PubSubClientInvalidStateException
from fastapi_websocket_rpc.rpc_channel import RpcChannelClosedException
from loguru import logger
from opal_client.data.updater import DataUpdater
from opal_common.schemas.data import DataUpdate, DataUpdateReport
from websockets.exceptions import ConnectionClosed

# What OPAL's pub/sub client raises from publish() when it has no live connection to the OPAL server:
# before its first connection, on a connection the server closed (the client keeps publishing on it
# until it reconnects), and when the connection closes before the server answers the publish.
_PUBSUB_CONNECTION_ERRORS = (PubSubClientInvalidStateException, ConnectionClosed, RpcChannelClosedException)


class DataUpdatePublishError(Exception):
    """A data update was not published, so nothing will report it arriving."""


class DataUpdateSubscriber:
    def __init__(self, updater: DataUpdater):
        self._updater = updater
        self._updater._should_send_reports = True
        self._notifier_id = uuid4().hex
        self._update_listeners: dict[str, asyncio.Event] = defaultdict(asyncio.Event)
        self._inject_subscriber()

    def _inject_subscriber(self):
        reporter = self._updater.callbacks_reporter
        reporter.report_update_results = self._reports_callback_decorator(reporter.report_update_results)

    def _reports_callback_decorator(self, func):
        @wraps(func)
        async def wrapper(report: DataUpdateReport, *args, **kwargs):
            if report.update_id is not None:
                self._resolve_listeners(report.update_id)
            else:
                logger.debug("Received report without update ID")
            return await func(report, *args, **kwargs)

        return wrapper

    def _resolve_listeners(self, update_id: str) -> None:
        event = self._update_listeners.get(update_id)
        if event is not None:
            logger.debug(f"Received acknowledgment for update ID {update_id!r}, resolving listener(s)")
            event.set()
        else:
            logger.debug(f"Received acknowledgment for update ID {update_id!r}, but no listener found")

    async def wait_for_message(self, update_id: str, timeout: float | None = None) -> bool:
        """
        Wait for a message with the given update ID to be received by the PubSub client.
        :param update_id: id of the update to wait for
        :param timeout: timeout in seconds
        :return: True if the message was received, False if the timeout was reached
        """
        logger.info(f"Waiting for update id={update_id!r}")
        event = self._update_listeners[update_id]
        try:
            await asyncio.wait_for(
                event.wait(),
                timeout=timeout,
            )
        except TimeoutError:
            logger.warning(f"Timeout waiting for update id={update_id!r}")
            return False
        else:
            return True
        finally:
            self._update_listeners.pop(update_id, None)

    async def publish(self, data_update: DataUpdate) -> None:
        """Publish a data update on the OPAL data updater's pub/sub client.

        Raises:
            DataUpdatePublishError: The data updater has no pub/sub client yet, or its client has no
                live connection to the OPAL server.
        """
        await asyncio.sleep(0)  # allow other wait task to run before publishing
        client = self._updater._client
        if client is None:
            raise DataUpdatePublishError(
                "the OPAL data updater has no pub/sub client yet (it creates one when it starts)"
            )
        topics = [topic for entry in data_update.entries for topic in entry.topics]
        logger.debug(
            f"Publishing data update with id={data_update.id!r} to topics {topics} as {self._notifier_id=}: "
            f"{data_update}"
        )
        try:
            await client.publish(
                topics=topics,
                data=data_update.dict(),
                notifier_id=self._notifier_id,  # we fake a different notifier id to make the other side broadcast
                # the message back to our main channel
                sync=False,  # sync=False means we don't wait for the other side to acknowledge the message,
                # as it causes a deadlock because we fake a different notifier id
            )
        except _PUBSUB_CONNECTION_ERRORS as e:
            raise DataUpdatePublishError(
                f"the OPAL pub/sub client has no live connection to the OPAL server ({type(e).__name__}: {e})"
            ) from e

    async def publish_and_wait(self, data_update: DataUpdate, timeout: float | None = None) -> bool:
        """Publish a data update and wait for the PDP's own data updater to report it.

        Args:
            data_update: The update to publish. It needs an id unless ``timeout`` is 0.
            timeout: Seconds to wait; 0 publishes without waiting, None waits without a limit.

        Returns:
            True if the update was reported (or, for a timeout of 0, published), False if the wait timed out.

        Raises:
            DataUpdatePublishError: The update was not published, so there is nothing to wait for.
            ValueError: ``data_update`` has no id to wait for.
        """
        if timeout == 0:
            await self.publish(data_update)
            return True
        if data_update.id is None:
            raise ValueError("publish_and_wait needs a DataUpdate with an id: the wait ends on the report for that id")

        # Start waiting before publishing, to avoid the message being received before we start waiting
        wait_task = asyncio.create_task(
            self.wait_for_message(data_update.id, timeout=timeout),
        )
        try:
            await self.publish(data_update)
        except BaseException:
            wait_task.cancel()  # nothing will report an update that was not published
            raise

        return await wait_task
