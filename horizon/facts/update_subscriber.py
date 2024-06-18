import asyncio
from collections import defaultdict
from uuid import uuid4

from fastapi_websocket_pubsub import ALL_TOPICS
from loguru import logger
from opal_client.data.updater import DataUpdater
from opal_common.schemas.data import DataUpdate


class DataUpdateSubscriber:
    def __init__(self, updater: DataUpdater):
        self._updater = updater
        self._notifier_id = uuid4().hex
        self._update_listeners: dict[str, asyncio.Event] = defaultdict(asyncio.Event)
        self._register_callbacks()

    def _register_callbacks(self) -> None:
        """
        Register the on_message callback for incoming messages from all topics subscribed by the PubSub client.
        """
        callbacks = self._updater._client._callbacks  # noqa
        if ALL_TOPICS not in callbacks:
            callbacks[ALL_TOPICS] = []
        callbacks[ALL_TOPICS].append(self._on_message)

    async def _on_message(self, topic: str = "", data: dict | None = None) -> None:
        """
        Callback for incoming messages from the PubSub client.
        """
        if data is None:
            logger.debug(f"Received message on topic {topic!r} without data")
            return

        update_id = data.get("id")
        if update_id is None:
            logger.debug(
                f"Received message on topic {topic!r} without an update ID: {data}"
            )
            return

        event = self._update_listeners.get(update_id)
        if event is not None:
            logger.info(
                f"Received message on topic {topic!r} with update ID {update_id!r}, resolving listener(s)"
            )
            event.set()
        else:
            logger.debug(
                f"Received message on topic {topic!r} with update ID {update_id!r}, but no listener found"
            )

    async def wait_for_message(
        self, update_id: str, timeout: float | None = None
    ) -> bool:
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
            return True
        except asyncio.TimeoutError:
            logger.warning(f"Timeout waiting for update id={update_id!r}")
            return False
        finally:
            self._update_listeners.pop(update_id, None)

    async def publish(self, data_update: DataUpdate) -> bool:
        await asyncio.sleep(0)  # allow other wait task to run before publishing
        topics = [topic for entry in data_update.entries for topic in entry.topics]
        logger.debug(
            f"Publishing data update with id={data_update.id!r} to topics {topics} as {self._notifier_id=}: {data_update}"
        )
        return await self._updater._client.publish(
            topics=topics,
            data=data_update.dict(),
            notifier_id=self._notifier_id,  # we fake a different notifier id to make the other side broadcast the message back to our main channel
            sync=False,  # sync=False means we don't wait for the other side to acknowledge the message, as it causes a deadlock because we fake a different notifier id
        )

    async def publish_and_wait(
        self, data_update: DataUpdate, timeout: float | None = None
    ) -> bool:
        """
        Publish a data update and wait for it to be received by the PubSub client.
        :param data_update: DataUpdate object to publish
        :param timeout: Wait timeout in seconds
        :return: True if the message was received, False if the timeout was reached or the message failed to publish
        """
        if timeout == 0:
            return await self.publish(data_update)

        # Start waiting before publishing, to avoid the message being received before we start waiting
        wait_task = asyncio.create_task(
            self.wait_for_message(data_update.id, timeout=timeout),
        )

        if not await self.publish(data_update):
            logger.warning("Failed to publish data entry. Aborting wait.")
            wait_task.cancel()
            return False

        return await wait_task
