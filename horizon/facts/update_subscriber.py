import asyncio

from loguru import logger
from opal_client.data.updater import DataUpdater
from opal_common.schemas.data import DataSourceEntry


class DataUpdateSubscriber:
    def __init__(self, updater: DataUpdater):
        self._updater = updater
        self._topic_events: dict[str, asyncio.Event] = {}

    @property
    def callbacks(self) -> dict[str, list[callable]]:
        # Callbacks registered for PubSub client by topics
        return self._updater._client._callbacks  # noqa

    async def _on_message(self, topic: str = "", data=None) -> None:
        if topic in self._topic_events:
            logger.debug(f"Resolving subscriber event for topic: {topic}")
            self._topic_events[topic].set()
        else:
            logger.info(f"No subscriber found for topic: {topic}")

    def _get_event(self, topic: str) -> asyncio.Event:
        if topic in self.callbacks:
            if topic not in self._topic_events:
                self._topic_events[topic] = asyncio.Event()

            # Injecting the callback directly into the PubSub client, because subscribing to the topic is not possible
            # after client is initialized. If the pubsub client does not already have callbacks for this topic, it is
            # no longer possible to subscribe to it.
            self.callbacks[topic].append(self._on_message)
            return self._topic_events[topic]
        else:
            raise Exception(f"PubSubClient is not subscribed to topic: {topic}")

    def _clear_event(self, topic: str) -> None:
        if topic in self.callbacks:
            self.callbacks[topic].remove(self._on_message)
        if topic in self._topic_events:
            self._topic_events.pop(topic)

    async def wait_for_message(self, topic: str, timeout: float | None = None) -> bool:
        logger.info(f"Waiting for message on topic: {topic}")
        event = self._get_event(topic)
        try:
            await asyncio.wait_for(
                event.wait(),
                timeout=timeout,
            )
            return True
        except asyncio.TimeoutError:
            logger.warning(f"Timeout waiting for message on topic: {topic}")
            return False
        finally:
            self._clear_event(topic)  # clear the event after it's set

    async def bulk_wait_for_messages(
        self, topics: list[str], timeout: float | None = None
    ) -> bool:
        return all(
            await asyncio.gather(
                *[self.wait_for_message(topic, timeout=timeout) for topic in topics]
            )
        )

    async def publish(self, data_entry: DataSourceEntry) -> bool:
        return await self._updater._client.publish(
            data_entry.topics, data=data_entry.dict()
        )

    async def publish_and_wait(
        self, data_entry: DataSourceEntry, timeout: float | None = None
    ) -> bool:
        # Start waiting before publishing, to avoid the message being received before we start waiting
        wait_task = asyncio.create_task(
            self.bulk_wait_for_messages(
                [
                    topic[: topic.find("/")]  # Trim extra path from topic
                    for topic in data_entry.topics
                ],
                timeout=timeout,
            )
        )

        if not await self.publish(data_entry):
            logger.warning("Failed to publish data entry. Aborting wait.")
            wait_task.cancel()
            return False

        if not await wait_task:
            return False

        return True
