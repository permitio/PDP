import requests
from typing import List

from opal_common.logger import logger
from tenacity import retry, wait, stop

from horizon.config import BACKEND_SERVICE_URL, DATA_TOPICS_ROUTE, CLIENT_TOKEN


def blocking_get_request(url: str, token: str, params=None):
    """
    utility method to send a *blocking* HTTP GET request and get the response back.
    """
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    response = requests.get(url, headers=headers, params=params)
    return response.json()


class DataTopicsFetcher:
    """
    Fetches the data topics opal client should subscribe to.

    Background:

    When the backend is updating a tenant-owned object, the update event is published
    to a topic named 'policy_data/{client_id}' where client_id belongs to the relevant
    project that belongs to said tenant.

    Since the sidecar should only subscribe to a single tenant (and project), it must
    know the proper topic name. Otherwise opal client will receive updates for all
    tenants (which is not secure).
    """
    DEFAULT_RETRY_CONFIG = {
        'wait': wait.wait_random_exponential(),
        'stop': stop.stop_after_attempt(10),
        'reraise': True,
    }

    def __init__(
        self,
        backend_url: str = BACKEND_SERVICE_URL,
        sidecar_access_token: str = CLIENT_TOKEN,
        data_topics_route: str = DATA_TOPICS_ROUTE,
        retry_config = None,
    ):
        """
        inits the DataTopicsFetcher.

        Args:
            backend_url (string, optional): url of the backend
            sidecar_access_token (string, optional): access token identifying this client (sidecar) to the backend
            data_topics_route (string, optional): api route to fetch relevant data topics.
        """
        self._url = f"{backend_url}/{data_topics_route}"
        self._token = sidecar_access_token
        self._retry_config = retry_config if retry_config is not None else self.DEFAULT_RETRY_CONFIG

    def fetch_topics(self) -> List[str]:
        """
        fetches the topics relevant to the sidecar by identifying with the sidecar access token.
        if failed to get topics, returns empty list of topics.
        """
        logger.info("fetching data topics from backend: {url}", url=self._url)
        fetch_with_retry = retry(**self._retry_config)(self._fetch_topics)
        try:
            return fetch_with_retry()
        except requests.RequestException:
            logger.warning("failed to get data topics")
            return []

    def _fetch_topics(self) -> List[str]:
        """
        Inner implementation of fetch_topics()

        NOTE: This method is using a *blocking* HTTP call.
        This is not ideal, but uvicorn does not currently allow running async code before
        the ASGI app is initialized. Unfortunately we must call the DataTopicsFetcher before
        initializing opal client, and this is done while initializing the sidecar ASGI app.

        However, this is ok because the DataTopicsFetcher runs *once* when the sidecar starts.
        """
        try:
            response = blocking_get_request(url=self._url, token=self._token)
            topics = response.get("topics", [])
            logger.info("received data topics: {topics}", topics=topics)
            return topics
        except requests.RequestException as exc:
            logger.error("got exception: {exc}", exc=exc)
            raise
