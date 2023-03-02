from typing import Dict, Optional

import requests
from opal_common.logger import logger
from pydantic import ValidationError
from tenacity import retry, retry_if_not_exception_type, stop, wait

from horizon.config import sidecar_config
from horizon.startup.schemas import RemoteConfig
from horizon.state import PersistentStateHandler


class NoRetryException(Exception):
    ...


class InvalidPDPTokenException(NoRetryException):
    ...


class BlockingRequest:
    def __init__(self, token: Optional[str]):
        self._token = token

    def _headers(self) -> Dict[str, str]:
        if self._token is None:
            return {}
        return {"Authorization": f"Bearer {self._token}"}

    def get(self, url: str, params=None) -> dict:
        """
        utility method to send a *blocking* HTTP GET request and get the response back.
        """
        response = requests.get(url, headers=self._headers(), params=params)

        if response.status_code == 401:
            raise InvalidPDPTokenException()

        return response.json()

    def post(self, url: str, payload: dict = None, params=None) -> dict:
        """
        utility method to send a *blocking* HTTP POST request with a JSON payload and get the response back.
        """
        response = requests.post(
            url, json=payload, headers=self._headers(), params=params
        )

        if response.status_code == 401:
            raise InvalidPDPTokenException()

        return response.json()


class RemoteConfigFetcher:
    """
    Fetches sidecar configuration from Permit.io cloud (backend).

    The sidecar should give a seamless experience to Permit.io users,
    so they should not worry (or be aware) about OPAL and multiple config options.

    This config fetcher runs before the uvicorn app is running and before the asyncio
    loop is starting (no way around that) so the fetcher uses blocking HTTP requests.
    However this happens once when the sidecar loads, so it's a reasonable tradeoff.

    Main configuation items that must be fetched remotely:

    * OPAL client token - the client token is a JWT signed by the OPAL server and
    must have an `permit_client_id` claim.

    * Client data topics - When the backend is updating a organization-owned object,
    the update event is published to a topic named 'policy_data/{client_id}'
    where client_id belongs to the relevant project that belongs to said organization's pdp.
    Since the sidecar should only subscribe to a single organization (and project), it must
    know the proper topic name. Otherwise opal client will receive updates for all
    organizations (which is not secure).
    """

    DEFAULT_RETRY_CONFIG = {
        "retry": retry_if_not_exception_type(NoRetryException),
        "wait": wait.wait_random_exponential(max=10),
        "stop": stop.stop_after_attempt(10),
        "reraise": True,
    }

    def __init__(
        self,
        backend_url: str = sidecar_config.CONTROL_PLANE,
        sidecar_access_token: str = sidecar_config.API_KEY,
        remote_config_route: str = sidecar_config.REMOTE_CONFIG_ENDPOINT,
        retry_config=None,
    ):
        """
        inits the RemoteConfigFetcher.

        Args:
            backend_url (string, optional): url of the backend
            sidecar_access_token (string, optional): access token identifying this client (sidecar) to the backend
            remote_config_route (string, optional): api route to fetch sidecar config
        """
        self._url = f"{backend_url}{remote_config_route}"
        self._token = sidecar_access_token
        self._retry_config = (
            retry_config if retry_config is not None else self.DEFAULT_RETRY_CONFIG
        )

    def fetch_config(self) -> Optional[RemoteConfig]:
        """
        fetches the sidecar config by identifying with the sidecar access token.
        if failed to get config from backend, returns None.
        """
        logger.info("Fetching PDP config from control plane: {url}", url=self._url)
        fetch_with_retry = retry(**self._retry_config)(self._fetch_config)
        try:
            return fetch_with_retry()
        except requests.RequestException:
            logger.warning("Failed to get PDP config")
            return None

    def _fetch_config(self) -> RemoteConfig:
        """
        Inner implementation of fetch_config()

        NOTE: This method is using a *blocking* HTTP call.
        This is not ideal, but uvicorn does not currently allow running async code before
        the ASGI app is initialized. Unfortunately we must call the RemoteConfigFetcher before
        initializing opal client, and this is done while initializing the sidecar ASGI app.

        However, this is ok because the RemoteConfigFetcher runs *once* when the sidecar starts.
        """
        try:
            response = BlockingRequest(token=self._token).post(
                url=self._url, payload=PersistentStateHandler.build_state_payload_sync()
            )

            try:
                sidecar_config = RemoteConfig(**response)
                config_context = sidecar_config.dict(include={"context"}).get(
                    "context", {}
                )
                logger.info(
                    f"Received remote config with the following context: {config_context}"
                )
            except ValidationError as exc:
                logger.error(
                    "Got invalid config contents: {exc}", exc=exc, response=response
                )
                raise
            return sidecar_config
        except requests.RequestException as exc:
            logger.error("Got exception: {exc}", exc=exc)
            raise
