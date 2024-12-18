import requests
from opal_common.logger import logger
from tenacity import retry, retry_if_not_exception_type, stop, wait

from horizon.config import MOCK_API_KEY, ApiKeyLevel, sidecar_config
from horizon.startup.blocking_request import BlockingRequest
from horizon.startup.exceptions import NoRetryException
from horizon.system.consts import GUNICORN_EXIT_APP


class EnvApiKeyFetcher:
    DEFAULT_RETRY_CONFIG = {
        "retry": retry_if_not_exception_type(NoRetryException),
        "wait": wait.wait_random_exponential(max=10),
        "stop": stop.stop_after_attempt(10),
        "reraise": True,
    }

    def __init__(
        self,
        backend_url: str = sidecar_config.CONTROL_PLANE,
        retry_config=None,
    ):
        self._backend_url = backend_url
        self._retry_config = retry_config or self.DEFAULT_RETRY_CONFIG
        self.api_key_level = self._get_api_key_level()

    @staticmethod
    def _get_api_key_level() -> ApiKeyLevel:
        if sidecar_config.API_KEY != MOCK_API_KEY:
            if sidecar_config.ORG_API_KEY or sidecar_config.PROJECT_API_KEY:
                logger.warning(
                    "PDP_API_KEY is set, but PDP_ORG_API_KEY or PDP_PROJECT_API_KEY are also set and will be ignored."
                )
            return ApiKeyLevel.ENVIRONMENT

        if sidecar_config.PROJECT_API_KEY:
            if sidecar_config.ORG_API_KEY:
                logger.warning("PDP_PROJECT_API_KEY is set, but PDP_ORG_API_KEY is also set and will be ignored.")
            if not sidecar_config.ACTIVE_ENV:
                logger.error(
                    "PDP_PROJECT_API_KEY is set, but PDP_ACTIVE_ENV is not. Please set it with Environment ID or Key."
                )
                raise
            return ApiKeyLevel.PROJECT

        if sidecar_config.ORG_API_KEY:
            if not sidecar_config.ACTIVE_ENV or not sidecar_config.ACTIVE_PROJECT:
                logger.error(
                    "PDP_ORG_API_KEY is set, but PDP_ACTIVE_ENV or PDP_ACTIVE_PROJECT are not. Please set them with Environment ID/Key and Project ID/Key."
                )
                raise
            return ApiKeyLevel.ORGANIZATION

        logger.critical("No API key specified. Please specify one with the PDP_API_KEY environment variable.")
        raise

    def get_env_api_key_by_level(self) -> str:
        api_key_level = self.api_key_level
        api_key = sidecar_config.ORG_API_KEY
        active_project_id = sidecar_config.ACTIVE_PROJECT
        active_env_id = sidecar_config.ACTIVE_ENV

        if api_key_level == ApiKeyLevel.ENVIRONMENT:
            return sidecar_config.API_KEY
        if api_key_level == ApiKeyLevel.PROJECT:
            api_key = sidecar_config.PROJECT_API_KEY
            active_project_id = get_scope(sidecar_config.ORG_API_KEY).get("project_id")
            if not active_project_id:
                logger.error(
                    "PDP_PROJECT_API_KEY is set, but failed to get Project ID from provided Organization API Key."
                )
                raise
        return self._fetch_env_key(api_key, active_project_id, active_env_id)

    def _fetch_env_key(self, api_key: str, active_project_key: str, active_env_key: str) -> str:
        """
        fetches the active environment's API Key by identifying with the provided Project/Organization API Key.
        """
        api_key_url = f"{self._backend_url}/v2/api-key/{active_project_key}/{active_env_key}"
        logger.info("Fetching Environment API Key from control plane: {url}", url=api_key_url)
        fetch_with_retry = retry(**self._retry_config)(
            lambda: BlockingRequest(
                token=api_key,
            ).get(url=api_key_url)
        )
        try:
            secret = fetch_with_retry().get("secret")
            if secret is None:
                logger.error("No secret found in response from control plane")
                raise
            return secret

        except requests.RequestException as e:
            logger.warning(f"Failed to get Environment API Key: {e}")
            raise

    def fetch_scope(self, api_key: str) -> dict | None:
        """
        fetches the provided Project/Organization Scope.
        """
        api_key_url = f"{self._backend_url}/v2/api-key/scope"
        logger.info("Fetching Scope from control plane: {url}", url=api_key_url)
        fetch_with_retry = retry(**self._retry_config)(
            lambda: BlockingRequest(
                token=api_key,
            ).get(url=api_key_url)
        )
        try:
            return fetch_with_retry()
        except requests.RequestException:
            logger.warning("Failed to get scope from provided API Key")
            return


_env_api_key: str | None = None


def get_env_api_key() -> str:
    global _env_api_key
    if not _env_api_key:
        try:
            _env_api_key = EnvApiKeyFetcher().get_env_api_key_by_level()
        except Exception as e:
            logger.error(f"Failed to get Environment API Key: {e}")
            raise SystemExit(GUNICORN_EXIT_APP)
    return _env_api_key


def get_scope(api_key: str) -> dict:
    if scope := EnvApiKeyFetcher().fetch_scope(api_key) is None:
        logger.warning("Failed to get scope from provided API Key")
        raise
    return scope
