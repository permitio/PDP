import requests
from opal_common.logger import logger
from tenacity import retry, retry_if_not_exception_type, stop, wait

from horizon.config import MOCK_API_KEY, ApiKeyLevel, sidecar_config
from horizon.startup.blocking_request import BlockingRequest
from horizon.startup.exceptions import ApiKeyError, NoRetryError
from horizon.system.consts import GUNICORN_EXIT_APP

DEFAULT_RETRY_CONFIG = {
    "retry": retry_if_not_exception_type(NoRetryError),
    "wait": wait.wait_random_exponential(max=10),
    "stop": stop.stop_after_attempt(10),
    "reraise": True,
}


class EnvApiKeyFetcher:
    def __init__(
        self,
        backend_url: str = sidecar_config.CONTROL_PLANE,
        timeout: float = sidecar_config.CONTROL_PLANE_TIMEOUT,
        retry_config=None,
    ):
        self._backend_url = backend_url
        self._timeout = timeout
        self._retry_config = retry_config or DEFAULT_RETRY_CONFIG
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
                raise ApiKeyError(
                    "PDP_PROJECT_API_KEY is set, but PDP_ACTIVE_ENV is not. Please set it with Environment ID or Key."
                )
            return ApiKeyLevel.PROJECT

        if sidecar_config.ORG_API_KEY:
            if not sidecar_config.ACTIVE_ENV or not sidecar_config.ACTIVE_PROJECT:
                raise ApiKeyError(
                    "PDP_ORG_API_KEY is set, but PDP_ACTIVE_ENV or PDP_ACTIVE_PROJECT are not. "
                    "Please set them with Environment ID/Key and Project ID/Key."
                )
            return ApiKeyLevel.ORGANIZATION

        raise ApiKeyError("No API key specified. Please specify one with the PDP_API_KEY environment variable.")

    def get_env_api_key_by_level(self) -> str:
        api_key_level = self.api_key_level
        api_key = sidecar_config.ORG_API_KEY
        active_project_id = sidecar_config.ACTIVE_PROJECT
        active_env_id = sidecar_config.ACTIVE_ENV

        if api_key_level == ApiKeyLevel.ENVIRONMENT:
            return sidecar_config.API_KEY
        if api_key_level == ApiKeyLevel.PROJECT:
            # A project key carries its own project: the control plane reports it in the key's
            # scope, so PDP_ACTIVE_PROJECT and PDP_ORG_API_KEY play no part here.
            api_key = sidecar_config.PROJECT_API_KEY
            scope = self.fetch_scope(api_key)
            active_project_id = scope.get("project_id") if scope else None
            if not active_project_id:
                raise ApiKeyError(
                    f"PDP_PROJECT_API_KEY is set, but {self.scope_url} returned no project_id for it. "
                    "Check that PDP_PROJECT_API_KEY is a project-level API key and that the control plane "
                    "is reachable."
                )
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
                timeout=self._timeout,
            ).get(url=api_key_url)
        )
        try:
            secret = fetch_with_retry().get("secret")
        except requests.RequestException as e:
            logger.warning(f"Failed to get Environment API Key: {e}")
            raise
        if secret is None:
            raise ApiKeyError(f"No secret found in the Environment API Key response from {api_key_url}.")
        return secret

    @property
    def scope_url(self) -> str:
        return f"{self._backend_url}/v2/api-key/scope"

    def fetch_scope(self, api_key: str) -> dict | None:
        """
        fetches the provided Project/Organization Scope.
        """
        logger.info("Fetching Scope from control plane: {url}", url=self.scope_url)
        fetch_with_retry = retry(**self._retry_config)(
            lambda: BlockingRequest(
                token=api_key,
                timeout=self._timeout,
            ).get(url=self.scope_url)
        )
        try:
            return fetch_with_retry()
        except requests.RequestException as e:
            logger.warning(f"Failed to get the API Key's scope from {self.scope_url}: {e}")
            return None


_env_api_key: str | None = None


def get_env_api_key() -> str:
    global _env_api_key  # noqa: PLW0603 - fetched from the control plane once per process
    if not _env_api_key:
        try:
            _env_api_key = EnvApiKeyFetcher().get_env_api_key_by_level()
        except Exception as e:
            # The type goes in too: some exceptions carry no message at all.
            logger.error(f"Failed to get Environment API Key: {type(e).__name__}: {e}")
            raise SystemExit(GUNICORN_EXIT_APP) from e
    return _env_api_key
