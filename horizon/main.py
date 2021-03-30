import requests

from horizon.config import OPENAPI_TAGS_METADATA
from fastapi import FastAPI

from opal_common.logger import logger
from opal_client.client import OpalClient

from horizon.proxy.api import router as proxy_router, sync_get_from_backend
from horizon.enforcer.api import init_enforcer_api_router
from horizon.local.api import init_local_cache_api_router
from horizon.config import BACKEND_SERVICE_URL, DATA_TOPICS_ROUTE, CLIENT_TOKEN


class AuthorizonSidecar:
    def __init__(
        self,
        backend_url: str = BACKEND_SERVICE_URL,
        backend_access_token: str = CLIENT_TOKEN,
        data_topics_route: str = DATA_TOPICS_ROUTE,
    ):
        self._backend_url = backend_url
        self._token = backend_access_token
        data_topics = self._fetch_data_topics(data_topics_route=data_topics_route)
        if not data_topics:
            logger.warning("reverting to default data topics")
            data_topics = None

        self._opal = OpalClient(data_topics=data_topics)

        # use opal client app and add sidecar routes on top
        app: FastAPI = self._opal.app
        self._override_app_metadata(app)
        self._configure_api_routes(app)

        self._app: FastAPI = app

    def _override_app_metadata(self, app: FastAPI):
        app.title = "Authorizon Sidecar"
        app.description = "This sidecar wraps Open Policy Agent (OPA) with a higher-level API intended for fine grained " + \
            "application-level authorization. The sidecar automatically handles pulling policy updates in real-time " + \
            "from a centrally managed cloud-service (api.authorizon.com)."
        app.version = "0.2.0"
        app.openapi_tags = OPENAPI_TAGS_METADATA
        return app

    def _configure_api_routes(self, app: FastAPI):
        """
        mounts the api routes on the app object
        """
        # Init api routers with required dependencies
        enforcer_router = init_enforcer_api_router(policy_store=self._opal.policy_store)
        local_router = init_local_cache_api_router(policy_store=self._opal.policy_store)

        # include the api routes
        app.include_router(enforcer_router, tags=["Authorization API"])
        app.include_router(local_router, prefix="/local", tags=["Local Queries"])
        app.include_router(proxy_router, tags=["Cloud API Proxy"])

    def _fetch_data_topics(self, data_topics_route: str):
        logger.info("fetching data topics from backend: {url}", url=f"{self._backend_url}/{data_topics_route}")
        try:
            response = sync_get_from_backend(backend_url=self._backend_url, path=data_topics_route, token=self._token)
            topics = response.get("topics", [])
            logger.info("received data topics: {topics}", topics=topics)
            return topics
        except requests.RequestException as exc:
            logger.exception("got exception while fetching data topics: {exc}", exc=exc)

    @property
    def app(self):
        return self._app


# expose app for Uvicorn
sidecar = AuthorizonSidecar()
app = sidecar.app