from fastapi import FastAPI, status
from fastapi.responses import RedirectResponse

from opal_common.logger import logger
from opal_client.client import OpalClient
from opal_client.config import opal_common_config, opal_client_config

from horizon.config import sidecar_config
from horizon.proxy.api import router as proxy_router
from horizon.enforcer.api import init_enforcer_api_router
from horizon.local.api import init_local_cache_api_router
from horizon.topics import DataTopicsFetcher

class AuthorizonSidecar:
    """
    Authorizon sidecar is a thin wrapper on top of opal client.

    by extending opal client, it runs:
    - a subprocess running the OPA agent (with opal client's opa runner)
    - policy updater
    - data updater

    it also run directly authorizon specific apis:
    - proxy api (proxies the REST api at api.authorizon.com to the sdks)
    - local api (wrappers on top of opa cache)
    - enforcer api (implementation of is_allowed())
    """
    def __init__(self):
        if sidecar_config.PRINT_CONFIG_ON_STARTUP:
            logger.info(
                "sidecar is loading with the following config:\n\n{sidecar_config}\n\n{opal_client_config}\n\n{opal_common_config}",
                sidecar_config=sidecar_config.debug_repr(),
                opal_client_config=opal_client_config.debug_repr(),
                opal_common_config=opal_common_config.debug_repr(),
            )

        topics_fetcher = DataTopicsFetcher()
        data_topics = topics_fetcher.fetch_topics()
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
        app.openapi_tags = sidecar_config.OPENAPI_TAGS_METADATA
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

        # TODO: remove this when clients update sdk version (legacy routes)
        @app.post("/update_policy", status_code=status.HTTP_200_OK, include_in_schema=False)
        async def legacy_trigger_policy_update():
            response = RedirectResponse(url='/policy-updater/trigger')
            return response

        @app.post("/update_policy_data", status_code=status.HTTP_200_OK, include_in_schema=False)
        async def legacy_trigger_data_update():
            response = RedirectResponse(url='/data-updater/trigger')
            return response

    @property
    def app(self):
        return self._app


# expose app for Uvicorn
sidecar = AuthorizonSidecar()
app = sidecar.app