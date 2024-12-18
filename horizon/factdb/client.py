import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi import FastAPI
from loguru import logger
from opal_client import OpalClient
from opal_client.config import EngineLogFormat, opal_client_config
from opal_client.data.api import init_data_router
from opal_client.data.updater import DataUpdater
from opal_client.engine.options import CedarServerOptions, OpaServerOptions
from opal_client.engine.runner import PolicyEngineRunner
from opal_client.policy.api import init_policy_router
from opal_client.policy.updater import PolicyUpdater
from opal_client.policy_store.api import init_policy_store_router
from opal_client.policy_store.base_policy_store_client import BasePolicyStoreClient
from opal_client.policy_store.schemas import PolicyStoreTypes
from opal_common.authentication.deps import JWTAuthenticator
from opal_common.authentication.verifier import JWTVerifier
from opal_common.fetcher.providers.http_fetch_provider import (
    HttpFetcherConfig,
    HttpMethods,
)
from scalar_fastapi import get_scalar_api_reference
from starlette import status
from starlette.responses import JSONResponse

from horizon.config import sidecar_config
from horizon.factdb.policy_store import FactDBPolicyStoreClient
from horizon.factdb.runner import FactDBRunner


class ExtendedOpalClient(OpalClient):
    """
    Extended OpalClient that allows for additional healthchecks besides of the
    policy store one
    it is only used in FactDB and will later be removed when we add FactDB Policy Store implementation
    """

    async def check_healthy(self) -> bool:
        return await self.policy_store.is_healthy()

    async def check_ready(self) -> bool:
        return self._backup_loaded or await self.policy_store.is_ready()

    def _init_fast_api_app(self) -> FastAPI:
        # Called at the end of OPALClient.__init__
        self._inject_extra_callbacks()
        return super()._init_fast_api_app()

    def _configure_api_routes(self, app: FastAPI):
        """mounts the api routes on the app object."""

        @app.get("/scalar", include_in_schema=False)
        async def scalar_html():
            return get_scalar_api_reference(
                openapi_url="/openapi.json",
                title="Permit.io PDP API",
            )

        authenticator = JWTAuthenticator(self.verifier)

        # Init api routers with required dependencies
        policy_router = init_policy_router(policy_updater=self.policy_updater)
        data_router = init_data_router(data_updater=self.data_updater)
        policy_store_router = init_policy_store_router(authenticator)

        # mount the api routes on the app object
        app.include_router(policy_router, tags=["Policy Updater"])
        app.include_router(data_router, tags=["Data Updater"])
        app.include_router(policy_store_router, tags=["Policy Store"])

        # excluded callbacks api from the main api, since we use it internally.
        # Use the DATA_UPDATE_CALLBACKS config to configure callbacks instead

        # top level routes (i.e: healthchecks)
        @app.get("/healthcheck", include_in_schema=False)
        @app.get("/", include_in_schema=False)
        @app.get("/healthy", include_in_schema=False)
        async def healthy():
            """returns 200 if updates keep being successfully fetched from the
            server and applied to the policy store."""
            healthy = await self.check_healthy()
            if healthy:
                return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "ok"})
            else:
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"status": "unavailable"},
                )

        @app.get("/ready", include_in_schema=False)
        async def ready():
            """returns 200 if the policy store is ready to serve requests."""
            ready = await self.check_ready()
            if ready:
                return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "ok"})
            else:
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"status": "unavailable"},
                )

        return app

    def _inject_extra_callbacks(self) -> None:
        register = self._callbacks_register
        default_config = HttpFetcherConfig(
            method=HttpMethods.POST,
            headers={"content-type": "application/json"},
            process_data=False,
            fetcher=None,
        )
        for entry in sidecar_config.DATA_UPDATE_CALLBACKS:
            entry.config = entry.config or default_config
            entry.key = entry.key or register.calc_hash(entry.url, entry.config)

            if register.get(entry.key):
                raise RuntimeError(f"Callback with key '{entry.key}' already exists. Please specify a different key.")

            logger.info(f"Registering data update callback to url '{entry.url}' with key '{entry.key}'")
            register.put(entry.url, entry.config, entry.key)


class FactDBClient(ExtendedOpalClient):
    def __init__(
        self,
        policy_store_type: PolicyStoreTypes = None,
        policy_store: BasePolicyStoreClient = None,
        data_updater: DataUpdater = None,
        data_topics: list[str] = None,
        policy_updater: PolicyUpdater = None,
        inline_opa_enabled: bool = None,
        inline_opa_options: OpaServerOptions = None,
        inline_cedar_enabled: bool = None,
        inline_cedar_options: CedarServerOptions = None,
        verifier: JWTVerifier | None = None,
        store_backup_path: str | None = None,
        store_backup_interval: int | None = None,
        offline_mode_enabled: bool = False,
        shard_id: str | None = None,
    ):
        self._factdb_enabled = sidecar_config.FACTDB_ENABLED
        if self._factdb_enabled:
            self._factdb_runner = FactDBRunner(
                storage_path=Path(sidecar_config.OFFLINE_MODE_BACKUP_DIR) / "factdb",
                factdb_url=sidecar_config.FACTDB_SERVICE_URL,
                factdb_binary_path=sidecar_config.FACTDB_BINARY_PATH,
                factdb_token=opal_client_config.CLIENT_TOKEN,
                factdb_backup_server_url=sidecar_config.FACTDB_BACKUP_SERVER_URL,
                # Limit retires when in offline mode or 0 (infinite retries) when online
                backup_fetch_max_retries=sidecar_config.CONFIG_FETCH_MAX_RETRIES
                if sidecar_config.ENABLE_OFFLINE_MODE
                else 0,
                engine_token=sidecar_config.API_KEY,
                piped_logs_format=EngineLogFormat.FULL,
            )
            policy_store = policy_store or FactDBPolicyStoreClient(
                factdb_client=lambda: self._factdb_runner.client,
                opa_server_url=opal_client_config.POLICY_STORE_URL,
                opa_auth_token=opal_client_config.POLICY_STORE_AUTH_TOKEN,
                auth_type=opal_client_config.POLICY_STORE_AUTH_TYPE,
                oauth_client_id=opal_client_config.POLICY_STORE_AUTH_OAUTH_CLIENT_ID,
                oauth_client_secret=opal_client_config.POLICY_STORE_AUTH_OAUTH_CLIENT_SECRET,
                oauth_server=opal_client_config.POLICY_STORE_AUTH_OAUTH_SERVER,
                data_updater_enabled=opal_client_config.DATA_UPDATER_ENABLED,
                policy_updater_enabled=opal_client_config.POLICY_UPDATER_ENABLED,
                cache_policy_data=opal_client_config.OFFLINE_MODE_ENABLED,
                tls_client_cert=opal_client_config.POLICY_STORE_TLS_CLIENT_CERT,
                tls_client_key=opal_client_config.POLICY_STORE_TLS_CLIENT_KEY,
                tls_ca=opal_client_config.POLICY_STORE_TLS_CA,
            )
        super().__init__(
            policy_store_type=policy_store_type,
            policy_store=policy_store,
            data_updater=data_updater,
            data_topics=data_topics,
            policy_updater=policy_updater,
            inline_opa_enabled=inline_opa_enabled,
            inline_opa_options=inline_opa_options,
            inline_cedar_enabled=inline_cedar_enabled,
            inline_cedar_options=inline_cedar_options,
            verifier=verifier,
            store_backup_path=store_backup_path,
            store_backup_interval=store_backup_interval,
            offline_mode_enabled=offline_mode_enabled,
            shard_id=shard_id,
        )

    @staticmethod
    async def _run_engine_runner(
        callback: Callable[[], Awaitable] | None,
        engine_runner: PolicyEngineRunner,
    ):
        # runs the callback after policy store is up
        engine_runner.register_process_initial_start_callbacks([callback] if callback else [])
        async with engine_runner:
            await engine_runner.wait_until_done()

    async def start_factdb_runner(self):
        await self._run_engine_runner(None, self._factdb_runner)

    async def stop_factdb_runner(self):
        logger.info("Stopping FactDB runner")
        await self._factdb_runner.stop()

    async def check_healthy(self) -> bool:
        try:
            opal_health = await super().check_healthy()
            if not opal_health:
                return False
            if self._factdb_enabled:
                return await self._factdb_runner.is_healthy()
        except Exception as e:
            logger.exception("Error checking health: {e}", e=e)
            return False
        else:
            return True

    async def check_ready(self) -> bool:
        try:
            opal_ready = await super().check_ready()
            if not opal_ready:
                return False
            if self._factdb_enabled:
                return await self._factdb_runner.is_ready()
        except Exception as e:
            logger.exception("Error checking ready: {e}", e=e)
            return False
        else:
            return True

    async def start_client_background_tasks(self):
        tasks = [super().start_client_background_tasks()]
        if self._factdb_enabled:
            logger.info("Starting FactDB runner")
            tasks.append(self.start_factdb_runner())
        await asyncio.gather(*tasks)

    async def stop_client_background_tasks(self):
        """stops all background tasks (called on shutdown event)"""
        await super().stop_client_background_tasks()
        if self._factdb_enabled:
            await self.stop_factdb_runner()
