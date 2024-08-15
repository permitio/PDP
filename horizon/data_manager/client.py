import asyncio
from typing import Optional, Awaitable, Callable

from fastapi import FastAPI
from loguru import logger
from opal_client import OpalClient
from opal_client.callbacks.api import init_callbacks_api
from opal_client.data.api import init_data_router
from opal_client.engine.runner import PolicyEngineRunner
from opal_client.policy.api import init_policy_router
from opal_client.policy_store.api import init_policy_store_router
from opal_common.authentication.deps import JWTAuthenticator
from starlette import status
from starlette.responses import JSONResponse

from horizon.config import sidecar_config
from horizon.data_manager.runner import DataManagerRunner


class ExtendedOpalClient(OpalClient):
    """
    Extended OpalClient that allows for additional healthchecks besides of the
    policy store one
    it is only used in data manager and will later be removed when we add Data Manager Policy Store implementation
    """

    async def check_healthy(self) -> bool:
        return await self.policy_store.is_healthy()

    async def check_ready(self) -> bool:
        return self._backup_loaded or await self.policy_store.is_ready()

    def _configure_api_routes(self, app: FastAPI):
        """mounts the api routes on the app object."""

        authenticator = JWTAuthenticator(self.verifier)

        # Init api routers with required dependencies
        policy_router = init_policy_router(policy_updater=self.policy_updater)
        data_router = init_data_router(data_updater=self.data_updater)
        policy_store_router = init_policy_store_router(authenticator)
        callbacks_router = init_callbacks_api(authenticator, self._callbacks_register)

        # mount the api routes on the app object
        app.include_router(policy_router, tags=["Policy Updater"])
        app.include_router(data_router, tags=["Data Updater"])
        app.include_router(policy_store_router, tags=["Policy Store"])
        app.include_router(callbacks_router, tags=["Callbacks"])

        # top level routes (i.e: healthchecks)
        @app.get("/healthcheck", include_in_schema=False)
        @app.get("/", include_in_schema=False)
        @app.get("/healthy", include_in_schema=False)
        async def healthy():
            """returns 200 if updates keep being successfully fetched from the
            server and applied to the policy store."""
            healthy = await self.check_healthy()
            if healthy:
                return JSONResponse(
                    status_code=status.HTTP_200_OK, content={"status": "ok"}
                )
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
                return JSONResponse(
                    status_code=status.HTTP_200_OK, content={"status": "ok"}
                )
            else:
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"status": "unavailable"},
                )

        return app


class DataManagerClient(ExtendedOpalClient):
    @staticmethod
    async def _run_engine_runner(
        callback: Optional[Callable[[], Awaitable]],
        engine_runner: PolicyEngineRunner,
    ):
        # runs the callback after policy store is up
        engine_runner.register_process_initial_start_callbacks(
            [callback] if callback else []
        )
        async with engine_runner:
            await engine_runner.wait_until_done()

    async def start_data_manager_runner(self):
        self._data_manager_runner = DataManagerRunner(
            data_manager_url=sidecar_config.DATA_MANAGER_SERVICE_URL,
            data_manager_token=sidecar_config.DATA_MANAGER_TOKEN,
            data_manager_remote_backup_enabled=sidecar_config.DATA_MANAGER_ENABLE_REMOTE_BACKUP,
            data_manager_remote_backup_url=sidecar_config.DATA_MANAGER_REMOTE_BACKUP_URL,
            engine_token=sidecar_config.API_KEY,
        )
        await self._run_engine_runner(None, self._data_manager_runner)

    async def stop_data_manager_runner(self):
        if hasattr(self, "_data_manager_runner") and self._data_manager_runner:
            logger.info("Stopping Data Manager runner")
            await self._data_manager_runner.stop()

    async def check_healthy(self) -> bool:
        opal_health = await super().check_healthy()
        if not opal_health:
            return False
        return await self._data_manager_runner.is_healthy()

    async def check_ready(self) -> bool:
        opal_ready = await super().check_ready()
        if not opal_ready:
            return False
        return await self._data_manager_runner.is_ready()

    async def start_client_background_tasks(
        self,
        *,
        data_manager_runner_enabled: bool = sidecar_config.ENABLE_EXTERNAL_DATA_MANAGER
    ):
        tasks = [super().start_client_background_tasks()]
        if data_manager_runner_enabled:
            logger.info("Starting Data Manager runner")
            tasks.append(self.start_data_manager_runner())
        await asyncio.gather(*tasks)

    async def stop_client_background_tasks(self):
        """stops all background tasks (called on shutdown event)"""
        await super().stop_client_background_tasks()
        await self.stop_data_manager_runner()
