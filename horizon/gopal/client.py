import asyncio
from typing import Optional, Awaitable, Callable

from loguru import logger
from opal_client import OpalClient
from opal_client.engine.runner import PolicyEngineRunner

from horizon.config import sidecar_config
from horizon.gopal.runner import GopalRunner


class GOPALClient(OpalClient):

    @staticmethod
    async def _run_engine_runner(
        callback: Optional[Callable[[], Awaitable]],
        engine_runner: PolicyEngineRunner,
    ):
        # runs the callback after policy store is up
        engine_runner.register_process_initial_start_callbacks([callback] if callback else [])
        async with engine_runner:
            await engine_runner.wait_until_done()

    async def _run_or_delay_for_engine_runner(
        self, callback: Callable[[], Awaitable]
    ):
        if self.engine_runner:
            # runs the callback after policy store is up
            await self._run_engine_runner(callback, self.engine_runner)
            return

        # we do not run the policy store in the same container
        # therefore we can immediately run the callback
        await callback()

    async def start_gopal_runner(self):
        self._gopal_runner = GopalRunner()
        await self._run_engine_runner(None, self._gopal_runner)

    async def stop_gopal_runner(self):
        if hasattr(self, "_gopal_runner") and self._gopal_runner:
            logger.info("Stopping GOPAL runner")
            await self._gopal_runner.stop()

    async def start_client_background_tasks(self, *, gopal_runner_enabled: bool = sidecar_config.ENABLE_GOPAL):
        tasks = [super().start_client_background_tasks()]
        if gopal_runner_enabled:
            logger.info("Starting GOPAL runner")
            tasks.append(self.start_gopal_runner())
        await asyncio.gather(*tasks)

    async def stop_client_background_tasks(self):
        """stops all background tasks (called on shutdown event)"""
        await super().stop_client_background_tasks()
        await self.stop_gopal_runner()
