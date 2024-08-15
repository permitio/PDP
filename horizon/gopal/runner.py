import os
import platform
from pathlib import Path

import aiohttp
from opal_client.config import EngineLogFormat
from opal_client.engine.runner import PolicyEngineRunner


class GopalRunner(PolicyEngineRunner):
    def __init__(
        self,
        engine_token: str,
        gopal_url: str,
        gopal_token: str | None,
        gopal_remote_backup_enabled: bool,
        gopal_remote_backup_url: str | None,
        piped_logs_format: EngineLogFormat = EngineLogFormat.NONE,
    ):
        super().__init__(piped_logs_format=piped_logs_format)
        self._engine_token = engine_token
        self._gopal_url = gopal_url
        self._gopal_token = gopal_token
        self._gopal_remote_backup_enabled = gopal_remote_backup_enabled
        self._gopal_remote_backup_url = gopal_remote_backup_url
        self.__client = None

    @property
    def _client(self) -> aiohttp.ClientSession:
        if self.__client is None:
            self.__client = aiohttp.ClientSession(
                base_url=self._gopal_url,
                headers={"Authorization": f"Bearer {self._engine_token}"},
            )
        return self.__client

    async def __aenter__(self):
        self.set_envs()
        await super().__aenter__()
        await self._client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await super().__aexit__(exc_type, exc_val, exc_tb)
        await self._client.__aexit__(exc_type, exc_val, exc_tb)

    async def is_healthy(self) -> bool:
        async with self._client.get("/healthy") as resp:
            try:
                resp.raise_for_status()
            except aiohttp.ClientResponseError:
                return False
            else:
                return True

    async def is_ready(self) -> bool:
        async with self._client.get("/ready") as resp:
            try:
                resp.raise_for_status()
            except aiohttp.ClientResponseError:
                return False
            else:
                return True

    def set_envs(self) -> None:
        os.environ["PDP_ENGINE_TOKEN"] = self._engine_token
        if self._gopal_token:
            os.environ["PDP_GOPAL_TOKEN"] = self._gopal_token
        os.environ["PDP_GOPAL_ENABLE_REMOTE_BACKUP"] = (
            "true" if self._gopal_remote_backup_enabled else "false"
        )
        if self._gopal_remote_backup_url:
            os.environ["PDP_GOPAL_REMOTE_BACKUP_URL"] = self._gopal_remote_backup_url

    @property
    def command(self) -> str:
        current_dir = Path(__file__).parent

        arch = platform.machine()
        if arch == "x86_64":
            binary_path = "gopal-amd"
        elif arch == "arm64" or arch == "aarch64":
            binary_path = "gopal-arm"
        else:
            raise ValueError(f"Unsupported architecture: {arch}")
        return os.path.join(current_dir, binary_path)
