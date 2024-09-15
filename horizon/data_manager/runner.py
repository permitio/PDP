import json
import logging
import os
import platform
from pathlib import Path

import aiohttp
from opal_client.config import EngineLogFormat
from opal_client.engine.logger import logging_level_from_string, log_entire_dict
from opal_client.engine.runner import PolicyEngineRunner
from opal_client.logger import logger


class DataManagerRunner(PolicyEngineRunner):
    def __init__(
        self,
        engine_token: str,
        data_manager_url: str,
        data_manager_binary_path: str,
        data_manager_token: str | None,
        data_manager_remote_backup_url: str | None,
        piped_logs_format: EngineLogFormat = EngineLogFormat.NONE,
    ):
        super().__init__(piped_logs_format=piped_logs_format)
        self._engine_token = engine_token
        self._data_manager_url = data_manager_url
        self._data_manager_binary_path = data_manager_binary_path
        self._data_manager_token = data_manager_token
        self._data_manager_remote_backup_url = data_manager_remote_backup_url
        self._client = None

    @property
    def client(self) -> aiohttp.ClientSession:
        if self._client is None:
            self._client = aiohttp.ClientSession(
                base_url=self._data_manager_url,
                headers={"Authorization": f"Bearer {self._engine_token}"},
            )
        return self._client

    async def handle_log_line(self, line: bytes) -> None:
        try:
            log_line = json.loads(line)
            level = logging.getLevelName(
                logging_level_from_string(log_line.pop("level", "info"))
            )
            msg = log_line.pop("msg", None)
            log_entire_dict(level, msg, log_line)
        except json.JSONDecodeError:
            logger.info(line.decode("utf-8"))

    async def __aenter__(self):
        self.set_envs()
        await super().__aenter__()
        await self.client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await super().__aexit__(exc_type, exc_val, exc_tb)
        await self.client.__aexit__(exc_type, exc_val, exc_tb)

    async def is_healthy(self) -> bool:
        async with self.client.get("/healthy") as resp:
            try:
                resp.raise_for_status()
            except aiohttp.ClientResponseError:
                return False
            else:
                return True

    async def is_ready(self) -> bool:
        async with self.client.get("/ready") as resp:
            try:
                resp.raise_for_status()
            except aiohttp.ClientResponseError:
                return False
            else:
                return True

    def set_envs(self) -> None:
        os.environ["PDP_ENGINE_TOKEN"] = self._engine_token
        if self._data_manager_token:
            os.environ["PDP_TOKEN"] = self._data_manager_token
        os.environ["PDP_BACKUP_ENABLED"] = "true"
        if self._data_manager_remote_backup_url:
            os.environ["PDP_BACKUP_URL"] = self._data_manager_remote_backup_url

    @property
    def command(self) -> str:
        return self._data_manager_binary_path
