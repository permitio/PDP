import json
import logging
import os
from pathlib import Path

import aiohttp
from opal_client.config import EngineLogFormat
from opal_client.engine.logger import logging_level_from_string, log_entire_dict
from opal_client.engine.runner import PolicyEngineRunner
from opal_client.logger import logger


class FactDBRunner(PolicyEngineRunner):
    def __init__(
        self,
        storage_path: Path,
        engine_token: str,
        factdb_url: str,
        factdb_binary_path: str,
        factdb_token: str | None,
        factdb_backup_server_url: str | None,
        backup_fetch_max_retries: int,
        piped_logs_format: EngineLogFormat = EngineLogFormat.NONE,
    ):
        super().__init__(piped_logs_format=piped_logs_format)
        self._storage_path = storage_path
        self._engine_token = engine_token
        self._factdb_url = factdb_url
        self._factdb_binary_path = factdb_binary_path
        self._factdb_token = factdb_token
        self._factdb_backup_server_url = factdb_backup_server_url
        self._backup_fetch_max_retries = backup_fetch_max_retries
        self._client = None

        self._storage_path.mkdir(parents=True, exist_ok=True)

    @property
    def client(self) -> aiohttp.ClientSession:
        if self._client is None:
            self._client = aiohttp.ClientSession(
                base_url=self._factdb_url,
                headers={"Authorization": f"Bearer {self._engine_token}"},
            )
        return self._client

    async def handle_log_line(self, line: bytes) -> None:
        try:
            log_line = json.loads(line)
            level = logging.getLevelName(logging_level_from_string(log_line.pop("level", "info")))
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
        os.environ["PDP_FACT_STORE_DSN"] = str(self._storage_path / "fact.db")
        os.environ["PDP_BACKUP_MAX_RETRIES"] = str(self._backup_fetch_max_retries)
        if self._factdb_token:
            os.environ["PDP_TOKEN"] = self._factdb_token
        os.environ["PDP_BACKUP_ENABLED"] = "true"
        if self._factdb_backup_server_url:
            os.environ["PDP_BACKUP_URL"] = self._factdb_backup_server_url

    def get_executable_path(self) -> str:
        return self._factdb_binary_path

    def get_arguments(self) -> list[str]:
        return []
