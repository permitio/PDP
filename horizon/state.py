import asyncio
import json
import os
import platform
import subprocess
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, List, Optional
from uuid import UUID, uuid4

import aiohttp
from fastapi import status
from opal_common.logger import logger
from opal_common.schemas.data import DataUpdateReport
from pydantic import BaseModel, ValidationError

from horizon.config import sidecar_config
from horizon.system.consts import API_VERSION

PERSISTENT_STATE_FILENAME = "/home/permit/persistent_state.json"
PDP_VERSION_FILENAME = "/permit_pdp_version"
MAX_STATE_UPDATE_INTERVAL_SECONDS = 60


class PersistentState(BaseModel):
    pdp_instance_id: UUID
    seen_sdks: Optional[List[Optional[str]]] = None


class StateUpdateThrottled(Exception):
    def __init__(self, next_allowed_update: float):
        super().__init__()
        self.next_allowed_update = next_allowed_update


class PersistentStateHandler:
    _instance: Optional["PersistentStateHandler"] = None

    def __init__(self, filename: str, env_api_key: str):
        self._filename = filename
        self._prev_state_update_attempt = 0.0
        self._seen_sdk_update_lock = asyncio.Lock()
        self._state_update_lock = asyncio.Lock()
        self._env_api_key = env_api_key
        if not self._load():
            self._new()

    def _new(self):
        self._state = PersistentState(
            pdp_instance_id=uuid4(),
            seen_sdks=[],
        )

    def _load(self) -> bool:
        if os.path.exists(self._filename):
            with open(self._filename, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    logger.warning(
                        "Unable to load existing persistent state: Invalid JSON."
                    )
                    return False
            try:
                self._state = PersistentState(**data)
            except ValidationError:
                logger.warning(
                    "Unable to load existing persistent state: Invalid schema."
                )
                return False
            return True
        return False

    def _save(self):
        new_filename = self._filename + ".new"
        with open(new_filename, "w") as f:
            f.write(self._state.json())
            f.flush()
            os.fsync(f.fileno())
        os.rename(new_filename, self._filename)

    @classmethod
    def initialize(cls, env_api_key: str):
        cls._instance = cls(PERSISTENT_STATE_FILENAME, env_api_key)
        logger.info("PDP ID is {}", cls.get().pdp_instance_id)

    @classmethod
    def get_instance(cls) -> "PersistentStateHandler":
        if cls._instance is None:
            raise RuntimeError("PersistentStateHandler not initialized.")
        return cls._instance

    @classmethod
    def get(cls) -> "PersistentState":
        return cls.get_instance()._state

    @asynccontextmanager
    async def update_state(self) -> AsyncGenerator[PersistentState, None]:
        async with self._state_update_lock:
            next_allowed_update = MAX_STATE_UPDATE_INTERVAL_SECONDS - (
                time.monotonic() - self._prev_state_update_attempt
            )
            # Since state updated are (for now) opportunistic and happen
            # regularly, we simply refuse to send them if they're too fast.
            # TODO: When we actually report information that doesn't repeat,
            # queue updates instead and retry if failing to report immediately
            if next_allowed_update > 0:
                raise StateUpdateThrottled(next_allowed_update)
            prev_state = self._state
            try:
                new_state = self._state.copy()
                yield new_state
                try:
                    await self._report(new_state)
                finally:
                    # Throttle even if the report failed
                    self._prev_state_update_attempt = time.monotonic()
                self._state = new_state.copy()
                self._save()
            except:
                self._state = prev_state

    @classmethod
    def _get_pdp_version(cls) -> Optional[str]:
        if os.path.exists(PDP_VERSION_FILENAME):
            with open(PDP_VERSION_FILENAME) as f:
                return f.read().strip()
        return "0.0.0"

    @classmethod
    def _get_pdp_runtime(cls) -> dict:
        return {
            "version": cls._get_pdp_version(),
            "os_name": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "os_platform": platform.platform(),
            "os_machine": platform.machine(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
        }

    @classmethod
    def _get_opa_version_vars(cls) -> dict:
        opa_proc = subprocess.run(
            ["opa", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if opa_proc.returncode != 0:
            logger.warning(
                "Unable to get OPA version: {}",
                opa_proc.stderr.decode(),
            )
            return {}
        return dict(
            [line.split(": ", 1) for line in opa_proc.stdout.decode().splitlines()]
        )

    @classmethod
    def get_runtime_state(cls) -> dict:
        # This is sync and called with run_in_executor because it has to be also
        # called from a sync context without using asyncio.run
        result = {}
        opa_version_vars = cls._get_opa_version_vars()
        result["pdp"] = cls._get_pdp_runtime()
        result["opa"] = {
            "version": opa_version_vars.get("Version"),
            "go_version": opa_version_vars.get("Go Version"),
            "platform": opa_version_vars.get("Platform"),
            "have_webassembly": opa_version_vars.get("WebAssembly") == "available",
        }
        return result

    @classmethod
    def _build_state_payload(cls, state: Optional[PersistentState] = None) -> dict:
        if state is None:
            state = cls.get()
        return {
            "pdp_instance_id": str(state.pdp_instance_id),
            "state": {
                "api_version": API_VERSION,
                "seen_sdks": state.seen_sdks,
            },
        }

    async def reporter_user_data_handler(
        self, report: DataUpdateReport
    ) -> dict[str, Any]:
        return {
            "pdp_instance_id": self.get().pdp_instance_id,
        }

    @classmethod
    async def build_state_payload(cls, state: Optional[PersistentState] = None) -> dict:
        payload = cls._build_state_payload()
        payload["state"].update(
            await asyncio.get_event_loop().run_in_executor(None, cls.get_runtime_state)
        )
        return payload

    @classmethod
    def build_state_payload_sync(cls, state: Optional[PersistentState] = None) -> dict:
        payload = cls._build_state_payload()
        payload["state"].update(cls.get_runtime_state())
        return payload

    async def _report(self, state: Optional[PersistentState] = None):
        config_url = (
            f"{sidecar_config.CONTROL_PLANE}{sidecar_config.REMOTE_STATE_ENDPOINT}"
        )
        async with aiohttp.ClientSession() as session:
            logger.info("Reporting status update to server...")
            response = await session.post(
                url=config_url,
                headers={"Authorization": f"Bearer {self._env_api_key}"},
                json=await PersistentStateHandler.build_state_payload(state),
            )
            if response.status != status.HTTP_204_NO_CONTENT:
                logger.warning(
                    "Unable to post PDP state update to server: {}",
                    await response.text(),
                )
                raise RuntimeError("Unable to post PDP state update to server.")

    async def seen_sdk(self, sdk: str):
        if not sdk in self._state.seen_sdks:
            # ensure_future is expensive, only call it if actually needed
            asyncio.ensure_future(self._report_seen_sdk(sdk))

    async def _report_seen_sdk(self, sdk: str):
        async with self._seen_sdk_update_lock:
            # We check this again because we might have waited because of the lock
            if not sdk in self._state.seen_sdks:
                try:
                    async with self.update_state() as new_state:
                        if new_state.seen_sdks is None:
                            new_state.seen_sdks = []
                        new_state.seen_sdks.append(sdk)
                except StateUpdateThrottled as e:
                    logger.debug(
                        "State updated throttled, next update {} seconds from now.",
                        e.next_allowed_update,
                    )
