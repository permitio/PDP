import asyncio
import json
import time
from base64 import urlsafe_b64decode
from urllib.parse import urljoin
from uuid import UUID

import aiohttp
from aiohttp import ClientSession
from fastapi import status
from fastapi.encoders import jsonable_encoder
from loguru import logger
from opal_client.client import OpalClient
from opal_client.config import opal_client_config
from pydantic import BaseModel

from horizon.config import sidecar_config
from horizon.startup.api_keys import get_env_api_key
from horizon.state import PersistentStateHandler


class RelayAPIError(Exception):
    def __init__(self, service: str, status_code: int, message: str):
        self.service = service
        self.status_code = status_code
        self.message = f"Relay API exception from {service} of {status_code}: {message}"
        super().__init__(self.message)


class RelayJWTResponse(BaseModel):
    token: str


class PDPPingPlatformPDPState(BaseModel):
    version: str
    os_name: str
    os_machine: str
    os_version: str
    os_release: str
    os_platform: str
    python_version: str
    python_implementation: str


class PDPPingPlatformOPAState(BaseModel):
    version: str
    go_version: str
    platform: str
    have_webassembly: bool


class PDPPingPlatformState(BaseModel):
    pdp: PDPPingPlatformPDPState
    opa: PDPPingPlatformOPAState


class PDPPingRequest(BaseModel):
    pdp_instance_id: UUID
    topics: list[str]
    timestamp_ns: int
    platform: PDPPingPlatformState


MAX_JWT_EXPIRY_BUFFER_TIME = 60 * 60  # 1 hour, has to be more than the ping interval


def get_jwt_expiry_time(jwt: str) -> int:
    """The ``exp`` claim of a JWT, read without verifying the token (that avoids a full JWT library).

    JWT segments are base64url with the padding stripped (RFC 7515), so the padding is put back first.
    """
    payload = jwt.split(".")[1]
    claims = json.loads(urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return claims["exp"]


class OpalRelayAPIClient:
    def __init__(self, context: dict[str, str], opal_client: OpalClient):
        self._relay_session: ClientSession | None = None
        self._api_session: ClientSession | None = None
        self._relay_token: str | None = None
        self._available = False
        self._opal_client = opal_client
        # Types of unexpected ping failures already logged with a traceback since the last good ping.
        self._traced_ping_failures: set[type[Exception]] = set()
        self._apply_context(context)

    @property
    def available(self) -> bool:
        return self._available

    def _apply_context(self, context: dict[str, str]):
        if "org_id" in context and "project_id" in context and "env_id" in context:
            try:
                self._org_id = UUID(context["org_id"])
                self._project_id = UUID(context["project_id"])
                self._env_id = UUID(context["env_id"])
                self._available = True
            except TypeError:
                logger.warning("Got bad context from backend. Not enabling OPAL relay client.")

    def api_session(self) -> ClientSession:
        if self._api_session is None:
            env_api_key = get_env_api_key()
            self._api_session = ClientSession(headers={"Authorization": f"Bearer {env_api_key}"}, trust_env=True)
        return self._api_session

    async def relay_session(self) -> ClientSession:
        session = self._relay_session
        if (
            session is None
            or self._relay_token is None
            or get_jwt_expiry_time(self._relay_token) - time.time() < MAX_JWT_EXPIRY_BUFFER_TIME
        ):
            async with self.api_session().post(
                urljoin(
                    sidecar_config.CONTROL_PLANE_RELAY_JWT_TIER,
                    f"v2/relay_jwt/{self._org_id.hex}/{self._project_id.hex}/{self._env_id.hex}",
                ),
                json={
                    "service_name": "opal_relay_api",
                },
            ) as response:
                if response.status != status.HTTP_200_OK:
                    text = await response.text()
                    raise RelayAPIError(
                        "relay-jwt-api",
                        response.status,
                        f"Server responded to token request with a bad status: {text}",
                    )
                try:
                    obj = RelayJWTResponse.parse_obj(await response.json())
                # ValueError covers pydantic's ValidationError and a body that is not JSON or not UTF-8.
                except (ValueError, aiohttp.ContentTypeError) as e:
                    try:
                        # json() above already read the body, so decoding it is all text() does here.
                        text = await response.text()
                    except UnicodeDecodeError:
                        text = None

                    raise RelayAPIError(
                        "relay-jwt-api",
                        response.status,
                        f"Server responded to token request with an invalid result: {text}",
                    ) from e
            self._relay_token = obj.token
            session = ClientSession(
                headers={"Authorization": f"Bearer {self._relay_token}"},
                trust_env=True,
                timeout=aiohttp.ClientTimeout(total=sidecar_config.CONTROL_PLANE_TIMEOUT),
            )
            self._relay_session = session
        return session

    async def send_ping(self):
        session = await self.relay_session()
        # OPAL has no policy updater when OPAL_POLICY_UPDATER_ENABLED is false; the PDP then listens on no policy topic.
        policy_updater = self._opal_client.policy_updater
        policy_topics = [] if policy_updater is None else policy_updater.topics
        data_topics = opal_client_config.DATA_TOPICS
        if opal_client_config.SCOPE_ID != "default":
            data_topics = [f"{opal_client_config.SCOPE_ID}:data:{topic}" for topic in opal_client_config.DATA_TOPICS]
        topics = data_topics + policy_topics
        async with session.post(
            urljoin(sidecar_config.CONTROL_PLANE_RELAY_API, "v2/pdp/ping"),
            json=jsonable_encoder(
                PDPPingRequest(
                    pdp_instance_id=PersistentStateHandler.get().pdp_instance_id,
                    topics=topics,
                    timestamp_ns=time.time_ns(),
                    platform=PDPPingPlatformState.parse_obj(
                        await asyncio.get_event_loop().run_in_executor(None, PersistentStateHandler.get_runtime_state)
                    ),
                )
            ),
        ) as response:
            if response.status != status.HTTP_202_ACCEPTED:
                try:
                    text = await response.text()
                except (aiohttp.ClientError, TimeoutError, UnicodeDecodeError):
                    text = None

                raise RelayAPIError(
                    "relay-api",
                    response.status,
                    f"Server responded to token request with a bad status: {text}",
                )
        logger.debug("Sent ping.")

    async def _run(self):
        while True:
            try:
                await self.send_ping()
            except RelayAPIError as e:
                logger.warning(
                    "Could not report uptime status to server: got status code {} from {}. "
                    "This does not affect the PDP's operational state or data updates.",
                    e.status_code,
                    e.service,
                )
            except (aiohttp.ClientError, TimeoutError) as e:
                logger.warning(
                    "Could not report uptime status to server: {}: {}. This does not affect the PDP's operational "
                    "state or data updates.",
                    type(e).__name__,
                    e,
                )
            except Exception as e:  # noqa: BLE001 - keep the ping loop alive: log it, retry next interval
                self._log_unexpected_ping_failure(e)
            else:
                self._traced_ping_failures.clear()

            await asyncio.sleep(sidecar_config.PING_INTERVAL)

    def _log_unexpected_ping_failure(self, error: Exception) -> None:
        """Log a ping failure no handler above expects, with a traceback the first time its type appears.

        Some of these last until a restart, such as a runtime state that does not validate, and the
        loop retries every PING_INTERVAL, so a traceback each time would flood the log. Later
        failures of the same type log one line until a ping succeeds.
        """
        if type(error) in self._traced_ping_failures:
            logger.warning(
                "Could not report uptime status to server: {}: {}. This does not affect the PDP's operational "
                "state or data updates.",
                type(error).__name__,
                error,
            )
            return
        self._traced_ping_failures.add(type(error))
        logger.opt(exception=error).warning(
            "Could not report uptime status to server. This does not affect the PDP's operational state or data "
            "updates. Until a ping succeeds, this error is logged again without its traceback."
        )

    async def start(self):
        self._task = asyncio.create_task(self._run())

    async def initialize(self):
        if self.available:
            await self.start()
