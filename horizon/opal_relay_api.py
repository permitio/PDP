import asyncio
import json
import time
from base64 import b64decode
from urllib.parse import urljoin
from uuid import UUID

from aiohttp import ClientSession
from fastapi import status
from fastapi.encoders import jsonable_encoder
from loguru import logger
from opal_client.client import OpalClient
from opal_client.config import opal_client_config
from pydantic import BaseModel

from horizon.config import sidecar_config
from horizon.state import PersistentStateHandler


class RelayAPIException(Exception):
    def __init__(self, service: str, status_code: int, message: str):
        self.service = service
        self.status_code = status_code
        self.message = f"Relay API exception from {service} of {status_code}: {message}"
        super().__init__(self.message)


class RelayJWTResponse(BaseModel):
    token: str


class PDPPingRequest(BaseModel):
    pdp_instance_id: UUID
    topics: list[str]
    timestamp_ns: int


MAX_JWT_EXPIRY_BUFFER_TIME = 10


def get_jwt_expiry_time(jwt: str) -> int:
    # We parse it like this to avoid pulling in a full JWT library
    claims = json.loads(b64decode(jwt.split(".")[1]))
    return claims["exp"]


class OpalRelayAPIClient:
    def __init__(self, context: dict[str, str], opal_client: OpalClient):
        self._relay_session: ClientSession | None = None
        self._api_session: ClientSession | None = None
        self._relay_token: str | None = None
        self._available = False
        self._opal_client = opal_client
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
                logger.warning(
                    "Got bad context from backend. Not enabling OPAL relay client."
                )

    def api_session(self) -> ClientSession:
        if self._api_session is None:
            self._api_session = ClientSession(
                headers={"Authorization": f"Bearer {sidecar_config.API_KEY}"}
            )
        return self._api_session

    async def relay_session(self) -> ClientSession:
        if (
            self._relay_token is None
            or get_jwt_expiry_time(self._relay_token) - time.time()
            < MAX_JWT_EXPIRY_BUFFER_TIME
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
                    raise RelayAPIException(
                        "relay-jwt-api",
                        response.status,
                        f"Server responded to token request with a bad status: {text}",
                    )
                try:
                    obj = RelayJWTResponse.parse_obj(await response.json())
                except TypeError:
                    try:
                        text = await response.text()
                    except:
                        text = None
                    raise RelayAPIException(
                        "relay-jwt-api",
                        response.status,
                        f"Server responded to token request with an invalid result: {text}",
                    )
            self._relay_token = obj.token
            self._relay_session = ClientSession(
                headers={"Authorization": f"Bearer {self._relay_token}"}
            )
        return self._relay_session

    async def send_ping(self):
        session = await self.relay_session()
        # This is ugly but for now this is not exposed publically in OPAL
        policy_topics = self._opal_client.policy_updater.topics
        data_topics = opal_client_config.DATA_TOPICS
        if opal_client_config.SCOPE_ID != "default":
            data_topics = [
                f"{opal_client_config.SCOPE_ID}:data:{topic}"
                for topic in opal_client_config.DATA_TOPICS
            ]
        topics = data_topics + policy_topics
        async with session.post(
            urljoin(sidecar_config.CONTROL_PLANE_RELAY_API, "v2/pdp/ping"),
            json=jsonable_encoder(
                PDPPingRequest(
                    pdp_instance_id=PersistentStateHandler.get().pdp_instance_id,
                    topics=topics,
                    timestamp_ns=time.time_ns(),
                )
            ),
        ) as response:
            if response.status != status.HTTP_202_ACCEPTED:
                try:
                    text = await response.text()
                except:
                    text = None
                raise RelayAPIException(
                    "relay-api",
                    response.status,
                    f"Server responded to token request with a bad status {response.status}: {text}",
                )
        logger.debug("Sent ping.")

    async def _run(self):
        while True:
            try:
                await self.send_ping()
            except RelayAPIException as e:
                logger.warning(
                    "Could not report uptime status to server: {}. This does not affect the PDP's operational state or data updates.",
                    e.message,
                )
            except Exception as e:
                logger.warning(
                    "Could not report uptime status to server: {}. This does not affect the PDP's operational state or data updates.",
                    str(e),
                )

            await asyncio.sleep(sidecar_config.PING_INTERVAL)

    async def start(self):
        self._task = asyncio.create_task(self._run())

    async def initialize(self):
        if self.available:
            await self.start()
