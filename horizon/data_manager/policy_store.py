from typing import Optional

from aiofiles.threadpool.text import AsyncTextIOWrapper
from aiohttp import ClientSession
from opal_client.policy_store.opa_client import OpaClient
from opal_client.policy_store.schemas import PolicyStoreAuth
from opal_common.schemas.data import JsonableValue
from pydantic import BaseModel


class DataManagerPolicyStoreClient(OpaClient):
    def __init__(
        self,
        data_manager_client: ClientSession,
        opa_server_url=None,
        opa_auth_token: Optional[str] = None,
        auth_type: PolicyStoreAuth = PolicyStoreAuth.NONE,
        oauth_client_id: Optional[str] = None,
        oauth_client_secret: Optional[str] = None,
        oauth_server: Optional[str] = None,
        data_updater_enabled: bool = True,
        policy_updater_enabled: bool = True,
        cache_policy_data: bool = False,
        tls_client_cert: Optional[str] = None,
        tls_client_key: Optional[str] = None,
        tls_ca: Optional[str] = None,
    ):
        super().__init__(
            opa_server_url,
            opa_auth_token,
            auth_type,
            oauth_client_id,
            oauth_client_secret,
            oauth_server,
            data_updater_enabled,
            policy_updater_enabled,
            cache_policy_data,
            tls_client_cert,
            tls_client_key,
            tls_ca,
        )
        self._client = data_manager_client

    async def set_policy_data(
        self,
        policy_data: JsonableValue,
        path: str = "",
        transaction_id: Optional[str] = None,
    ):
        ...  # TODO

    async def delete_policy_data(
        self, path: str = "", transaction_id: Optional[str] = None
    ):
        ...  # TODO

    async def get_data(self, path: str) -> dict:
        ...  # TODO

    async def get_data_with_input(self, path: str, input: BaseModel) -> dict:
        ...  # TODO

    async def init_healthcheck_policy(self, policy_id: str, policy_code: str):
        ...  # TODO

    async def full_export(self, writer: AsyncTextIOWrapper) -> None:
        ...  # TODO

    async def full_import(self, reader: AsyncTextIOWrapper) -> None:
        ...  # TODO
