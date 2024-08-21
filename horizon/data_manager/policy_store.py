from typing import Optional

from aiofiles.threadpool.text import AsyncTextIOWrapper
from aiohttp import ClientSession
from opal_client.policy_store.opa_client import OpaClient
from opal_common.schemas.data import JsonableValue
from pydantic import BaseModel


class DataManagerPolicyStoreClient(OpaClient):
    def __init__(self, data_manager_client: ClientSession):
        super().__init__()
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
