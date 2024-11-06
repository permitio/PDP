import time
from typing import Optional, Iterator, Callable

import aiohttp
from aiohttp import ClientSession
from loguru import logger
from opal_client.policy_store.opa_client import OpaClient
from opal_client.policy_store.schemas import PolicyStoreAuth
from opal_common.schemas.data import JsonableValue

from horizon.data_manager.data_update import DataUpdate, AnyOperation
from horizon.data_manager.update_operations import (
    _get_operations_for_update_relationship_tuple,
    _get_operations_for_update_role_assigment,
    _get_operations_for_update_user,
    _get_operations_for_update_resource_instance,
)


class DataManagerPolicyStoreClient(OpaClient):
    def __init__(
        self,
        data_manager_client: ClientSession | Callable[[], ClientSession],
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

    @property
    def client(self):
        if isinstance(self._client, ClientSession):
            return self._client
        return self._client()

    async def set_policy_data(
        self,
        policy_data: JsonableValue,
        path: str = "",
        transaction_id: Optional[str] = None,
    ):
        parts = path.lstrip("/").split("/")
        try:
            update = DataUpdate.from_operations(
                self._generate_operations(parts, policy_data),
            )
        except NotImplementedError as e:
            logger.info("Storing policy data in OPA, target_path='{}'", path)
            return await super().set_policy_data(
                policy_data=policy_data, path=path, transaction_id=transaction_id
            )
        else:
            logger.info(
                "Storing policy data in external factstore, target_path='{}'", path
            )

        return await self._apply_data_update(update)

    def _generate_operations(
        self, parts: list[str], data: JsonableValue
    ) -> Iterator[AnyOperation]:
        match parts:
            case ["relationships", obj]:
                yield from _get_operations_for_update_relationship_tuple(obj, data)
            case ["role_assignments", full_user_key]:
                yield from _get_operations_for_update_role_assigment(
                    full_user_key, data
                )
            case ["users", user_key]:
                yield from _get_operations_for_update_user(user_key, data)
            case ["resource_instances", instance_key]:
                yield from _get_operations_for_update_resource_instance(
                    instance_key, data
                )
            case _:
                raise NotImplementedError(
                    f"Unsupported path for external factstore: {parts}"
                )

    async def _apply_data_update(
        self, data_update: DataUpdate
    ) -> aiohttp.ClientResponse:
        start_time = time.perf_counter_ns()
        res = await self.client.post(
            "/v1/facts/applyUpdate",
            json=data_update.dict(),
        )
        elapsed_time_ms = (time.perf_counter_ns() - start_time) / 1_000
        if res.status != 200:
            logger.error(
                "Failed to apply data update to external factstore: {}",
                await res.text(),
            )
        else:
            logger.info(
                f"Data update applied to external factstore: status={res.status} duration={elapsed_time_ms:.2f}ms"
            )
        return res
