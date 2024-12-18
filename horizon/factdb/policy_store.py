import time
from collections.abc import Callable, Iterator
from typing import Any

import aiohttp
from aiohttp import ClientSession
from loguru import logger
from opal_client.policy_store.opa_client import OpaClient
from opal_client.policy_store.schemas import PolicyStoreAuth
from opal_common.schemas.data import JsonableValue

from horizon.factdb.data_update import AnyOperation, DataUpdate
from horizon.factdb.update_operations import (
    _get_operations_for_update_relationship_tuple,
    _get_operations_for_update_resource_instance,
    _get_operations_for_update_role_assigment,
    _get_operations_for_update_user,
)


class FactDBPolicyStoreClient(OpaClient):
    def __init__(
        self,
        factdb_client: ClientSession | Callable[[], ClientSession],
        *,
        opa_server_url=None,
        opa_auth_token: str | None = None,
        auth_type: PolicyStoreAuth = PolicyStoreAuth.NONE,
        oauth_client_id: str | None = None,
        oauth_client_secret: str | None = None,
        oauth_server: str | None = None,
        tls_client_cert: str | None = None,
        tls_client_key: str | None = None,
        tls_ca: str | None = None,
        data_updater_enabled: bool = True,
        policy_updater_enabled: bool = True,
        cache_policy_data: bool = False,
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
        self._client = factdb_client

    @property
    def client(self):
        if isinstance(self._client, ClientSession):
            return self._client
        return self._client()

    async def set_policy_data(
        self,
        policy_data: JsonableValue,
        path: str = "",
        transaction_id: str | None = None,
    ):
        parts = path.lstrip("/").split("/")
        try:
            update = DataUpdate.from_operations(
                self._generate_operations(parts, policy_data),
            )
        except NotImplementedError as e:
            logger.warning(f"{e}, storing in OPA directly...")
            return await super().set_policy_data(policy_data=policy_data, path=path, transaction_id=transaction_id)

        return await self._apply_data_update(update)

    def _generate_operations(self, parts: list[str], data: JsonableValue) -> Iterator[AnyOperation]:  # noqa: C901
        match parts:
            case ["relationships"]:
                for obj, _data in data.items():
                    yield from _get_operations_for_update_relationship_tuple(obj, _data)
            case ["relationships", obj]:
                yield from _get_operations_for_update_relationship_tuple(obj, data)
            case ["role_assignments"]:
                for full_user_key, _data in data.items():
                    yield from _get_operations_for_update_role_assigment(full_user_key, _data)
            case ["role_assignments", full_user_key]:
                yield from _get_operations_for_update_role_assigment(full_user_key, data)
            case ["users"]:
                for user_key, _data in data.items():
                    yield from _get_operations_for_update_user(user_key, _data)
            case ["users", user_key]:
                yield from _get_operations_for_update_user(user_key, data)
            case ["resource_instances"]:
                for instance_key, _data in data.items():
                    yield from _get_operations_for_update_resource_instance(instance_key, _data)
            case ["resource_instances", instance_key]:
                yield from _get_operations_for_update_resource_instance(instance_key, data)
            case _:
                raise NotImplementedError(f"Unsupported path for FactDB: {parts}")

    async def _apply_data_update(self, data_update: DataUpdate) -> aiohttp.ClientResponse:
        start_time = time.perf_counter_ns()
        res = await self.client.post(
            "/v1/facts/applyUpdate",
            json=data_update.dict(),
        )
        elapsed_time_ms = (time.perf_counter_ns() - start_time) / 1_000_000
        if res.status != 200:
            logger.error(
                "Failed to apply data update to FactDB: {}",
                await res.text(),
            )
        else:
            logger.info(f"Data update applied to FactDB: status={res.status} duration={elapsed_time_ms:.2f}ms")
        return res

    async def list_facts_by_type(
        self,
        fact_type: str,
        page: int = 1,
        per_page: int = 30,
        filters: dict[str, Any] | None = None,
    ) -> aiohttp.ClientResponse:
        logger.info(
            "Performing list facts for '{fact_type}' fact type from the FactDB",
            fact_type=fact_type,
        )
        query_params = {
            "page": page,
            "per_page": per_page,
        } | (filters or {})
        res = await self.client.get(
            f"/v1/facts/{fact_type}",
            params=query_params,
        )
        if res.status != 200:
            logger.error(
                "Failed to list '{fact_type}' facts from FactDB: {res}",
                fact_type=fact_type,
                res=await res.text(),
            )
            res.raise_for_status()
        return res
