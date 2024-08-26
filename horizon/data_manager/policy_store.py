from typing import Optional
from uuid import uuid4

from aiohttp import ClientSession
from loguru import logger
from opal_client.policy_store.opa_client import OpaClient
from opal_client.policy_store.schemas import PolicyStoreAuth
from opal_common.schemas.data import JsonableValue


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
        parts = path.lstrip("/").split("/")
        match parts:
            case ["relationships", obj]:
                for full_relation, targets in policy_data.items():
                    relation = full_relation.lstrip("relation:")
                    for target_type, target_objects in targets.items():
                        for target in target_objects:
                            await self._insert_fact(
                                "relationship_tuples",
                                {
                                    "id": uuid4(),
                                    "subject": f"{target_type}:{target}",
                                    "relation": relation,
                                    "object": obj,
                                },
                            )
            case ["role_assignments", full_user_key]:
                user_key = full_user_key.lstrip("user:")
                for subject, roles in policy_data.items():
                    subject_type, subject_key = subject.split(":", 1)
                    for role_key in roles:
                        if subject_type == "__tenant":
                            await self._insert_fact(
                                "role_assignments",
                                {
                                    "id": uuid4(),
                                    "actor": user_key,
                                    "tenant": subject_key,
                                    "role": role_key,
                                    "resource": "",
                                },
                            )
                        else:
                            await self._insert_fact(
                                "role_assignments",
                                {
                                    "id": uuid4(),
                                    "actor": user_key,
                                    "tenant": "",
                                    "role": role_key,
                                    "resource": subject,
                                },
                            )
            case ["users", user_key]:
                attributes = policy_data.get("attributes", {})
                return await self._insert_fact(
                    "users",
                    {
                        "id": user_key,
                        "attributes": attributes,
                    },
                )
            case ["resource_instances", instance_key]:
                return await self._insert_fact(
                    "resource_instance",
                    {
                        "id": instance_key,
                        "attributes": policy_data.get("attributes", {}),
                    },
                )
            case _:
                return await super().set_policy_data(
                    policy_data=policy_data, path=path, transaction_id=transaction_id
                )

    async def _insert_fact(self, fact_type: str, attributes: dict[str, str]):
        try:
            res = await self._client.post(
                "/facts/insert",
                json={
                    "type": fact_type,
                    "attributes": attributes,
                },
            )
            if res.status != 200:
                error = await res.text()
                logger.error(f"Failed to insert fact: {res.status}\n{error}")
            return res
        except Exception as e:
            logger.exception(f"Failed to insert fact: {e}")

    async def delete_policy_data(
        self, path: str = "", transaction_id: Optional[str] = None
    ):
        # TODO forward relevant objects to data manager instead of OPA
        return super().delete_policy_data(path=path, transaction_id=transaction_id)
