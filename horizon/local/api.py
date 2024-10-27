from typing import Any, Dict, List, Optional, cast

from fastapi import APIRouter, Depends, HTTPException, status, Query
from loguru import logger
from opal_client.policy_store.base_policy_store_client import BasePolicyStoreClient
from opal_client.policy_store.policy_store_client_factory import (
    DEFAULT_POLICY_STORE_GETTER,
)
from pydantic import parse_raw_as, parse_obj_as
from starlette.responses import Response

from horizon.authentication import enforce_pdp_token
from horizon.config import sidecar_config
from horizon.data_manager.policy_store import DataManagerPolicyStoreClient
from horizon.local.schemas import (
    Message,
    SyncedRole,
    RoleAssignment,
    ListRoleAssignmentsFilters,
    ListRoleAssignmentsPDPBody,
    WrappedResponse,
    ListRoleAssignmentsPagination,
)


def init_local_cache_api_router(policy_store: BasePolicyStoreClient = None):
    policy_store = policy_store or DEFAULT_POLICY_STORE_GETTER()
    router = APIRouter(dependencies=[Depends(enforce_pdp_token)])

    def error_message(msg: str):
        return {
            "model": Message,
            "description": msg,
        }

    async def get_grants_for_role(role_name: str) -> List[str]:
        response = (await policy_store.get_data(f"/roles/{role_name}")).get("result")

        if not response:
            return []

        grants = response.get("grants", {})
        result = []

        for resource_name, actions in grants.items():
            for action in actions:
                result.append(f"{resource_name}:{action}")

        return result

    async def get_roles_for_user(opa_user: Dict[str, Any]) -> List[SyncedRole]:
        role_assignments = opa_user.get("roleAssignments", {})
        roles_grants = {}
        result = []

        for tenant_name, roles in role_assignments.items():
            for role in roles:
                grants = roles_grants.get(role)

                if not grants:
                    grants = await get_grants_for_role(role)
                    roles_grants[role] = grants

                result.append(
                    SyncedRole(id=role, tenant_id=tenant_name, permissions=grants)
                )

        return result

    async def get_data_for_synced_user(user_id: str) -> Dict[str, Any]:
        response = await policy_store.get_data(f"/users/{user_id}")
        result = response.get("result", None)
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"user with id '{user_id}' was not found in OPA cache! (not synced)",
            )
        return result

    def permission_shortname(permission: Dict[str, Any]) -> Optional[str]:
        resource = permission.get("resource", {}).get("type", None)
        action = permission.get("action", None)

        if resource is None or action is None:
            return None
        return f"{resource}:{action}"

    @router.get(
        "/role_assignments",
        response_model=list[RoleAssignment],
    )
    async def list_role_assignments(
        user: Optional[str] = Query(
            None,
            description="optional user filter, "
            "will only return role assignments granted to this user.",
        ),
        role: Optional[str] = Query(
            None,
            description="optional role filter, "
            "will only return role assignments granting this role.",
        ),
        tenant: Optional[str] = Query(
            None,
            description="optional tenant filter, "
            "will only return role assignments granted in that tenant.",
        ),
        resource: Optional[str] = Query(
            None,
            description="optional resource **type** filter, "
            "will only return role assignments granted on that resource type.",
        ),
        resource_instance: Optional[str] = Query(
            None,
            description="optional resource instance filter, "
            "will only return role assignments granted on that resource instance.",
        ),
        page: int = Query(
            default=1,
            ge=1,
            description="Page number of the results to fetch, starting at 1.",
        ),
        per_page: int = Query(
            default=30,
            ge=1,
            le=100,
            description="The number of results per page (max 100).",
        ),
    ) -> list[RoleAssignment]:
        """
        Get all role assignments stored in the PDP.

        You can filter the results by providing optional filters.
        """
        filters = ListRoleAssignmentsFilters.construct(
            user=user,
            role=role,
            tenant=tenant,
            resource=resource,
            resource_instance=resource_instance,
        ).dict(exclude_none=True)
        pagination = ListRoleAssignmentsPagination.construct(
            page=page,
            per_page=per_page,
        )

        async def legacy_list_role_assignments() -> list[RoleAssignment]:
            # the type hint of the get_data_with_input is incorrect, it claims it returns a dict but it
            # actually returns a Response
            result = cast(
                Response | Dict,
                await policy_store.get_data_with_input(
                    "/permit/api/role_assignments/list_role_assignments",
                    ListRoleAssignmentsPDPBody.construct(
                        filters=filters, pagination=pagination
                    ),
                ),
            )
            if isinstance(result, Response):
                return parse_raw_as(WrappedResponse, result.body).result
            else:
                return parse_obj_as(WrappedResponse, result).result

        if sidecar_config.ENABLE_EXTERNAL_DATA_MANAGER:
            if not isinstance(policy_store, DataManagerPolicyStoreClient):
                logger.warning(
                    "External Data Manager is enabled by policy store is not set to {store_type}",
                    store_type=DataManagerPolicyStoreClient.__name__,
                )
                return await legacy_list_role_assignments()
            else:
                res = await policy_store.list_facts_by_type("role_assignments")
                return parse_obj_as(list[RoleAssignment], await res.json())
        else:
            return await legacy_list_role_assignments()

    return router
