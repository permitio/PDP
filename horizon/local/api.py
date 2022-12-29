from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from opal_client.policy_store.base_policy_store_client import BasePolicyStoreClient
from opal_client.policy_store.policy_store_client_factory import (
    DEFAULT_POLICY_STORE_GETTER,
)

from horizon.authentication import enforce_pdp_token
from horizon.local.schemas import Message, SyncedRole, SyncedUser


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
        "/users/{user_id}",
        response_model=SyncedUser,
        responses={
            404: error_message(
                "User not found (i.e: not synced to Authorization service)"
            ),
        },
    )
    async def get_user(user_id: str):
        """
        Get user data directly from OPA cache.

        If user does not exist in OPA cache (i.e: not synced), returns 404.
        """
        result = await get_data_for_synced_user(user_id)

        user = SyncedUser(
            id=user_id,
            email=result.get("attributes", {}).get("email"),
            name=result.get("attributes", {}).get("name"),
            metadata=result.get("metadata", {}),
            roles=await get_roles_for_user(result),
        )
        return user

    @router.get(
        "/users",
        response_model=List[SyncedUser],
        responses={
            404: error_message("OPA has no users stored in cache"),
        },
    )
    async def list_users():
        """
        Get all users stored in OPA cache.

        Be advised, if you have many (i.e: few hundreds or more) users this query might be expensive latency-wise.
        """
        response = await policy_store.get_data(f"/users")
        result = response.get("result", None)

        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"OPA has no users stored in cache! Did you synced users yet via the sdk or the cloud console?",
            )

        users = []

        for user_id, user_data in iter(result.items()):
            users.append(
                SyncedUser(
                    id=user_id,
                    email=user_data.get("attributes", {}).get("email"),
                    name=user_data.get("attributes", {}).get("name"),
                    metadata=user_data.get("metadata", {}),
                    roles=await get_roles_for_user(user_data),
                )
            )
        return users

    @router.get(
        "/users/{user_id}/permissions",
        response_model=Dict[str, List[str]],
        responses={
            404: error_message(
                "User not found (i.e: not synced to Authorization service)"
            ),
        },
    )
    async def get_user_permissions(user_id: str):
        """
        Get roles **assigned to user** directly from OPA cache.

        If user does not exist in OPA cache (i.e: not synced), returns 404.
        """
        result = await get_data_for_synced_user(user_id)
        roles = await get_roles_for_user(result)

        permissions: Dict[str, List[str]] = {}

        for role in roles:
            if role.tenant_id not in permissions:
                permissions[role.tenant_id] = []
            permissions[role.tenant_id].extend(role.permissions)

        return permissions

    @router.get(
        "/users/{user_id}/roles",
        response_model=List[SyncedRole],
        responses={
            404: error_message(
                "User not found (i.e: not synced to Authorization service)"
            ),
        },
    )
    async def get_user_roles(user_id: str):
        """
        Get roles **assigned to user** directly from OPA cache.

        If user does not exist in OPA cache (i.e: not synced), returns 404.
        """
        result = await get_data_for_synced_user(user_id)
        return await get_roles_for_user(result)

    @router.get(
        "/users/{user_id}/tenants",
        response_model=List[str],
        responses={
            404: error_message(
                "User not found (i.e: not synced to Authorization service)"
            ),
        },
    )
    async def get_user_tenants(user_id: str):
        """
        Get tenants **assigned to user** directly from OPA cache.
        This endpoint only returns tenants that the user **has an assigned role in**.
        i.e: if the user is assigned to tenant "tenant1" but has no roles in that tenant,
        "tenant1" will not be returned by this endpoint.

        If user does not exist in OPA cache (i.e: not synced), returns 404.
        """
        result = await get_data_for_synced_user(user_id)
        tenants = result.get("roleAssignments", {})
        tenants = [k for k in tenants.keys() if tenants[k]]
        return tenants

    @router.get(
        "/roles",
        response_model=List[SyncedRole],
        responses={
            404: error_message("OPA has no roles stored in cache"),
        },
    )
    async def list_roles():
        """
        Get all roles stored in OPA cache.
        """
        response = await policy_store.get_data(f"/roles")

        result = response.get("result", None)
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"OPA has no roles stored in cache! Did you define roles yet via the sdk or the cloud console?",
            )

        roles = []

        for role_id, role_data in iter(result.items()):
            permissions = []

            for resource, actions in role_data.get("grants", {}).items():
                for action in actions:
                    permissions.append(f"{resource}:{action}")

            roles.append(
                SyncedRole(
                    id=role_id,
                    name=role_data.get("name"),
                    metadata=role_data.get("metadata", {}),
                    permissions=permissions,
                )
            )
        return roles

    @router.get(
        "/roles/{role_id}",
        response_model=SyncedRole,
        responses={
            404: error_message("Role not found"),
        },
    )
    async def get_role_by_id(role_id: str):
        """
        Get role (by the role id) directly from OPA cache.

        If role is not found, returns 404.
        Possible reasons are either:

        - role was never created via SDK or via the cloud console.
        - role was (very) recently created and the policy update did not propagate yet.
        """
        response = await policy_store.get_data(f"/roles/{role_id}")

        result = response.get("result", None)
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
            )

        permissions = []

        for resource, actions in result.get("grants", {}).items():
            for action in actions:
                permissions.append(f"{resource}:{action}")

        return SyncedRole(
            id=role_id,
            name=result.get("name"),
            metadata=result.get("metadata", {}),
            permissions=permissions,
        )

    @router.get(
        "/roles/by-name/{role_name}",
        response_model=SyncedRole,
        responses={
            404: error_message("Role not found"),
        },
    )
    async def get_role_by_name(role_name: str):
        """
        Get role (by the role name - case sensitive) directly from OPA cache.

        If role is not found, returns 404.
        Possible reasons are either:

        - role with such name was never created via SDK or via the cloud console.
        - role was (very) recently created and the policy update did not propagate yet.
        """
        response = await policy_store.get_data(f"/role_permissions")
        result = response.get("result", None)
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"OPA has no roles stored in cache!",
            )
        for role_id, role_data in iter(result.items()):
            name = role_data.get("name")
            if name is None or name != role_name:
                continue
            permissions = [
                permission_shortname(p) for p in role_data.get("permissions", [])
            ]
            permissions = [p for p in permissions if p is not None]
            return SyncedRole(
                id=role_id,
                name=name,
                metadata=role_data.get("metadata", {}),
                permissions=permissions,
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No such role in OPA cache!"
        )

    return router
