from typing import Annotated, cast

from fastapi import APIRouter, Depends, Query
from opal_client.policy_store.base_policy_store_client import BasePolicyStoreClient
from opal_client.policy_store.policy_store_client_factory import (
    DEFAULT_POLICY_STORE_GETTER,
)
from pydantic import parse_obj_as, parse_raw_as
from starlette.responses import Response

from horizon.authentication import enforce_pdp_token
from horizon.local.schemas import (
    ListRoleAssignmentsFilters,
    ListRoleAssignmentsPagination,
    ListRoleAssignmentsPDPBody,
    RoleAssignment,
    WrappedResponse,
)

PageQuery = Annotated[int, Query(ge=1, description="The page number (starts from 1).")]
PerPageQuery = Annotated[int, Query(ge=1, le=100, description="The number of results per page (max 100).")]


def init_local_cache_api_router(policy_store: BasePolicyStoreClient = None):
    policy_store = policy_store or DEFAULT_POLICY_STORE_GETTER()
    router = APIRouter(dependencies=[Depends(enforce_pdp_token)])

    @router.get(
        "/role_assignments",
        response_model=list[RoleAssignment],
    )
    async def list_role_assignments(
        user: Annotated[
            str | None,
            Query(
                description="optional user filter, will only return role assignments granted to this user.",
            ),
        ] = None,
        role: Annotated[
            str | None,
            Query(
                description="optional role filter, will only return role assignments granting this role.",
            ),
        ] = None,
        tenant: Annotated[
            str | None,
            Query(
                description="optional tenant filter, will only return role assignments granted in that tenant.",
            ),
        ] = None,
        resource: Annotated[
            str | None,
            Query(
                description="optional resource **type** filter, "
                "will only return role assignments granted on that resource type.",
            ),
        ] = None,
        resource_instance: Annotated[
            str | None,
            Query(
                description="optional resource instance filter, "
                "will only return role assignments granted on that resource instance.",
            ),
        ] = None,
        page: PageQuery = 1,
        per_page: PerPageQuery = 30,
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

        # the type hint of the get_data_with_input is incorrect, it claims it returns a dict but it
        # actually returns a Response
        result = cast(
            Response | dict,
            await policy_store.get_data_with_input(
                "/permit/api/role_assignments/list_role_assignments",
                ListRoleAssignmentsPDPBody.construct(filters=filters, pagination=pagination),
            ),
        )
        if isinstance(result, Response):
            return parse_raw_as(WrappedResponse, result.body).result
        else:
            return parse_obj_as(WrappedResponse, result).result

    return router
