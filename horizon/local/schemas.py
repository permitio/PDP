from typing import Any

from pydantic import BaseModel, Field


class BaseSchema(BaseModel):
    class Config:
        orm_mode = True


class Message(BaseModel):
    detail: str


class SyncedRole(BaseSchema):
    id: str
    name: str | None
    tenant_id: str | None
    metadata: dict[str, Any] | None
    permissions: list[str] | None


class SyncedUser(BaseSchema):
    id: str
    name: str | None
    email: str | None
    metadata: dict[str, Any] | None
    roles: list[SyncedRole]


class ListRoleAssignmentsFilters(BaseSchema):
    user: str | None = None
    role: str | None = None
    tenant: str | None = None
    resource: str | None = None
    resource_instance: str | None = None


class ListRoleAssignmentsPagination(BaseSchema):
    page: int = Field(1, ge=1, description="The page number to return")
    per_page: int = Field(10, ge=1, le=100, description="The number of items to return per page")


class ListRoleAssignmentsPDPBody(BaseSchema):
    filters: ListRoleAssignmentsFilters = Field(..., description="The filters to apply to the list")
    pagination: ListRoleAssignmentsPagination = Field(..., description="The pagination settings")


class RoleAssignment(BaseSchema):
    """
    The format of a role assignment
    """

    user: str = Field(..., description="the user the role is assigned to")
    role: str = Field(..., description="the role that is assigned")
    tenant: str = Field(..., description="the tenant the role is associated with")
    resource_instance: str | None = Field(None, description="the resource instance the role is associated with")

    class Config:
        schema_extra = {  # noqa: RUF012
            "example": [
                {
                    "user": "jane@coolcompany.com",
                    "role": "admin",
                    "tenant": "stripe-inc",
                },
                {
                    "user": "jane@coolcompany.com",
                    "role": "admin",
                    "tenant": "stripe-inc",
                    "resource_instance": "document:doc-1234",
                },
            ]
        }


class WrappedResponse(BaseSchema):
    result: list[RoleAssignment]
