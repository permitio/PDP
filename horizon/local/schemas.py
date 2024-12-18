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


class FactDBFact(BaseSchema):
    type: str
    attributes: dict[str, Any]


class RoleAssignmentFactDBFact(FactDBFact):
    @property
    def user(self) -> str:
        return self.attributes.get("actor", "").removeprefix("user:")

    @property
    def role(self) -> str:
        return self.attributes.get("role", "")

    @property
    def tenant(self) -> str:
        return self.attributes.get("tenant", "")

    @property
    def resource_instance(self) -> str:
        return self.attributes.get("resource", "")

    def into_role_assignment(self) -> RoleAssignment:
        return RoleAssignment(
            user=self.user,
            role=self.role,
            tenant=self.tenant,
            resource_instance=self.resource_instance,
        )

    class Config:
        schema_extra = {  # noqa: RUF012
            "example": {
                "type": "role_assignments",
                "attributes": {
                    "actor": "user:author-user",
                    "id": "user:author-user-author-document:doc-1",
                    "last_modified": "2024-09-23 09:10:10 +0000 UTC",
                    "resource": "document:doc-1",
                    "role": "author",
                    "tenant": "default",
                },
            }
        }
