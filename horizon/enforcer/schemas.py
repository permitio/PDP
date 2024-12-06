from __future__ import annotations

from typing import Any, Dict, Optional, List

from pydantic import BaseModel, Field, AnyHttpUrl, PositiveInt, PrivateAttr


class BaseSchema(BaseModel):
    class Config:
        orm_mode = True
        allow_population_by_field_name = True


class User(BaseSchema):
    key: str
    first_name: Optional[str] = Field(None, alias="firstName")
    last_name: Optional[str] = Field(None, alias="lastName")
    email: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = {}


class Resource(BaseSchema):
    type: str
    key: Optional[str] = None
    tenant: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = {}
    context: Optional[Dict[str, Any]] = {}


class AuthorizationQuery(BaseSchema):
    """
    the format of is_allowed() input
    """

    user: User
    action: str
    resource: Resource
    context: Optional[Dict[str, Any]] = {}
    sdk: Optional[str]

    def __repr__(self) -> str:
        return f"({self.user.key}, {self.action}, {self.resource.type})"


class BulkAuthorizationQuery(BaseSchema):
    checks: List[AuthorizationQuery]

    def __repr__(self) -> str:
        return " | ".join([repr(query) for query in self.checks])


class UrlAuthorizationQuery(BaseSchema):
    """
    the format of is_allowed_url() input
    """

    user: User
    http_method: str
    url: AnyHttpUrl
    tenant: str
    context: Optional[Dict[str, Any]] = {}
    sdk: Optional[str]


class UserTenantsQuery(BaseSchema):
    user: User
    context: Optional[dict[str, Any]] = {}


class UserPermissionsQuery(BaseSchema):
    user: User
    tenants: Optional[list[str]] = None
    resources: Optional[list[str]] = None
    resource_types: Optional[list[str]] = None
    context: Optional[dict[str, Any]] = {}
    _offset: Optional[PositiveInt] = PrivateAttr(None)
    _limit: Optional[PositiveInt] = PrivateAttr(None)

    def set_pagination(
        self, page: Optional[PositiveInt], per_page: Optional[PositiveInt]
    ) -> bool:
        if per_page:
            self._limit = per_page
            if page:
                self._offset = (page - 1) * per_page
            return True
        return False

    def get_params(self) -> dict:
        params = {}
        if self.tenants:
            params["tenants"] = self.tenants
        if self.resources:
            params["resource_instances"] = self.resources
        if self.resource_types:
            params["resource_types"] = self.resource_types
        if self._offset:
            params["offset"] = self._offset
        if self._limit:
            params["limit"] = self._limit

        return params


class AuthorizationResult(BaseSchema):
    allow: bool = False
    query: Optional[dict] = None
    debug: Optional[dict]
    result: bool = False  # fallback for older sdks (TODO: remove)


class BulkAuthorizationResult(BaseSchema):
    allow: List[AuthorizationResult] = []


class _TenantDetails(BaseSchema):
    key: str
    attributes: dict = {}


class _ResourceDetails(_TenantDetails):
    type: str


class _UserPermissionsResult(BaseSchema):
    tenant: Optional[_TenantDetails]
    resource: Optional[_ResourceDetails]
    permissions: list[str] = Field(..., regex="^.+:.+$")
    roles: Optional[list[str]] = None


UserPermissionsResult = dict[str, _UserPermissionsResult]
UserTenantsResult = list[_TenantDetails]


class _AllTenantsAuthorizationResult(AuthorizationResult):
    tenant: _TenantDetails


class AllTenantsAuthorizationResult(BaseSchema):
    allowed_tenants: List[_AllTenantsAuthorizationResult] = []


class MappingRuleData(BaseModel):
    url: str
    http_method: str
    resource: str
    action: str
    priority: int | None = None
    type: Optional[str] = None

    @property
    def resource_action(self) -> str:
        return self.action or self.http_method


class AuthorizedUserAssignment(BaseSchema):
    user: str = Field(..., description="The user that is authorized")
    tenant: str = Field(..., description="The tenant that the user is authorized for")
    resource: str = Field(
        ..., description="The resource that the user is authorized for"
    )
    role: str = Field(..., description="The role that the user is assigned to")


AuthorizedUsersDict = dict[str, list[AuthorizedUserAssignment]]


class AuthorizedUsersResult(BaseSchema):
    resource: str = Field(
        ...,
        description="The resource that the result is about."
        "Can be either 'resource:*' or 'resource:resource_instance'",
    )
    tenant: str = Field(..., description="The tenant that the result is about")
    users: AuthorizedUsersDict = Field(
        ...,
        description="A key value mapping of the users that are "
        "authorized for the resource."
        "The key is the user key and the value is a list of assignments allowing the user to perform"
        "the requested action",
    )

    @classmethod
    def empty(cls, resource: Resource) -> AuthorizedUsersResult:
        if resource.key is None:
            resource_key = "*"
        else:
            resource_key = resource.key
        return cls(
            resource=f"{resource.type}:{resource_key}",
            tenant=resource.tenant or "default",
            users={},
        )

    class Config:
        schema_extra = {
            "examples": [
                {
                    "resource": "repo:*",
                    "tenant": "default",
                    "users": {
                        "user1": [
                            {
                                "user": "user1",
                                "tenant": "default",
                                "resource": "__tenant:default",
                                "role": "admin",
                            }
                        ]
                    },
                },
                {
                    "resource": "repo:OPAL",
                    "tenant": "default",
                    "users": {
                        "user1": [
                            {
                                "user": "user1",
                                "tenant": "default",
                                "resource": "repo:OPAL",
                                "role": "admin",
                            },
                            {
                                "user": "user1",
                                "tenant": "default",
                                "resource": "__tenant:default",
                                "role": "admin",
                            },
                        ]
                    },
                },
            ]
        }


class AuthorizedUsersAuthorizationQuery(BaseSchema):
    """
    the format of authorized_users input
    """

    action: str
    resource: Resource
    context: Optional[Dict[str, Any]] = {}
    sdk: Optional[str]

    def __repr__(self) -> str:
        return f"({self.action}, {self.resource.type})"
