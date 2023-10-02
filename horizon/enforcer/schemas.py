from typing import Any, Dict, Optional, List, cast

from pydantic import BaseModel, Field, AnyHttpUrl, validator


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


class UserPermissionsQuery(BaseSchema):
    user: User
    tenants: Optional[list[str]] = Field(None, exclude=True)
    resources: Optional[list[str]] = None
    resource_types: Optional[list[str]] = None
    context: Optional[dict[str, Any]] = {}

    @validator("resources", always=True)
    def add_tenants_to_resources(
        cls, v: Optional[list[str]], values: dict
    ) -> Optional[list[str]]:
        tenants = cast(Optional[list[str]], values.get("tenants"))
        if v is None and tenants is None:
            return v
        full_qualified_tenants = [f"__tenant:{tenant}" for tenant in tenants]

        return (v or []) + full_qualified_tenants


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


class _UserPermissionsResult(BaseSchema):
    tenant: _TenantDetails
    permissions: list[str] = Field(..., regex="^.+:.+$")


UserPermissionsResult = dict[str, _UserPermissionsResult]


class _AllTenantsAuthorizationResult(AuthorizationResult):
    tenant: _TenantDetails


class AllTenantsAuthorizationResult(BaseSchema):
    allowed_tenants: List[_AllTenantsAuthorizationResult] = []


class MappingRuleData(BaseSchema):
    url: AnyHttpUrl
    http_method: str
    resource: str
    action: str
    priority: int | None = None

    @property
    def resource_action(self) -> str:
        return self.action or self.http_method
