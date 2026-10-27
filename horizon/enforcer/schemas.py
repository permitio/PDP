from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any

from pydantic import AfterValidator, AnyHttpUrl, BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter

_ANY_HTTP_URL = TypeAdapter(AnyHttpUrl)


def _check_http_url(url: str) -> str:
    # Validates like pydantic 1's AnyHttpUrl but keeps the caller's string. pydantic 2 would return a
    # Url object and normalize it (e.g. "http://h" -> "http://h/"), which changes what URL mapping
    # rules match against. pydantic 1's AnyHttpUrl stripped surrounding whitespace, so this does too.
    url = url.strip()
    _ANY_HTTP_URL.validate_python(url)
    return url


HttpUrlStr = Annotated[str, AfterValidator(_check_http_url)]


class BaseSchema(BaseModel):
    # coerce_numbers_to_str: pydantic 1 accepted a number for a str field ({"key": 1} -> "1");
    # pydantic 2 rejects it with a 422 unless told otherwise. SDKs and integrations that send
    # numeric user or resource keys keep working (PER-16197).
    model_config = ConfigDict(from_attributes=True, populate_by_name=True, coerce_numbers_to_str=True)


class User(BaseSchema):
    key: str
    first_name: str | None = Field(None, alias="firstName")
    last_name: str | None = Field(None, alias="lastName")
    email: str | None = None
    attributes: dict[str, Any] | None = Field(default_factory=dict)


class Resource(BaseSchema):
    type: str
    key: str | None = None
    tenant: str | None = None
    attributes: dict[str, Any] | None = Field(default_factory=dict)
    context: dict[str, Any] | None = Field(default_factory=dict)


class AuthorizationQuery(BaseSchema):
    """
    the format of is_allowed() input
    """

    user: User
    action: str
    resource: Resource
    context: dict[str, Any] | None = Field(default_factory=dict)
    sdk: str | None = None

    def __repr__(self) -> str:
        return f"({self.user.key}, {self.action}, {self.resource.type})"


class BulkAuthorizationQuery(BaseSchema):
    checks: list[AuthorizationQuery]

    def __repr__(self) -> str:
        return " | ".join([repr(query) for query in self.checks])


class UrlTypes(StrEnum):
    """Enum for URL matching types"""

    DEFAULT = "default"
    REGEX = "regex"


class UrlAuthorizationQuery(BaseSchema):
    """
    the format of is_allowed_url() input
    """

    user: User
    http_method: str
    url: HttpUrlStr
    tenant: str
    context: dict[str, Any] | None = Field(default_factory=dict)
    sdk: str | None = None


class UserTenantsQuery(BaseSchema):
    user: User
    context: dict[str, Any] | None = Field(default_factory=dict)


class UserPermissionsQuery(BaseSchema):
    user: User
    tenants: list[str] | None = None
    resources: list[str] | None = None
    resource_types: list[str] | None = None
    context: dict[str, Any] | None = Field(default_factory=dict)


class AuthorizationResult(BaseSchema):
    allow: bool = False
    query: dict | None = None
    debug: dict | None = None
    result: bool = False  # fallback for older sdks (TODO: remove)


class BulkAuthorizationResult(BaseSchema):
    allow: list[AuthorizationResult] = []


class _TenantDetails(BaseSchema):
    key: str
    attributes: dict = {}


class _ResourceDetails(_TenantDetails):
    type: str


class _UserPermissionsResult(BaseSchema):
    tenant: _TenantDetails | None = None
    resource: _ResourceDetails | None = None
    # Per item, as pydantic 1 applied Field(regex=) on a list[str]. pydantic 2 cannot apply `pattern`
    # to a list: it raises on every non-empty value.
    permissions: list[Annotated[str, StringConstraints(pattern="^.+:.+$")]] = Field(default_factory=list)
    roles: list[str] | None = None


UserPermissionsResult = dict[str, _UserPermissionsResult]
UserTenantsResult = list[_TenantDetails]


class _AllTenantsAuthorizationResult(AuthorizationResult):
    tenant: _TenantDetails


class AllTenantsAuthorizationResult(BaseSchema):
    allowed_tenants: list[_AllTenantsAuthorizationResult] = []


class MappingRuleData(BaseSchema):
    url: str
    http_method: str
    resource: str
    action: str
    priority: int | None = None
    url_type: UrlTypes = UrlTypes.DEFAULT

    @property
    def resource_action(self) -> str:
        return self.action or self.http_method


class AuthorizedUserAssignment(BaseSchema):
    user: str = Field(..., description="The user that is authorized")
    tenant: str = Field(..., description="The tenant that the user is authorized for")
    resource: str = Field(..., description="The resource that the user is authorized for")
    role: str = Field(..., description="The role that the user is assigned to")


AuthorizedUsersDict = dict[str, list[AuthorizedUserAssignment]]


class AuthorizedUsersResult(BaseSchema):
    resource: str = Field(
        ...,
        description="The resource that the result is about. Can be either 'resource:*' or 'resource:resource_instance'",
    )
    tenant: str = Field(..., description="The tenant that the result is about")
    users: AuthorizedUsersDict = Field(
        ...,
        description="A key value mapping of the users that are "
        "authorized for the resource. "
        "The key is the user key and the value is a list of assignments allowing the user to perform "
        "the requested action",
    )

    @classmethod
    def empty(cls, resource: Resource) -> AuthorizedUsersResult:
        resource_key = "*" if resource.key is None else resource.key
        return cls(
            resource=f"{resource.type}:{resource_key}",
            tenant=resource.tenant or "default",
            users={},
        )

    model_config = ConfigDict(
        json_schema_extra={
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
    )


class AuthorizedUsersAuthorizationQuery(BaseSchema):
    """
    the format of authorized_users input
    """

    action: str
    resource: Resource
    context: dict[str, Any] | None = Field(default_factory=dict)
    sdk: str | None = None

    def __repr__(self) -> str:
        return f"({self.action}, {self.resource.type})"
