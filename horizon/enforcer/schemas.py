from __future__ import annotations

import functools
import types
import typing
from enum import StrEnum
from typing import Annotated, Any

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    SerializationInfo,
    SerializerFunctionWrapHandler,
    StringConstraints,
    ValidationInfo,
    WithJsonSchema,
    field_serializer,
    field_validator,
)
from pydantic.v1 import AnyHttpUrl as _V1AnyHttpUrl
from pydantic.v1 import ValidationError as _V1ValidationError
from pydantic.v1 import parse_obj_as as _v1_parse


def _check_http_url(url: str) -> str:
    # pydantic 1's own AnyHttpUrl, from the pydantic.v1 package pydantic 2 still ships, so
    # /allowed_url accepts, rejects and rewrites exactly what it did on pydantic 1: it strips the
    # string, rejects a backslash, an empty host or port and invalid host labels, IDNA-encodes
    # only the host, and drops an empty `?` or `#`. pydantic 2's AnyHttpUrl parses WHATWG-style
    # and repairs some of those, so the URL that passed would not be the one MappingRulesUtils
    # matches. Compared input by input with pydantic 1.10.26 (test_pydantic2_compat.py).
    # pydantic.v1 goes away in pydantic 3: replace this with an equivalent check before that.
    try:
        return str(_v1_parse(_V1AnyHttpUrl, url))
    except _V1ValidationError as e:
        raise ValueError(f"invalid URL: {e.errors()[0]['msg']}") from None


# A str in the model and in the OPA input, documented as pydantic 1 documented it.
HttpUrlStr = Annotated[
    str,
    AfterValidator(_check_http_url),
    WithJsonSchema({"type": "string", "format": "uri", "minLength": 1, "maxLength": 65536}),
]


def _arms(annotation: Any) -> list[Any]:
    """The types a field annotation accepts, with Optional/Union/Annotated unwrapped."""
    origin = typing.get_origin(annotation)
    if origin is Annotated:
        return _arms(typing.get_args(annotation)[0])
    if origin in (typing.Union, types.UnionType):
        return [arm for arg in typing.get_args(annotation) for arm in _arms(arg)]
    return [annotation]


@functools.cache
def _coercion_plan(annotation: Any) -> tuple[bool, bool, bool, bool, bool]:
    """Which pydantic 1 coercions apply to a field, worked out once per annotation: (bool -> str,
    fractional float -> int, list -> dict, bool values of a dict[..., str] -> str, bool items of a
    list[str] -> str)."""
    arms = _arms(annotation)
    plain = {arm for arm in arms if isinstance(arm, type)}
    dicts = [arm for arm in arms if arm is dict or typing.get_origin(arm) is dict]
    lists = [arm for arm in arms if typing.get_origin(arm) is list]
    return (
        str in plain and bool not in plain,
        int in plain and float not in plain,
        bool(dicts),
        any(typing.get_args(arm)[1:] == (str,) for arm in dicts),
        any(typing.get_args(arm) == (str,) for arm in lists),
    )


def _bool_in_str_field(value: Any, plan: tuple[bool, ...]) -> Any:
    # pydantic 1 gave "True"/"False"; pydantic 2 answers 422.
    return str(value) if plan[0] else value


def _fractional_float_in_int_field(value: float, plan: tuple[bool, ...]) -> Any:
    # pydantic 1 truncated; pydantic 2 rejects a fractional float for an int.
    return int(value) if plan[1] and not value.is_integer() else value


def _list_in_dict_field(value: list, plan: tuple[bool, ...]) -> Any:
    # A list[str] field: pydantic 1 coerced each item like a str field ([true] -> ["True"]).
    if plan[4]:
        return [str(v) if isinstance(v, bool) else v for v in value]
    # pydantic 1 ran dict(value): [] -> {} (an empty map some JSON encoders write as an array) and
    # a list of pairs -> a dict. Anything dict() refuses is left to fail.
    if not plan[2]:
        return value
    try:
        return dict(value)
    except (TypeError, ValueError):
        return value


def _bools_in_str_dict(value: dict, plan: tuple[bool, ...]) -> Any:
    # dict[..., str]: pydantic 1 coerced each value like a str field (Kong's querystring holds
    # `true` for a flag parameter with no value).
    return {k: str(v) if isinstance(v, bool) else v for k, v in value.items()} if plan[3] else value


_COERCIONS: dict[type, Any] = {
    bool: _bool_in_str_field,
    float: _fractional_float_in_int_field,
    list: _list_in_dict_field,
    dict: _bools_in_str_dict,
}


def _pydantic1_coercion(value: Any, annotation: Any) -> Any:
    """What pydantic 1 accepted for a field and pydantic 2's lax mode does not."""
    coerce = _COERCIONS.get(type(value))  # None for the common case: str, int, None
    return value if coerce is None else coerce(value, _coercion_plan(annotation))


def _drop_none(value: Any) -> Any:
    # FastAPI's jsonable_encoder(exclude_none=True), which pydantic 1 responses went through:
    # None-valued keys go from every dict, at any depth; list items are kept (and recursed into).
    if isinstance(value, dict):
        return {k: _drop_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_none(v) for v in value]
    return value


class Pydantic1Compat(BaseModel):
    """Keeps what callers and OPA saw from these models on pydantic 1 (PER-16197)."""

    # coerce_numbers_to_str: pydantic 1 accepted a number for a str field ({"key": 1} -> "1");
    # pydantic 2 rejects it with a 422 unless told otherwise. SDKs and integrations that send
    # numeric user or resource keys keep working.
    model_config = ConfigDict(coerce_numbers_to_str=True)

    @field_validator("*", mode="before")
    @classmethod
    def _accept_what_pydantic1_accepted(cls, value: Any, info: ValidationInfo) -> Any:
        # The rest of pydantic 1's coercions on the request and OPA-result models: see
        # _pydantic1_coercion. Before-validators do not change the JSON schema.
        if info.field_name is None:
            return value
        return _pydantic1_coercion(value, cls.model_fields[info.field_name].annotation)

    @field_serializer("*", mode="wrap")
    def _exclude_none_inside_dicts(self, value: Any, handler: SerializerFunctionWrapHandler, info: SerializationInfo):
        # response_model_exclude_none used to drop nulls inside dict fields too (debug, query,
        # attributes): FastAPI encoded pydantic 1 responses with jsonable_encoder. On pydantic 2 it
        # serializes through pydantic, which drops only None model fields. PER-16197.
        out = handler(value)
        return _drop_none(out) if info.exclude_none and isinstance(out, dict | list) else out


class BaseSchema(Pydantic1Compat):
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
