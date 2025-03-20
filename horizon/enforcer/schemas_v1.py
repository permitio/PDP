from typing import Any

from pydantic import Field

from horizon.enforcer.schemas import BaseSchema


class BaseSchemaV1(BaseSchema):
    class Config:
        schema_extra = {"deprecated": True}  # noqa: RUF012


class ResourceV1(BaseSchemaV1):
    type: str
    id: str | None = None
    tenant: str | None = None
    attributes: dict[str, Any] | None = None
    context: dict[str, Any] | None = Field(default_factory=dict)


class AuthorizationQueryV1(BaseSchema):
    """
    the format of is_allowed() input
    """

    user: str  # user_id or jwt
    action: str
    resource: ResourceV1
    context: dict[str, Any] | None = Field(default_factory=dict)
