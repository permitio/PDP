from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, AnyHttpUrl


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


class AuthorizationResult(BaseSchema):
    allow: bool = False
    query: Optional[dict]
    debug: Optional[dict]
    result: bool = False  # fallback for older sdks (TODO: remove)


class MappingRuleData(BaseSchema):
    url: AnyHttpUrl
    http_method: str
    resource: str
    action: str
    priority: int | None = None

    @property
    def resource_action(self) -> str:
        return self.action or self.http_method
