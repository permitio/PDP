from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


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


class AuthorizationResult(BaseSchema):
    allow: bool = False
    query: Optional[dict]
    debug: Optional[dict]
    result: bool = False  # fallback for older sdks (TODO: remove)
