from typing import Any, Dict, Optional

from pydantic import Field

from horizon.enforcer.schemas import BaseSchema


class BaseSchemaV2(BaseSchema):
    class Config:
        schema_extra = {"deprecated": True}


class UserV2(BaseSchemaV2):
    key: str
    first_name: Optional[str] = Field(None, alias="firstName")
    last_name: Optional[str] = Field(None, alias="lastName")
    email: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = {}


class ResourceV2(BaseSchemaV2):
    type: str
    key: Optional[str] = None
    tenant: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = {}
    context: Optional[Dict[str, Any]] = {}


class AuthorizationQueryV2(BaseSchemaV2):
    """
    the format of is_allowed() input
    """

    user: UserV2
    action: str
    resource: ResourceV2
    context: Optional[Dict[str, Any]] = {}
    sdk: Optional[str]
