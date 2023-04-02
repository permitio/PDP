from typing import Any, Dict, Optional

from horizon.enforcer.schemas import BaseSchema


class BaseSchemaV1(BaseSchema):
    class Config:
        schema_extra = {"deprecated": True}


class ResourceV1(BaseSchemaV1):
    type: str
    id: Optional[str] = None
    tenant: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None
    context: Optional[Dict[str, Any]] = {}


class AuthorizationQueryV1(BaseSchema):
    """
    the format of is_allowed() input
    """

    user: str  # user_id or jwt
    action: str
    resource: ResourceV1
    context: Optional[Dict[str, Any]] = {}
