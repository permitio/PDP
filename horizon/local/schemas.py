from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class BaseSchema(BaseModel):
    class Config:
        orm_mode = True


class Message(BaseModel):
    detail: str


class SyncedRole(BaseSchema):
    id: str
    name: Optional[str]
    tenant_id: Optional[str]
    metadata: Optional[Dict[str, Any]]
    permissions: Optional[List[str]]


class SyncedUser(BaseSchema):
    id: str
    name: Optional[str]
    email: Optional[str]
    metadata: Optional[Dict[str, Any]]
    roles: List[SyncedRole]
