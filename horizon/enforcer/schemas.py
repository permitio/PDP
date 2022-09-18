from typing import Any, Dict, List, Optional
from uuid import UUID

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


class KongAuthorizationInputRequestHttp(BaseSchema):
    host: str
    port: int
    tls: dict
    method: str
    scheme: str
    path: str
    querystring: Dict[str, str]
    headers: Dict[str, str]


class KongAuthorizationInputRequest(BaseSchema):
    http: KongAuthorizationInputRequestHttp


class KongAuthorizationInputService(BaseSchema):
    host: str
    created_at: int
    connect_timeout: int
    id: UUID
    procotol: str
    name: str
    read_timeout: int
    port: int
    updated_at: int
    ws_id: UUID
    retries: int
    write_timeout: int


class KongAuthorizationInputRouteService(BaseSchema):
    id: UUID


class KongAuthorizationInputRoute(BaseSchema):
    id: UUID
    paths: List[str]
    protocols: List[str]
    strip_path: bool
    created_at: int
    ws_id: UUID
    request_buffering: bool
    updated_at: int
    preserve_host: bool
    regex_priority: int
    response_buffering: bool
    https_redirect_status_code: int
    path_handling: str
    service: KongAuthorizationInputRouteService


class KongAuthorizationInputConsumer(BaseSchema):
    id: UUID
    username: str


class KongAuthorizationInput(BaseSchema):
    request: KongAuthorizationInputRequest
    client_ip: Optional[str]
    service: Optional[KongAuthorizationInputService]
    route: Optional[KongAuthorizationInputRoute]
    consumer: Optional[KongAuthorizationInputConsumer]


class KongAuthorizationQuery(BaseSchema):
    """
    the format of is_allowed_kong() input
    """

    input: KongAuthorizationInput


class KongAuthorizationResult(BaseSchema):
    result: bool = False
