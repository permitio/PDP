from typing import Dict, List, Optional
from uuid import UUID

from .schemas import BaseSchema


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
