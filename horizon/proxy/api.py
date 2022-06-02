from typing import Dict

import aiohttp
from urllib.parse import urlparse

from fastapi import APIRouter, status, Request, HTTPException, Response
from opal_client.utils import proxy_response
from opal_common.logger import logger
from opal_client.config import OpalClientConfig, opal_client_config
from pydantic import parse_raw_as

from horizon.config import sidecar_config

from horizon.enforcer.schemas import UserRoles

HTTP_GET = "GET"
HTTP_DELETE = "DELETE"
HTTP_POST = "POST"
HTTP_PUT = "PUT"
HTTP_PATCH = "PATCH"


ALL_METHODS = [
    HTTP_GET,
    HTTP_DELETE,
    HTTP_POST,
    HTTP_PUT,
    HTTP_PATCH,
]

REQUIRED_HTTP_HEADERS = {"authorization", "content-type"}

router = APIRouter()


async def sync_user_handler(response: Response):
    store = OpalClientConfig.load_policy_store()
    user_roles = parse_raw_as(Dict[str, UserRoles], response.body)

    for id, role in user_roles.items():
        await store.set_policy_data(role.dict(), f"/user_roles/{id}")


special_handlers = {
    ("PUT", "users", sync_user_handler)
}


@router.api_route("/cloud/{path:path}", methods=ALL_METHODS, summary="Proxy Endpoint")
async def cloud_proxy(request: Request, path: str):
    """
    Proxies the request to the cloud API. Actual API docs are located here: https://api.permit.io/redoc
    """
    response = await proxy_request_to_cloud_service(request, path, cloud_service_url=sidecar_config.BACKEND_SERVICE_URL)

    for handler in special_handlers:
        if request.method == handler[0] and request.path_params["path"] == handler[1]:
            await handler[2](response)


# TODO: remove this once we migrate all clients
@router.api_route("/sdk/{path:path}", methods=ALL_METHODS, summary="Old Proxy Endpoint", include_in_schema=False)
async def old_proxy(request: Request, path: str):
    return await proxy_request_to_cloud_service(request, path, cloud_service_url=sidecar_config.BACKEND_LEGACY_URL)


async def proxy_request_to_cloud_service(request: Request, path: str, cloud_service_url: str) -> Response:
    auth_header = request.headers.get("Authorization")
    if auth_header is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Must provide a bearer token!",
            headers={"WWW-Authenticate": "Bearer"}
        )
    path = f"{cloud_service_url}/{path}"
    params = dict(request.query_params) or {}
    params['emit_data_change'] = '1'

    original_headers = {k.lower(): v for k,v in iter(dict(request.headers).items())}
    headers = {}

    # copy only required header
    for header_name in REQUIRED_HTTP_HEADERS:
        if header_name in original_headers.keys():
            headers[header_name] = original_headers[header_name]

    # override host header (required by k8s ingress)
    try:
        headers["host"] = urlparse(cloud_service_url).netloc
    except Exception as e:
        # fallback
        logger.error(f"could not urlparse cloud service url: {cloud_service_url}, exception: {e}")

    logger.info(f"Proxying request: {request.method} {path}")

    async with aiohttp.ClientSession() as session:
        if request.method == HTTP_GET:
            async with session.get(path, headers=headers, params=params) as backend_response:
                return await proxy_response(backend_response)

        if request.method == HTTP_DELETE:
            async with session.delete(path, headers=headers, params=params) as backend_response:
                return await proxy_response(backend_response)

        # these methods has data payload
        data = await request.body()

        if request.method == HTTP_POST:
            async with session.post(path, headers=headers, data=data, params=params) as backend_response:
                return await proxy_response(backend_response)

        if request.method == HTTP_PUT:
            async with session.put(path, headers=headers, data=data, params=params) as backend_response:
                return await proxy_response(backend_response)

        if request.method == HTTP_PATCH:
            async with session.patch(path, headers=headers, data=data, params=params) as backend_response:
                return await proxy_response(backend_response)

    raise HTTPException(
        status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
        detail="This method is not supported"
    )
