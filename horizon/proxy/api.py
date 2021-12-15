import aiohttp
from aiohttp.client import request

from fastapi import APIRouter, status, Request, HTTPException
from opal_client.utils import proxy_response

from horizon.config import sidecar_config


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

router = APIRouter()


@router.api_route("/cloud/{path:path}", methods=ALL_METHODS, summary="Proxy Endpoint")
async def cloud_proxy(request: Request, path: str):
    """
    Proxies the request to the cloud API. Actual API docs are located here: https://api.permit.io/redoc
    """
    return await proxy_request_to_cloud_service(request, path, cloud_service_url=sidecar_config.BACKEND_SERVICE_URL)


# TODO: remove this once we migrate all clients
@router.api_route("/sdk/{path:path}", methods=ALL_METHODS, summary="Old Proxy Endpoint", include_in_schema=False)
async def old_proxy(request: Request, path: str):
    return await proxy_request_to_cloud_service(request, path, cloud_service_url=sidecar_config.BACKEND_LEGACY_URL)


async def proxy_request_to_cloud_service(request: Request, path: str, cloud_service_url: str):
    auth_header = request.headers.get("Authorization")
    if auth_header is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Must provide a bearer token!",
            headers={"WWW-Authenticate": "Bearer"}
        )
    headers = dict(request.headers)
    path = f"{cloud_service_url}/{path}"
    params = dict(request.query_params) or {}

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
