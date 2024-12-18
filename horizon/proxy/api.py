import json
import re
from typing import Any
from urllib.parse import urlparse

import aiohttp
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from opal_client.config import OpalClientConfig, opal_client_config
from opal_client.utils import proxy_response
from opal_common.logger import logger
from pydantic import BaseModel, Field, parse_obj_as

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

REQUIRED_HTTP_HEADERS = {"authorization", "content-type"}


class JSONPatchAction(BaseModel):
    """
    Abstract base class for JSON patch actions (RFC 6902)
    """

    op: str = Field(..., description="patch action to perform")
    path: str = Field(..., description="target location in modified json")
    value: dict[str, Any] | None = Field(None, description="json document, the operand of the action")


router = APIRouter()


async def patch_handler(response: Response) -> Response:
    """
    Handle write APIs (from the SDK) where OpalClient will have to be manually updated from sidecar.
    """
    if not status.HTTP_200_OK <= response.status_code < status.HTTP_400_BAD_REQUEST:
        return response

    response_json = json.loads(response.body)

    if "patch" not in response_json:
        return response

    patch_json = response_json["patch"]

    try:
        store = OpalClientConfig.load_policy_store()

        patch = parse_obj_as(list[JSONPatchAction], patch_json)
        await store.patch_data("", patch)
    except Exception as ex:  # noqa: BLE001
        logger.exception("Failed to update OPAL store with: {err}", err=ex)

    del response_json["patch"]
    del response.headers["Content-Length"]
    return JSONResponse(response_json, status_code=response.status_code, headers=dict(response.headers))


write_routes = {
    ("PUT", re.compile("users")),
    ("DELETE", re.compile("users\\/.+")),
    ("POST", re.compile("role_assignments")),
    ("DELETE", re.compile("role_assignments")),
}


@router.api_route(
    "/cloud/{path:path}",
    methods=ALL_METHODS,
    summary="Proxy Endpoint",
    include_in_schema=False,
)
async def cloud_proxy(request: Request, path: str):
    """
    Proxies the request to the cloud API. Actual API docs are located here: https://api.permit.io/redoc
    """
    write_route = any(
        request.method == route[0] and route[1].match(request.path_params["path"]) for route in write_routes
    )

    headers = {}
    if write_route:
        headers["X-Include-Patch"] = "true"

    response = await proxy_request_to_cloud_service(
        request,
        path,
        cloud_service_url=sidecar_config.BACKEND_SERVICE_URL,
        additional_headers=headers,
    )

    if write_route:
        return await patch_handler(response)

    return response


@router.api_route(
    "/healthchecks/opa/ready",
    methods=[HTTP_GET],
    summary="Proxy ready healthcheck - OPAL_OPA_HEALTH_CHECK_POLICY_ENABLED must be set to True",
)
async def ready_opa_healthcheck(request: Request):
    return await proxy_request_to_cloud_service(
        request,
        path="v1/data/system/opal/ready",
        cloud_service_url=opal_client_config.POLICY_STORE_URL,
        additional_headers={},
    )


@router.api_route(
    "/healthchecks/opa/healthy",
    methods=[HTTP_GET],
    summary="Proxy healthy healthcheck -  OPAL_OPA_HEALTH_CHECK_POLICY_ENABLED must be set to True",
)
async def health_opa_healthcheck(request: Request):
    return await proxy_request_to_cloud_service(
        request,
        path="v1/data/system/opal/healthy",
        cloud_service_url=opal_client_config.POLICY_STORE_URL,
        additional_headers={},
    )


@router.api_route(
    "/healthchecks/opa/system",
    methods=[HTTP_GET],
    summary="Proxy system data -  OPAL_OPA_HEALTH_CHECK_POLICY_ENABLED must be set to True",
)
async def system_opa_healthcheck(request: Request):
    return await proxy_request_to_cloud_service(
        request,
        path="v1/data/system/opal",
        cloud_service_url=opal_client_config.POLICY_STORE_URL,
        additional_headers={},
    )


# TODO: remove this once we migrate all clients
@router.api_route(
    "/sdk/{path:path}",
    methods=ALL_METHODS,
    summary="Old Proxy Endpoint",
    include_in_schema=False,
)
async def old_proxy(request: Request, path: str):
    return await proxy_request_to_cloud_service(
        request,
        path,
        cloud_service_url=sidecar_config.BACKEND_LEGACY_URL,
        additional_headers={},
    )


async def proxy_request_to_cloud_service(
    request: Request,
    path: str,
    cloud_service_url: str,
    additional_headers: dict[str, str],
) -> Response:
    auth_header = request.headers.get("Authorization")
    if auth_header is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Must provide a bearer token!",
            headers={"WWW-Authenticate": "Bearer"},
        )
    path = f"{cloud_service_url}/{path}"
    params = dict(request.query_params) or {}

    original_headers = {k.lower(): v for k, v in iter(dict(request.headers).items())}
    headers = additional_headers

    # copy only required header
    for header_name in REQUIRED_HTTP_HEADERS:
        if header_name in original_headers:
            headers[header_name] = original_headers[header_name]

    # override host header (required by k8s ingress)
    try:
        headers["host"] = urlparse(cloud_service_url).netloc
    except Exception as e:  # noqa: BLE001
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
        detail="This method is not supported",
    )
