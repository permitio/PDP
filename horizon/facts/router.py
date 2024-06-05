from urllib.parse import urljoin

from fastapi import APIRouter, Depends, Request as FastApiRequest
from loguru import logger
from opal_common.fetcher.providers.http_fetch_provider import HttpFetcherConfig
from opal_common.schemas.data import DataSourceEntry

from authentication import enforce_pdp_token
from config import sidecar_config
from facts.client import FactsClientDependency
from startup.remote_config import get_remote_config

facts_router = APIRouter(dependencies=[Depends(enforce_pdp_token)])


def generate_opal_data_source_entry(
    obj_type: str,
    obj_id: str,
    obj_key: str,
    authorization_header: str,
) -> DataSourceEntry:
    remote_config = get_remote_config()
    org_id = remote_config.context.get("org_id")
    proj_id = remote_config.context.get("project_id")
    env_id = remote_config.context.get("env_id")
    url = urljoin(
        sidecar_config.CONTROL_PLANE,
        f"/v2/internal/opal_data/{org_id}/{proj_id}/{env_id}/{obj_type}/{obj_id}",
    )

    headers = {
        "Authorization": authorization_header,
    }
    if sidecar_config.SHARD_ID:
        headers["X-Shard-Id"] = sidecar_config.SHARD_ID

    pdp_client_id = remote_config.context.get("client_id")
    topic = f"{pdp_client_id}:data:policy_data/{pdp_client_id}"
    if sidecar_config.SHARD_ID:
        topic += f"?shard_id={sidecar_config.SHARD_ID}"

    return DataSourceEntry(
        url=url,
        data=None,
        dst_path=f"{obj_type}/{obj_key}",
        save_method="PUT",
        topics=[topic],
        config=HttpFetcherConfig(headers=headers).dict(),
    )


@facts_router.post("/users")
async def create_user(request: FastApiRequest, client: FactsClientDependency):
    logger.info("Creating user.")
    response = await client.send_forward_request(request, "users")
    body = response.json()
    data_entry = generate_opal_data_source_entry(
        obj_type="users",
        obj_id=body.get("id"),
        obj_key=body.get("key"),
        authorization_header=request.headers.get("Authorization"),
    )
    logger.info(f"Created user id: {data_entry}")
    return client.convert_response(response)


@facts_router.api_route("/{full_path:path}")
async def forward_remaining_requests(
    request: FastApiRequest, client: FactsClientDependency, full_path: str
):
    logger.info(f"Forwarding facts request to {full_path!r}")
    forward_request = await client.build_forward_request(request, full_path)
    response = await client.send(forward_request, stream=True)
    return client.convert_response(response, stream=True)
