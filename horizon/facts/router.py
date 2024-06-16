from fastapi import APIRouter, Depends, Request as FastApiRequest
from loguru import logger

from authentication import enforce_pdp_token
from config import sidecar_config
from facts.client import FactsClientDependency
from facts.dependencies import DataUpdateSubscriberDependency
from facts.opal_forwarder import generate_opal_data_source_entry

facts_router = APIRouter(dependencies=[Depends(enforce_pdp_token)])


@facts_router.post("/users")
async def create_user(
    request: FastApiRequest,
    client: FactsClientDependency,
    update_subscriber: DataUpdateSubscriberDependency,
):
    logger.info("-" * 100)
    response = await client.send_forward_request(request, "users")
    if response.status_code != 200:
        return client.convert_response(response)

    body = response.json()
    data_entry = generate_opal_data_source_entry(
        obj_type="users",
        obj_id=body.get("id"),
        obj_key=body.get("key"),
        authorization_header=request.headers.get("Authorization"),
    )
    await update_subscriber.publish_and_wait(
        data_entry, timeout=sidecar_config.LOCAL_FACTS_WAIT_TIMEOUT
    )
    return client.convert_response(response)


@facts_router.api_route("/{full_path:path}")
async def forward_remaining_requests(
    request: FastApiRequest, client: FactsClientDependency, full_path: str
):
    logger.info(f"Forwarding facts request to {full_path!r}")
    forward_request = await client.build_forward_request(request, full_path)
    response = await client.send(forward_request, stream=True)
    return client.convert_response(response, stream=True)
