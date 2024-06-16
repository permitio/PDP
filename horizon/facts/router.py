from fastapi import APIRouter, Depends, Request as FastApiRequest
from loguru import logger

from authentication import enforce_pdp_token
from config import sidecar_config
from facts.client import FactsClientDependency, FactsClient
from facts.dependencies import DataUpdateSubscriberDependency
from facts.opal_forwarder import generate_opal_data_source_entry
from facts.update_subscriber import DataUpdateSubscriber

facts_router = APIRouter(dependencies=[Depends(enforce_pdp_token)])


@facts_router.post("/users")
async def create_user(
    request: FastApiRequest,
    client: FactsClientDependency,
    update_subscriber: DataUpdateSubscriberDependency,
):
    return await forward_request_then_wait_for_update(
        client,
        request,
        update_subscriber,
        path="/users",
        obj_type="user",
    )


async def forward_request_then_wait_for_update(
    client: FactsClient,
    request: FastApiRequest,
    update_subscriber: DataUpdateSubscriber,
    *,
    path: str,
    obj_type: str,
    obj_id_field: str = "id",
    obj_key_field: str = "key",
):
    logger.info("-" * 100)
    response = await client.send_forward_request(request, path)
    if response.status_code != 200:
        return client.convert_response(response)

    body = response.json()
    if obj_id_field not in body or obj_key_field not in body:
        logger.error(
            f"Missing required fields in response body: {obj_id_field!r}, {obj_key_field!r}, skipping wait for update."
        )
        return client.convert_response(response)

    data_entry = generate_opal_data_source_entry(
        obj_type=obj_type,
        obj_id=body[obj_id_field],
        obj_key=body[obj_key_field],
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
