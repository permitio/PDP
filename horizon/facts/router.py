from fastapi import APIRouter, Depends, Request as FastApiRequest, HTTPException
from loguru import logger

from authentication import enforce_pdp_token
from config import sidecar_config
from facts.client import FactsClientDependency, FactsClient
from facts.dependencies import DataUpdateSubscriberDependency
from facts.opal_forwarder import generate_opal_data_update
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
    expected_status_code: int = status.HTTP_200_OK,
):
    response = await client.send_forward_request(request, path)
    if response.status_code != expected_status_code:
        logger.info(
            f"Response status code is not {expected_status_code}, skipping wait for update."
        )
        return client.convert_response(response)

    body = response.json()
    if obj_id_field not in body or obj_key_field not in body:
        logger.error(
            f"Missing required fields in response body: {obj_id_field!r}, {obj_key_field!r}, skipping wait for update."
        )
        return client.convert_response(response)

    wait_timeout = get_wait_timeout(request)
    data_entry = generate_opal_data_update(
        obj_type=obj_type,
        obj_id=body[obj_id_field],
        obj_key=body[obj_key_field],
        authorization_header=request.headers.get("Authorization"),
    )
    await update_subscriber.publish_and_wait(
        data_entry,
        timeout=wait_timeout,
    )
    return client.convert_response(response)


def get_wait_timeout(request: FastApiRequest) -> float | None:
    wait_timeout = request.headers.get(
        "X-Wait-timeout", sidecar_config.LOCAL_FACTS_WAIT_TIMEOUT
    )
    try:
        wait_timeout = float(wait_timeout)
    except ValueError as e:
        raise HTTPException(
            status_code=400, detail="Invalid X-Wait-timeout header"
        ) from e
    if wait_timeout < 0:
        return None
    else:
        return wait_timeout


@facts_router.api_route("/{full_path:path}")
async def forward_remaining_requests(
    request: FastApiRequest, client: FactsClientDependency, full_path: str
):
    forward_request = await client.build_forward_request(request, full_path)
    response = await client.send(forward_request, stream=True)
    return client.convert_response(response, stream=True)
