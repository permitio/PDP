from fastapi import (
    APIRouter,
    Depends,
    Request as FastApiRequest,
    status,
    Response,
)
from loguru import logger

from authentication import enforce_pdp_token
from facts.client import FactsClientDependency, FactsClient
from facts.dependencies import DataUpdateSubscriberDependency, WaitTimeoutDependency
from facts.opal_forwarder import create_data_source_entry, create_data_update_entry
from facts.update_subscriber import DataUpdateSubscriber

facts_router = APIRouter(dependencies=[Depends(enforce_pdp_token)])


@facts_router.post("/users")
async def create_user(
    request: FastApiRequest,
    client: FactsClientDependency,
    update_subscriber: DataUpdateSubscriberDependency,
    wait_timeout: WaitTimeoutDependency,
):
    return await forward_request_then_wait_for_update(
        client,
        request,
        update_subscriber,
        wait_timeout,
        path="/users",
        obj_type="user",
    )


@facts_router.put("/users/{user_id}")
async def sync_user(
    request: FastApiRequest,
    client: FactsClientDependency,
    update_subscriber: DataUpdateSubscriberDependency,
    wait_timeout: WaitTimeoutDependency,
    user_id: str,
):
    return await forward_request_then_wait_for_update(
        client,
        request,
        update_subscriber,
        wait_timeout,
        path=f"/users/{user_id}",
        obj_type="user",
    )


@facts_router.patch("/users/{user_id}")
async def replace_user(
    request: FastApiRequest,
    client: FactsClientDependency,
    update_subscriber: DataUpdateSubscriberDependency,
    wait_timeout: WaitTimeoutDependency,
    user_id: str,
):
    return await forward_request_then_wait_for_update(
        client,
        request,
        update_subscriber,
        wait_timeout,
        path=f"/users/{user_id}",
        obj_type="user",
    )


@facts_router.post("/users/{user_id}/roles")
async def assign_user_role(
    request: FastApiRequest,
    client: FactsClientDependency,
    update_subscriber: DataUpdateSubscriberDependency,
    wait_timeout: WaitTimeoutDependency,
    user_id: str,
):
    response = await client.send_forward_request(request, f"/users/{user_id}/roles")
    if response.status_code != 200:
        logger.warning("Response status code is not 200, skipping wait for update.")
        return client.convert_response(response)

    body = response.json()
    try:
        data_update_entry = create_data_update_entry(
            [
                create_data_source_entry(
                    obj_type="role_assignments",
                    obj_id=body["id"],
                    obj_key=f"user:{body['user']}",
                    authorization_header=request.headers.get("Authorization"),
                ),
                create_data_source_entry(
                    obj_type="users",
                    obj_id=body["user_id"],
                    obj_key=body["user"],
                    authorization_header=request.headers.get("Authorization"),
                ),
            ]
        )
    except KeyError as e:
        logger.error(
            f"Missing required field {e.args[0]} in the response body, skipping wait for update."
        )
        return client.convert_response(response)

    await update_subscriber.publish_and_wait(
        data_update_entry,
        timeout=wait_timeout,
    )
    return client.convert_response(response)


async def forward_request_then_wait_for_update(
    client: FactsClient,
    request: FastApiRequest,
    update_subscriber: DataUpdateSubscriber,
    wait_timeout: float | None,
    *,
    path: str,
    obj_type: str,
    obj_id_field: str = "id",
    obj_key_field: str = "key",
    expected_status_code: int = status.HTTP_200_OK,
) -> Response:
    response = await client.send_forward_request(request, path)
    if response.status_code != expected_status_code:
        logger.warning(
            f"Response status code is not {expected_status_code}, skipping wait for update."
        )
        return client.convert_response(response)

    body = response.json()
    if obj_id_field not in body or obj_key_field not in body:
        logger.error(
            f"Missing required fields in response body: {obj_id_field!r}, {obj_key_field!r}, skipping wait for update."
        )
        return client.convert_response(response)

    data_update_entry = create_data_update_entry(
        [
            create_data_source_entry(
                obj_type=obj_type,
                obj_id=body[obj_id_field],
                obj_key=body[obj_key_field],
                authorization_header=request.headers.get("Authorization"),
            )
        ]
    )
    await update_subscriber.publish_and_wait(
        data_update_entry,
        timeout=wait_timeout,
    )
    return client.convert_response(response)


@facts_router.api_route(
    "/{full_path:path}",
    methods=["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"],
)
async def forward_remaining_requests(
    request: FastApiRequest, client: FactsClientDependency, full_path: str
):
    forward_request = await client.build_forward_request(request, full_path)
    response = await client.send(forward_request, stream=True)
    return client.convert_response(response, stream=True)
