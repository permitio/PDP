from typing import Callable, Any, Iterable

from fastapi import (
    APIRouter,
    Depends,
    Request as FastApiRequest,
    status,
    Response,
)
from loguru import logger
from opal_common.schemas.data import DataSourceEntry

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
        entries_callback=lambda r, body: [
            create_data_source_entry(
                obj_type="users",
                obj_id=body["id"],
                obj_key=body["key"],
                authorization_header=r.headers.get("Authorization"),
            )
        ],
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
        entries_callback=lambda r, body: [
            create_data_source_entry(
                obj_type="users",
                obj_id=body["id"],
                obj_key=body["key"],
                authorization_header=r.headers.get("Authorization"),
            )
        ],
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
        entries_callback=lambda r, body: [
            create_data_source_entry(
                obj_type="users",
                obj_id=body["id"],
                obj_key=body["key"],
                authorization_header=r.headers.get("Authorization"),
            )
        ],
    )


@facts_router.post("/users/{user_id}/roles")
async def assign_user_role(
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
        path=f"/users/{user_id}/roles",
        entries_callback=lambda r, body: [
            create_data_source_entry(
                obj_type="role_assignments",
                obj_id=body["id"],
                obj_key=f"user:{body['user']}",
                authorization_header=r.headers.get("Authorization"),
            ),
            create_data_source_entry(
                obj_type="users",
                obj_id=body["user_id"],
                obj_key=body["user"],
                authorization_header=r.headers.get("Authorization"),
            ),
        ],
    )


@facts_router.post("/resource_instances")
async def create_resource_instance(
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
        path="/resource_instances",
        entries_callback=lambda r, body: [
            create_data_source_entry(
                obj_type="resource_instances",
                obj_id=body["id"],
                obj_key=f"{body['resource']}:{body['key']}",
                authorization_header=r.headers.get("Authorization"),
            ),
        ],
    )


@facts_router.put("/resource_instances/{instance_id}")
async def update_resource_instance(
    request: FastApiRequest,
    client: FactsClientDependency,
    update_subscriber: DataUpdateSubscriberDependency,
    wait_timeout: WaitTimeoutDependency,
    instance_id: str,
):
    return await forward_request_then_wait_for_update(
        client,
        request,
        update_subscriber,
        wait_timeout,
        path=f"/resource_instances/{instance_id}",
        entries_callback=lambda r, body: [
            create_data_source_entry(
                obj_type="resource_instances",
                obj_id=body["id"],
                obj_key=f"{body['resource']}:{body['key']}",
                authorization_header=r.headers.get("Authorization"),
            ),
        ],
    )


async def forward_request_then_wait_for_update(
    client: FactsClient,
    request: FastApiRequest,
    update_subscriber: DataUpdateSubscriber,
    wait_timeout: float | None,
    *,
    path: str,
    entries_callback: Callable[
        [FastApiRequest, dict[str, Any]], Iterable[DataSourceEntry]
    ],
    expected_status_code: int = status.HTTP_200_OK,
) -> Response:
    response = await client.send_forward_request(request, path)
    body = client.extract_body(response, expected_status_code)
    if body is None:
        return client.convert_response(response)

    try:
        data_update_entry = create_data_update_entry(
            list(entries_callback(request, body))
        )
    except KeyError as e:
        logger.warning(
            f"Missing required field {e.args[0]} in the response body, skipping wait for update."
        )
        return client.convert_response(response)

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
