from collections.abc import Callable, Iterable
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    Response,
)
from fastapi import (
    Request as FastApiRequest,
)
from loguru import logger
from opal_common.schemas.data import DataSourceEntry

from horizon.authentication import enforce_pdp_token
from horizon.facts.client import FactsClient, FactsClientDependency
from horizon.facts.dependencies import (
    DataUpdateSubscriberDependency,
    WaitTimeoutDependency,
)
from horizon.facts.opal_forwarder import (
    create_data_source_entry,
    create_data_update_entry,
)
from horizon.facts.update_subscriber import DataUpdateSubscriber

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


@facts_router.post("/tenants")
async def create_tenant(
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
        path="/tenants",
        entries_callback=lambda r, body: [
            create_data_source_entry(
                obj_type="tenants",
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
async def update_user(
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


def create_role_assignment_data_entries(request: FastApiRequest, body: dict[str, Any]) -> Iterable[DataSourceEntry]:
    if not body.get("resource_instance"):
        yield create_data_source_entry(
            obj_type="role_assignments",
            obj_id=body["id"],
            obj_key=f"user:{body['user']}",
            authorization_header=request.headers.get("Authorization"),
        )
        yield create_data_source_entry(
            obj_type="users",
            obj_id=body["user_id"],
            obj_key=body["user"],
            authorization_header=request.headers.get("Authorization"),
        )
    else:
        # note that user_id == subject_id,
        # and user == user_key == subject_key == subject_str
        yield create_data_source_entry(
            obj_type="role_assignments",
            obj_id=body["user_id"],
            obj_key=body["user"],
            authorization_header=request.headers.get("Authorization"),
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
        entries_callback=create_role_assignment_data_entries,
    )


@facts_router.post("/role_assignments")
async def create_role_assignment(
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
        path="/role_assignments",
        entries_callback=create_role_assignment_data_entries,
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


@facts_router.patch("/resource_instances/{instance_id}")
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


@facts_router.post("/relationship_tuples")
async def create_relationship_tuple(
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
        path="/relationship_tuples",
        entries_callback=lambda r, body: [
            create_data_source_entry(
                obj_type="relationships",
                obj_id=body["object_id"],
                obj_key=body["object"],
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
    entries_callback: Callable[[FastApiRequest, dict[str, Any]], Iterable[DataSourceEntry]],
) -> Response:
    response = await client.send_forward_request(request, path)
    body = client.extract_body(response)
    if body is None:
        return client.convert_response(response)

    try:
        data_update_entry = create_data_update_entry(list(entries_callback(request, body)))
    except KeyError as e:
        logger.warning(f"Missing required field {e.args[0]} in the response body, skipping wait for update.")
        return client.convert_response(response)

    await update_subscriber.publish_and_wait(
        data_update_entry,
        timeout=wait_timeout,
    )
    return client.convert_response(response)


@facts_router.api_route(
    "/{full_path:path}",
    methods=["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"],
    include_in_schema=False,
)
async def forward_remaining_requests(request: FastApiRequest, client: FactsClientDependency, full_path: str):
    forward_request = await client.build_forward_request(request, full_path)
    response = await client.send(forward_request, stream=True)
    return client.convert_response(response, stream=True)
