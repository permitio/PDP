from typing import Annotated

from fastapi import APIRouter, Depends, Request as FastApiRequest
from loguru import logger
from opal_client import OpalClient

from authentication import enforce_pdp_token
from facts.client import FactsClientDependency
from facts.opal_forwarder import generate_opal_data_source_entry

facts_router = APIRouter(dependencies=[Depends(enforce_pdp_token)])


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
