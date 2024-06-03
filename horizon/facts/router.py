from fastapi import APIRouter, Depends, Request as FastApiRequest
from loguru import logger

from authentication import enforce_pdp_token
from facts.client import FactsClientDependency

facts_router = APIRouter(dependencies=[Depends(enforce_pdp_token)])


@facts_router.post("/users")
async def create_user(request: FastApiRequest, client: FactsClientDependency):
    logger.info("Creating user.")
    response = await client.send_forward_request(request, "users")
    obj_id = response.json().get("id")
    logger.info(f"Created user id: {obj_id}")
    return client.convert_response(response)


@facts_router.api_route("/{full_path:path}")
async def forward_remaining_requests(request: FastApiRequest, client: FactsClientDependency, full_path: str):
    logger.info(f"Forwarding facts request to {full_path!r}")
    forward_request = await client.build_forward_request(request, full_path)
    response = await client.send(forward_request, stream=True)
    return client.convert_response(response, stream=True)
