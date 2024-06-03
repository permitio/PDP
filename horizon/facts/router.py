from dataclasses import dataclass
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Response as FastApiResponse, Request as FastApiRequest, HTTPException
from httpx import AsyncClient, Response as HttpxResponse, Request as HttpxRequest
from loguru import logger
from starlette import status
from starlette.responses import StreamingResponse

from authentication import enforce_pdp_token
from config import sidecar_config


@dataclass
class APIKeyScope:
    organization_id: str
    project_id: Optional[str]
    environment_id: Optional[str]


_client: Optional[AsyncClient] = None


class FactsClient:
    def __init__(self):
        self._client: Optional[AsyncClient] = None
        self._api_key_scope: Optional[APIKeyScope] = None

    @property
    def client(self) -> AsyncClient:
        global _client
        if _client is None:
            _client = AsyncClient(
                base_url=sidecar_config.CONTROL_PLANE,
                headers={"Authorization": f"Bearer {sidecar_config.API_KEY}"},
            )
        return _client

    async def get_api_scope(self) -> APIKeyScope:
        if self._api_key_scope is not None:
            return self._api_key_scope

        logger.info(f"Fetching API Key scope for control plane {self.client.base_url!r}.")
        response = await self.client.get("/v2/api-key/scope")
        response.raise_for_status()
        self._api_key_scope = APIKeyScope(**response.json())
        return self._api_key_scope

    async def build_forward_request(self, request: FastApiRequest, path: str) -> HttpxRequest:
        forward_headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() in {"authorization", "content-type"}
        }
        scope = await self.get_api_scope()
        if scope.environment_id is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="PDP API Key for environment is required.",
            )

        full_path = f"/v2/facts/{scope.project_id}/{scope.environment_id}/{path}"
        return self.client.build_request(
            method=request.method,
            url=full_path,
            params=request.query_params,
            headers=forward_headers,
            content=request.stream(),
        )

    async def send(self, request: HttpxRequest, *, stream: bool = False) -> HttpxResponse:
        logger.info(f"Forwarding facts request: {request.method} {request.url}")
        return await self.client.send(request, stream=stream)

    async def send_forward_request(self, request: FastApiRequest, path: str) -> HttpxResponse:
        forward_request = await self.build_forward_request(request, path)
        return await self.send(forward_request)

    @staticmethod
    def convert_response(response: HttpxResponse, *, stream: bool = True) -> FastApiResponse:
        if stream or not hasattr(response, "_content"):
            # if the response content has not loaded yet, optimize it to stream the response.
            return StreamingResponse(
                content=response.aiter_bytes(),
                status_code=response.status_code,
                headers=response.headers,
            )
        else:
            return FastApiResponse(
                content=response.content,
                status_code=response.status_code,
                headers=response.headers,
            )


facts_router = APIRouter(dependencies=[Depends(enforce_pdp_token)])


def get_facts_client() -> FactsClient:
    return FactsClient()


FactsClientDependency = Annotated[FactsClient, Depends(get_facts_client)]


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
