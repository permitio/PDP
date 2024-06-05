from dataclasses import dataclass
from typing import Optional, Annotated

from fastapi import HTTPException, Depends
from httpx import AsyncClient, Request as HttpxRequest, Response as HttpxResponse
from loguru import logger
from starlette import status
from starlette.requests import Request as FastApiRequest
from starlette.responses import Response as FastApiResponse, StreamingResponse

from config import sidecar_config


@dataclass
class APIKeyScope:
    organization_id: str
    project_id: Optional[str]
    environment_id: Optional[str]


class FactsClient:
    def __init__(self):
        self._client: Optional[AsyncClient] = None
        self._api_key_scope: Optional[APIKeyScope] = None

    @property
    def client(self) -> AsyncClient:
        if self._client is None:
            self._client = AsyncClient(
                base_url=sidecar_config.CONTROL_PLANE,
                headers={"Authorization": f"Bearer {sidecar_config.API_KEY}"},
            )
        return self._client

    async def get_api_scope(self) -> APIKeyScope:
        if self._api_key_scope is not None:
            return self._api_key_scope

        logger.info(
            f"Fetching API Key scope for control plane {self.client.base_url!r}."
        )
        response = await self.client.get("/v2/api-key/scope")
        response.raise_for_status()
        self._api_key_scope = APIKeyScope(**response.json())
        return self._api_key_scope

    async def build_forward_request(
        self, request: FastApiRequest, path: str
    ) -> HttpxRequest:
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

    async def send(
        self, request: HttpxRequest, *, stream: bool = False
    ) -> HttpxResponse:
        logger.info(f"Forwarding facts request: {request.method} {request.url}")
        return await self.client.send(request, stream=stream)

    async def send_forward_request(
        self, request: FastApiRequest, path: str
    ) -> HttpxResponse:
        forward_request = await self.build_forward_request(request, path)
        return await self.send(forward_request)

    @staticmethod
    def convert_response(
        response: HttpxResponse, *, stream: bool = True
    ) -> FastApiResponse:
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


_facts_client: Optional[FactsClient] = None


def get_facts_client() -> FactsClient:
    global _facts_client
    if _facts_client is None:
        _facts_client = FactsClient()

    return _facts_client


FactsClientDependency = Annotated[FactsClient, Depends(get_facts_client)]
