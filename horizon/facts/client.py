from typing import Annotated
from urllib.parse import urljoin

from fastapi import Depends, HTTPException
from httpx import AsyncClient
from httpx import Request as HttpxRequest
from httpx import Response as HttpxResponse
from loguru import logger
from starlette import status
from starlette.requests import Request as FastApiRequest
from starlette.responses import Response as FastApiResponse
from starlette.responses import StreamingResponse

from horizon.config import sidecar_config
from horizon.startup.api_keys import get_env_api_key
from horizon.startup.remote_config import get_remote_config


class FactsClient:
    def __init__(self):
        self._client: AsyncClient | None = None

    @property
    def client(self) -> AsyncClient:
        if self._client is None:
            env_api_key = get_env_api_key()
            self._client = AsyncClient(
                base_url=sidecar_config.CONTROL_PLANE,
                headers={"Authorization": f"Bearer {env_api_key}"},
            )
        return self._client

    async def build_forward_request(self, request: FastApiRequest, path: str) -> HttpxRequest:
        """
        Build an HTTPX request from a FastAPI request to forward to the facts service.
        :param request: FastAPI request
        :param path: Backend facts service path to forward to
        :return: HTTPX request
        """
        forward_headers = {
            key: value for key, value in request.headers.items() if key.lower() in {"authorization", "content-type"}
        }
        remote_config = get_remote_config()
        project_id = remote_config.context.get("project_id")
        environment_id = remote_config.context.get("env_id")
        if project_id is None or environment_id is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="PDP API Key for environment is required.",
            )

        full_path = urljoin(f"/v2/facts/{project_id}/{environment_id}/", path.removeprefix("/"))
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
        """
        Send a forward request to the facts service.
        :param request: FastAPI request
        :param path: Backend facts service path to forward to
        :return: HTTPX response
        """
        forward_request = await self.build_forward_request(request, path)
        return await self.send(forward_request)

    @staticmethod
    def convert_response(response: HttpxResponse, *, stream: bool = False) -> FastApiResponse:
        """
        Convert an HTTPX response to a FastAPI response.
        :param response: HTTPX response
        :param stream: Stream the response content (automatic by default if content has not loaded)
        :return:
        """
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

    @staticmethod
    def extract_body(response: HttpxResponse):
        if not response.is_success:
            logger.warning(
                f"Response status code is not successful ( {response.status_code} ), " f"skipping wait for update."
            )
            return None

        try:
            body = response.json()
        except Exception:
            logger.exception("Failed to parse response body as JSON, skipping wait for update.")
            return None
        else:
            return body


_facts_client: FactsClient | None = None


def get_facts_client() -> FactsClient:
    global _facts_client
    if _facts_client is None:
        _facts_client = FactsClient()

    return _facts_client


FactsClientDependency = Annotated[FactsClient, Depends(get_facts_client)]
