import json

import aiohttp
from fastapi import HTTPException, Response, status
from opal_client.config import opal_client_config
from opal_client.logger import logger

from horizon.enforcer.schemas import AuthorizationQuery


class OpaCompileClient:
    def __init__(self, headers: dict):
        self._base_url = f"{opal_client_config.POLICY_STORE_URL}"
        self._headers = headers
        self._client = aiohttp.ClientSession(
            base_url=self._base_url, headers=self._headers
        )

    async def compile_query(
        self, query: str, input: AuthorizationQuery, unknowns: list[str]
    ):
        input = {**input.dict(), "use_debugger": False}
        data = {
            "query": query,
            # we don't want debug rules when we try to reduce the policy into a partial policy
            "input": input,
            "unknowns": unknowns,
        }
        try:
            logger.debug("Compiling OPA query: {}", data)
            async with self._client as session:
                async with session.post(
                    "/v1/compile",
                    data=json.dumps(data),
                    raise_for_status=True,
                ) as response:
                    content = await response.text()
                    return Response(
                        content=content,
                        status_code=response.status,
                        headers=dict(response.headers),
                        media_type="application/json",
                    )
        except aiohttp.ClientResponseError as e:
            exc = HTTPException(
                status.HTTP_502_BAD_GATEWAY,  # 502 indicates server got an error from another server
                detail="OPA request failed (url: {url}, status: {status}, message: {message})".format(
                    url=self._base_url, status=e.status, message=e.message
                ),
            )
        except aiohttp.ClientError as e:
            exc = HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                detail="OPA request failed (url: {url}, error: {error}".format(
                    url=self._base_url, error=str(e)
                ),
            )
        logger.warning(exc.detail)
        raise exc
