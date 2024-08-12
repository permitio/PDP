import json

import aiohttp
from fastapi import HTTPException, status
from loguru import logger

from permit_datafilter.compile_api.schemas import CompileResponse
from permit_datafilter.rego_ast import parser as ast
from permit_datafilter.boolean_expression.schemas import (
    ResidualPolicyResponse,
)
from permit_datafilter.boolean_expression.translator import (
    translate_opa_queryset,
)


class OpaCompileClient:
    def __init__(self, base_url: str, headers: dict):
        self._base_url = base_url  # f"{opal_client_config.POLICY_STORE_URL}"
        self._headers = headers
        self._client = aiohttp.ClientSession(
            base_url=self._base_url, headers=self._headers
        )

    async def compile_query(
        self,
        query: str,
        input: dict,
        unknowns: list[str],
        raw: bool = False,
    ) -> ResidualPolicyResponse:
        # we don't want debug rules when we try to reduce the policy into a partial policy
        input = {**input, "use_debugger": False}
        data = {
            "query": query,
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
                    opa_compile_result = await response.json()
                    logger.debug(
                        "OPA compile query result: status={status}, response={response}",
                        status=response.status,
                        response=json.dumps(opa_compile_result),
                    )
                    try:
                        residual_policy = self.translate_rego_ast(opa_compile_result)
                        if raw:
                            residual_policy.raw = opa_compile_result
                        return residual_policy
                    except Exception as exc:
                        return HTTPException(
                            status.HTTP_406_NOT_ACCEPTABLE,
                            detail="failed to translate compiled OPA query (query: {query}, response: {response}, exc={exc})".format(
                                query=data, response=opa_compile_result, exc=exc
                            ),
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

    def translate_rego_ast(self, response: dict) -> ResidualPolicyResponse:
        response = CompileResponse(**response)
        queryset = ast.QuerySet.parse(response)
        return translate_opa_queryset(queryset)
