import json
from http.client import HTTPException
from typing import Dict, Optional

import aiohttp
from fastapi import APIRouter, Depends, Request, Response, status
from opal_client.config import opal_client_config
from opal_client.logger import logger
from opal_client.policy_store.base_policy_store_client import BasePolicyStoreClient
from opal_client.policy_store.opa_client import fail_silently
from opal_client.policy_store.policy_store_client_factory import (
    DEFAULT_POLICY_STORE_GETTER,
)
from opal_client.utils import proxy_response

from horizon.authentication import enforce_pdp_token
from horizon.config import sidecar_config
from horizon.enforcer.schemas import AuthorizationQuery, AuthorizationResult

AUTHZ_HEADER = "Authorization"
MAIN_POLICY_PACKAGE = "permit.root"


def extract_pdp_api_key(request: Request) -> str:
    authorization: str = request.headers.get(AUTHZ_HEADER, "")
    parts = authorization.split(" ")
    if len(parts) != 2:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail=f"bad authz header: {authorization}",
        )
    schema, token = parts
    if schema.strip().lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid PDP token")
    return token


def transform_headers(request: Request) -> dict:
    token = extract_pdp_api_key(request)
    return {
        AUTHZ_HEADER: f"Bearer {token}",
        "Content-Type": "application/json",
    }


def log_query_result(query: AuthorizationQuery, response: Response):
    """
    formats a nice log to default logger with the results of permit.check()
    """
    params = "({}, {}, {})".format(query.user.key, query.action, query.resource.type)
    try:
        result: dict = json.loads(response.body).get("result", {})
        allowed = result.get("allow", False)
        debug = result.get("debug", {})

        if allowed:
            format = "<green>is allowed = {allowed} </>"
        else:
            format = "<red>is allowed = {allowed}</>"
        format += " | <cyan>{api_params}</>"
        if sidecar_config.DECISION_LOG_DEBUG_INFO:
            format += (
                " | full_input=<fg #fff980>{input}</> | debug=<fg #f7e0c1>{debug}</>"
            )
        logger.opt(colors=True).info(
            format,
            allowed=allowed,
            api_params=params,
            input=query.dict(),
            debug=debug,
        )
    except:
        try:
            body = str(response.body, "utf-8")
        except:
            body = None
        data = {} if body is None else {"response_body": body}
        logger.info(
            "is allowed",
            params=params,
            query=query.dict(),
            response_status=response.status_code,
            **data,
        )


def get_v1_processed_query(result: dict) -> Optional[dict]:
    if "authorization_query" not in result:
        return None  # not a v1 query result

    processed_input = result.get("authorization_query", {})
    return {
        "user": processed_input.get("user", {}),
        "action": processed_input.get("action", ""),
        "resource": processed_input.get("resource", {}),
    }


def get_v2_processed_query(result: dict) -> Optional[dict]:
    return result.get("debug", {}).get("input", None)


def init_enforcer_api_router(policy_store: BasePolicyStoreClient = None):
    policy_store = policy_store or DEFAULT_POLICY_STORE_GETTER()
    router = APIRouter(dependencies=[Depends(enforce_pdp_token)])

    @router.post(
        "/allowed",
        response_model=AuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
    )
    async def is_allowed(request: Request, query: AuthorizationQuery):
        async def _is_allowed():
            opa_input = {"input": query.dict()}
            headers = transform_headers(request)

            path = MAIN_POLICY_PACKAGE.replace(".", "/")
            url = f"{opal_client_config.POLICY_STORE_URL}/v1/data/{path}"

            try:
                logger.debug(f"calling OPA at '{url}' with input: {opa_input}")
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url, data=json.dumps(opa_input), headers=headers
                    ) as opa_response:
                        return await proxy_response(opa_response)
            except aiohttp.ClientError as e:
                logger.warning("OPA client error: {err}", err=repr(e))
                raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=repr(e))

        fallback_response = dict(result=dict(allow=False, debug="OPA not responding"))
        is_allowed_with_fallback = fail_silently(fallback=fallback_response)(
            _is_allowed
        )
        response = await is_allowed_with_fallback()
        log_query_result(query, response)
        try:
            raw_result = json.loads(response.body).get("result", {})
            processed_query = (
                get_v1_processed_query(raw_result)
                or get_v2_processed_query(raw_result)
                or {}
            )
            result = {
                "allow": raw_result.get("allow", False),
                "result": raw_result.get(
                    "allow", False
                ),  # fallback for older sdks (TODO: remove)
                "query": processed_query,
                "debug": raw_result.get("debug", {}),
            }
        except:
            result = dict(allow=False, result=False)
            logger.warning(
                "is allowed (fallback response)", reason="cannot decode opa response"
            )
        return result

    return router
