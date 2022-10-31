import json
import os
import re
from http.client import HTTPException
from typing import Dict, Optional

import aiohttp
from fastapi import APIRouter, Depends
from fastapi import HTTPException as fastapi_HTTPException
from fastapi import Request, Response, status
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
from horizon.enforcer.schemas_kong import (
    KongAuthorizationInput,
    KongAuthorizationQuery,
    KongAuthorizationResult,
)

AUTHZ_HEADER = "Authorization"
MAIN_POLICY_PACKAGE = "permit.root"
KONG_ROUTES_TABLE_FILE = "/config/kong_routes.json"


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


def log_query_result_kong(input: KongAuthorizationInput, response: Response):
    """
    formats a nice log to default logger with the results of permit.check()
    """
    params = "({}, {}, {})".format(
        input.consumer.username, input.request.http.method, input.request.http.path
    )
    try:
        result: dict = json.loads(response.body).get("result", {})
        allowed = result.get("allow", False)
        debug = result.get("debug", {})

        color = "<green>"
        if not allowed:
            color = "<red>"
        format = color + "is allowed = {allowed} </>"
        format += " | <cyan>{api_params}</>"
        if sidecar_config.DECISION_LOG_DEBUG_INFO:
            format += (
                " | full_input=<fg #fff980>{input}</> | debug=<fg #f7e0c1>{debug}</>"
            )
        logger.opt(colors=True).info(
            format,
            allowed=allowed,
            api_params=params,
            input=input.dict(),
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
            query=input.dict(),
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
    router = APIRouter()
    if sidecar_config.KONG_INTEGRATION:
        with open(KONG_ROUTES_TABLE_FILE, "r") as f:
            kong_routes_table_raw = json.load(f)
        kong_routes_table = [
            (re.compile(regex), resource) for regex, resource in kong_routes_table_raw
        ]
        logger.info(
            f"Kong integration: Loaded {len(kong_routes_table)} translation rules."
        )

    @router.post(
        "/allowed",
        response_model=AuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        dependencies=[Depends(enforce_pdp_token)],
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

    @router.post(
        "/kong",
        response_model=KongAuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
    )
    async def is_allowed_kong(request: Request, query: KongAuthorizationQuery):
        # Short circuit if disabled
        if sidecar_config.KONG_INTEGRATION is False:
            raise fastapi_HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Kong integration is disabled. Please set the PDP_KONG_INTEGRATION variable to true to enable it.",
            )

        async def _is_allowed():
            opa_input = {
                "input": {
                    "user": {
                        "key": query.input.consumer.username,
                    },
                    "resource": {
                        "tenant": "default",
                        "type": object_type,
                    },
                    "action": query.input.request.http.method.lower(),
                }
            }
            headers = {"Authorization": f"Bearer {sidecar_config.API_KEY}"}

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

        if sidecar_config.KONG_INTEGRATION_DEBUG:
            payload = await request.json()
            logger.info(f"Got request from Kong with payload {payload}")

        if query.input.consumer is None:
            logger.warning(
                "Got request from Kong with no consumer (perhaps you forgot to check 'Config.include Consumer In Opa Input' in the Kong OPA plugin config?), returning allowed=False"
            )
            return {
                "result": False,
            }

        object_type = None
        for regex, resource in kong_routes_table:
            r = regex.match(query.input.request.http.path)
            if r is not None:
                if isinstance(resource, str):
                    object_type = resource
                elif isinstance(resource, int):
                    object_type = r.groups()[resource]
                break

        if object_type is None:
            logger.warning(
                "Got request from Kong to path {} with no matching route, returning allowed=False",
                query.input.request.http.path,
            )
            return {
                "result": False,
            }
        fallback_response = dict(result=dict(allow=False, debug="OPA not responding"))
        is_allowed_with_fallback = fail_silently(fallback=fallback_response)(
            _is_allowed
        )

        response = await is_allowed_with_fallback()
        log_query_result_kong(query.input, response)
        try:
            raw_result = json.loads(response.body).get("result", {})
            result = {
                "result": raw_result.get("allow", False),
            }
        except:
            result = dict(allow=False, result=False)
            logger.warning(
                "is allowed (fallback response)",
                reason="cannot decode opa response",
            )
        return result

    return router
