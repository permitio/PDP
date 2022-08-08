from http.client import HTTPException
import json
import aiohttp

from typing import Dict, Optional

from fastapi import APIRouter, Depends, Response, status, Request
from opal_client.logger import logger
from opal_client.policy_store.base_policy_store_client import BasePolicyStoreClient
from opal_client.policy_store.opa_client import fail_silently
from opal_client.policy_store.policy_store_client_factory import (
    DEFAULT_POLICY_STORE_GETTER,
)
from opal_client.config import opal_client_config
from opal_client.utils import proxy_response

from horizon.authentication import enforce_pdp_token
from horizon.config import sidecar_config
from horizon.enforcer.schemas import AuthorizationQuery, AuthorizationResult


AUTHZ_HEADER = "Authorization"


def init_enforcer_api_router(policy_store: BasePolicyStoreClient = None):
    policy_store = policy_store or DEFAULT_POLICY_STORE_GETTER()
    router = APIRouter(dependencies=[Depends(enforce_pdp_token)])

    def log_query_and_result(query: AuthorizationQuery, response: Response):
        params = "({}, {}, {})".format(query.user.key, query.action, query.resource.type)
        try:
            result: dict = json_response.get("result", {})
            allowed = result.get("allow", False)
            permission = None
            granting_role = None
            if allowed:
                granting_permissions = result.get("granting_permission", [])
                granting_permission = (
                    {} if len(granting_permissions) == 0 else granting_permissions[0]
                )
                permission = granting_permission.get("permission", {})
                granting_role: Optional[Dict] = granting_permission.get(
                    "granting_role", None
                )
                if granting_role:
                    role_id = granting_role.get("id", "__NO_ID__")
                    roles = [
                        r
                        for r in result.get("user_roles", [])
                        if r.get("id", "") == role_id
                    ]
                    granting_role = granting_role if not roles else roles[0]

            debug = {
                "opa_warnings": result.get("debug", []),
                "opa_processed_input": result.get("authorization_query", {}),
                "q": result.get("q", {}),
            }
            if allowed and permission is not None and granting_role is not None:
                debug["opa_granting_permision"] = permission
                debug["opa_granting_role"] = granting_role

            if allowed:
                format = "<green>is allowed = {allowed} </>"
            else:
                format = "<red>is allowed = {allowed}</>"
            format += " | <cyan>{api_params}</>"
            if sidecar_config.DECISION_LOG_DEBUG_INFO:
                format += " | full_input=<fg #fff980>{input}</> | debug=<fg #f7e0c1>{debug}</>"
            logger.opt(colors=True).info(
                format,
                allowed=allowed,
                api_params=params,
                input=query.dict(),
                debug=debug,
            )
        except:
            try:
                body = raw_response
            except:
                body = None
            data = {} if body is None else {"response_body": body}
            logger.info(
                "is allowed",
                params=params,
                query=query.dict(),
                response_status=status_code,
                **data
            )

    @router.post(
        "/allowed",
        response_model=AuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
    )
    async def is_allowed(request: Request, query: AuthorizationQuery):
        async def _is_allowed():
            opa_input = {
                "input": query.dict()
            }
            authorization: str = request.headers.get(AUTHZ_HEADER, "")
            parts = authorization.split(" ")
            if len(parts) != 2:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=f"bad authz header: {authorization}")
            schema, token = parts
            if schema.strip().lower() != "bearer":
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid PDP token")

            path = "permit/rbac"
            if path.startswith("/"):
                path = path[1:]
            url = f"{opal_client_config.POLICY_STORE_URL}/v1/data/{path}"
            headers = {AUTHZ_HEADER: f"Bearer {token}", "Content-Type": "application/json"}
            try:
                logger.info(f"calling OPA at '{url}' with input: {opa_input} and headers: {headers}")
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        data=json.dumps(opa_input),
                        headers=headers
                    ) as opa_response:
                        return await proxy_response(opa_response)
            except aiohttp.ClientError as e:
                logger.warning("OPA client error: {err}", err=repr(e))
                raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=repr(e))

        fallback_response = (dict(result=dict(allow=False, debug="OPA not responding")), "", 500)
        is_allowed_with_fallback = fail_silently(fallback=fallback_response)(
            _is_allowed
        )
        json_response, raw_response, status_code = await is_allowed_with_fallback()
        log_query_and_result(query, json_response, raw_response, status_code)
        try:
            raw_result = json_response.get("result", {})
            processed_query = raw_result.get("authorization_query", {})
            result = {
                "allow": raw_result.get("allow", False),
                "result": raw_result.get(
                    "allow", False
                ),  # fallback for older sdks (TODO: remove)
                "query": {
                    "user": processed_query.get("user", {"id": query.user}),
                    "action": processed_query.get("action", query.action),
                    "resource": processed_query.get(
                        "resource", query.resource.dict(exclude_none=True)
                    ),
                },
                "debug": {
                    "warnings": raw_result.get("debug", []),
                    "user_roles": raw_result.get("user_roles", []),
                    "granting_permission": raw_result.get("granting_permission", []),
                    "user_permissions": raw_result.get("user_permissions", []),
                },
            }
        except:
            result = dict(allow=False, result=False)
            logger.warning(
                "is allowed (fallback response)", reason="cannot decode opa response"
            )
        return result

    return router
