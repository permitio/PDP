import json
from typing import Dict, Optional

from fastapi import APIRouter, Depends, Response, status
from opal_client.logger import logger
from opal_client.policy_store import DEFAULT_POLICY_STORE_GETTER, BasePolicyStoreClient
from opal_client.policy_store.opa_client import fail_silently

from horizon.authentication import enforce_pdp_token
from horizon.config import sidecar_config
from horizon.enforcer.schemas import AuthorizationQuery, AuthorizationResult


def init_enforcer_api_router(policy_store: BasePolicyStoreClient = None):
    policy_store = policy_store or DEFAULT_POLICY_STORE_GETTER()
    router = APIRouter(dependencies=[Depends(enforce_pdp_token)])

    def log_query_and_result(query: AuthorizationQuery, response: Response):
        params = "({}, {}, {})".format(query.user, query.action, query.resource.type)
        try:
            result: dict = json.loads(response.body).get("result", {})
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
                body = str(response.body, "utf-8")
            except:
                body = None
            data = {} if body is None else {"response_body": body}
            logger.info(
                "is allowed",
                params=params,
                query=query.dict(),
                response_status=response.status_code,
                **data
            )

    @router.post(
        "/allowed",
        response_model=AuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
    )
    async def is_allowed(query: AuthorizationQuery):
        async def _is_allowed():
            return await policy_store.get_data_with_input(path="rbac", input=query)

        fallback_response = dict(result=dict(allow=False, debug="OPA not responding"))
        is_allowed_with_fallback = fail_silently(fallback=fallback_response)(
            _is_allowed
        )
        response = await is_allowed_with_fallback()
        log_query_and_result(query, response)
        try:
            raw_result = json.loads(response.body).get("result", {})
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
