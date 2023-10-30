import json
import re
from http.client import HTTPException
from typing import cast, Optional, Union, Dict, List

import aiohttp
from fastapi import APIRouter, Depends, Header
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
from pydantic import parse_obj_as

from horizon.authentication import enforce_pdp_token
from horizon.config import sidecar_config
from horizon.enforcer.schemas import (
    AuthorizationQuery,
    AuthorizationResult,
    UrlAuthorizationQuery,
    MappingRuleData,
    Resource,
    BulkAuthorizationResult,
    AllTenantsAuthorizationResult,
    BaseSchema,
    BulkAuthorizationQuery,
    UserPermissionsQuery,
    UserPermissionsResult,
)
from horizon.enforcer.schemas_kong import (
    KongAuthorizationInput,
    KongAuthorizationQuery,
    KongAuthorizationResult,
    KongWrappedAuthorizationQuery,
)
from horizon.enforcer.schemas_v1 import AuthorizationQueryV1
from horizon.enforcer.utils.mapping_rules_utils import MappingRulesUtils
from horizon.state import PersistentStateHandler

AUTHZ_HEADER = "Authorization"
MAIN_POLICY_PACKAGE = "permit.root"
BULK_POLICY_PACKAGE = "permit.bulk"
ALL_TENANTS_POLICY_PACKAGE = "permit.any_tenant"
USER_PERMISSIONS_POLICY_PACKAGE = "permit.user_permissions"
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


def log_query_result(query: BaseSchema, response: Response):
    """
    formats a nice log to default logger with the results of permit.check()
    """
    params = repr(query)
    try:
        result: Dict = json.loads(response.body).get("result", {})
        allowed: bool | List[Dict] = result.get("allow", None)
        color = "<red>"
        allow_output = False
        if isinstance(allowed, bool):
            allow_output = allowed
            if allowed:
                color = "<green>"
        elif isinstance(allowed, list):
            allow_output = [a.get("allow", False) for a in allowed]
            if any(allow_output):
                color = "<green>"

        if allowed is None:
            allowed_tenants = result.get("allowed_tenants")
            allow_output = [
                f"({a.get('tenant', {}).get('key')}, {a.get('allow', False)})"
                for a in allowed_tenants
            ]
            if len(allow_output) > 0:
                color = "<green>"

        debug = result.get("debug", {})

        format = color + "is allowed = {allowed} </>"
        format += " | <cyan>{api_params}</>"
        if sidecar_config.DECISION_LOG_DEBUG_INFO:
            format += (
                " | full_input=<fg #fff980>{input}</> | debug=<fg #f7e0c1>{debug}</>"
            )
        logger.opt(colors=True).info(
            format,
            allowed=allow_output,
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


async def notify_seen_sdk(
    x_permit_sdk_language: Optional[str] = Header(default=None),
) -> Optional[str]:
    if x_permit_sdk_language is not None:
        await PersistentStateHandler.get_instance().seen_sdk(x_permit_sdk_language)
    return x_permit_sdk_language


async def _is_allowed(query: BaseSchema, request: Request, policy_package: str):
    opa_input = {"input": query.dict()}
    headers = transform_headers(request)

    path = policy_package.replace(".", "/")
    url = f"{opal_client_config.POLICY_STORE_URL}/v1/data/{path}"

    try:
        logger.debug(f"calling OPA at '{url}' with input: {opa_input}")
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                data=json.dumps(opa_input),
                headers=headers,
                timeout=sidecar_config.ALLOWED_QUERY_TIMEOUT,
            ) as opa_response:
                return await proxy_response(opa_response)
    except aiohttp.ClientError as e:
        logger.warning("OPA client error: {err}", err=repr(e))
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=repr(e))


async def is_allowed_with_fallback(
    query: BaseSchema, request: Request, policy_package: str, fallback_response: dict
) -> Response:
    _is_allowed_with_fallback = fail_silently(fallback=fallback_response)(_is_allowed)

    return await _is_allowed_with_fallback(query, request, policy_package)


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
        "/allowed_url",
        response_model=AuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        dependencies=[Depends(enforce_pdp_token)],
    )
    async def is_allowed_url(
        request: Request,
        query: UrlAuthorizationQuery,
        x_permit_sdk_language: Optional[str] = Depends(notify_seen_sdk),
    ):
        headers = transform_headers(request)
        mapping_rules_url = (
            f"{opal_client_config.POLICY_STORE_URL}/v1/data/mapping_rules"
        )
        try:
            logger.debug(f"calling OPA at '{mapping_rules_url}'")
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    mapping_rules_url, headers=headers
                ) as opa_response:
                    data = await proxy_response(opa_response)
        except aiohttp.ClientError as e:
            logger.warning("OPA client error: {err}", err=repr(e))
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=repr(e))

        mapping_rules = []
        data_result = json.loads(data.body).get("result")
        if data_result is None:
            mapping_rules_json = None
        else:
            mapping_rules_json = data_result.get("all")

        for mapping_rule in mapping_rules_json:
            mapping_rules.append(parse_obj_as(MappingRuleData, mapping_rule))
        matched_mapping_rule = MappingRulesUtils.extract_mapping_rule_by_request(
            mapping_rules, query.http_method, query.url
        )
        if matched_mapping_rule is None:
            return {
                "allow": False,
                "result": False,
                "query": query.dict(),
                "debug": {
                    "reason": "Matched mapping rule not found for the requested URL and HTTP method",
                    "mapping_rules": mapping_rules_json,
                },
            }
        path_attributes = MappingRulesUtils.extract_attributes_from_url(
            matched_mapping_rule.url, query.url
        )
        query_params_attributes = (
            MappingRulesUtils.extract_attributes_from_query_params(
                matched_mapping_rule.url, query.url
            )
        )
        attributes = {**path_attributes, **query_params_attributes}
        allowed_query = AuthorizationQuery(
            user=query.user,
            action=matched_mapping_rule.action,
            resource=Resource(
                type=matched_mapping_rule.resource,
                tenant=query.tenant,
                attributes=attributes,
            ),
            context=query.context,
            sdk=query.sdk,
        )
        return await is_allowed(request, allowed_query, x_permit_sdk_language)

    @router.post(
        "/user-permissions",
        response_model=UserPermissionsResult,
        name="Get User Permissions",
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        dependencies=[Depends(enforce_pdp_token)],
    )
    async def user_permissions(
        request: Request,
        query: UserPermissionsQuery,
        x_permit_sdk_language: Optional[str] = Depends(notify_seen_sdk),
    ):
        fallback_response = dict(
            result=dict(permissions={}, debug="OPA not responding")
        )
        response = await is_allowed_with_fallback(
            query, request, USER_PERMISSIONS_POLICY_PACKAGE, fallback_response
        )
        log_query_result(query, response)
        try:
            raw_result = json.loads(response.body).get("result", {})
            processed_query = (
                get_v1_processed_query(raw_result)
                or get_v2_processed_query(raw_result)
                or {}
            )

            result = parse_obj_as(
                UserPermissionsResult, raw_result.get("permissions", {})
            )
        except:
            result = parse_obj_as(UserPermissionsResult, {})
            logger.warning(
                "is allowed (fallback response)", reason="cannot decode opa response"
            )
        return result

    @router.post(
        "/allowed/all-tenants",
        response_model=AllTenantsAuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        dependencies=[Depends(enforce_pdp_token)],
    )
    async def is_allowed_all_tenants(
        request: Request,
        query: AuthorizationQuery,
        x_permit_sdk_language: Optional[str] = Depends(notify_seen_sdk),
    ):
        fallback_response = dict(result=dict(allow=[], debug="OPA not responding"))
        response = await is_allowed_with_fallback(
            query, request, ALL_TENANTS_POLICY_PACKAGE, fallback_response
        )
        log_query_result(query, response)
        try:
            raw_result = json.loads(response.body).get("result", {})
            processed_query = (
                get_v1_processed_query(raw_result)
                or get_v2_processed_query(raw_result)
                or {}
            )

            result = AllTenantsAuthorizationResult(
                allowed_tenants=raw_result.get("allowed_tenants", []),
            )
        except:
            result = AllTenantsAuthorizationResult(allowed_tenants=[])
            logger.warning(
                "is allowed (fallback response)", reason="cannot decode opa response"
            )
        return result

    @router.post(
        "/allowed/bulk",
        response_model=BulkAuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        dependencies=[Depends(enforce_pdp_token)],
    )
    async def is_allowed_bulk(
        request: Request,
        queries: list[AuthorizationQuery],
        x_permit_sdk_language: Optional[str] = Depends(notify_seen_sdk),
    ):
        fallback_response = dict(
            result=dict(allow=[dict(allow=False, debug="OPA not responding")])
        )
        bulk_query = BulkAuthorizationQuery(checks=queries)
        response = await is_allowed_with_fallback(
            bulk_query, request, BULK_POLICY_PACKAGE, fallback_response
        )
        log_query_result(bulk_query, response)
        try:
            raw_result = json.loads(response.body).get("result", {})
            processed_query = (
                get_v1_processed_query(raw_result)
                or get_v2_processed_query(raw_result)
                or {}
            )
            result = BulkAuthorizationResult(
                allow=raw_result.get("allow", []),
            )
        except:
            result = BulkAuthorizationResult(
                allow=[],
            )
            logger.warning(
                "is allowed (fallback response)", reason="cannot decode opa response"
            )
        return result

    @router.post(
        "/allowed",
        response_model=AuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        dependencies=[Depends(enforce_pdp_token)],
    )
    async def is_allowed(
        request: Request,
        query: Union[AuthorizationQuery, AuthorizationQueryV1],
        x_permit_sdk_language: Optional[str] = Depends(notify_seen_sdk),
    ):
        if isinstance(query, AuthorizationQueryV1):
            raise fastapi_HTTPException(
                status_code=status.HTTP_421_MISDIRECTED_REQUEST,
                detail="Mismatch between client version and PDP version,"
                " required v2 request body, got v1. "
                "hint: try to update your client version to v2",
            )
        query = cast(AuthorizationQuery, query)

        fallback_response = dict(result=dict(allow=False, debug="OPA not responding"))
        response = await is_allowed_with_fallback(
            query, request, MAIN_POLICY_PACKAGE, fallback_response
        )
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
                detail="Kong integration is disabled. "
                "Please set the PDP_KONG_INTEGRATION variable to true to enable it.",
            )

        await PersistentStateHandler.get_instance().seen_sdk("kong")

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

        response = await is_allowed_with_fallback(
            KongWrappedAuthorizationQuery(
                user={
                    "key": query.input.consumer.username,
                },
                resource={
                    "tenant": "default",
                    "type": object_type,
                },
                action=query.input.request.http.method.lower(),
            ),
            request,
            MAIN_POLICY_PACKAGE,
            fallback_response,
        )
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
