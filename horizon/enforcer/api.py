import asyncio
import json
import re
from typing import cast, Optional, Union, Dict, List

import aiohttp
from fastapi import APIRouter, Depends, Header
from fastapi import HTTPException
from fastapi import Request, Response, status
from opal_client.config import opal_client_config
from opal_client.logger import logger
from opal_client.policy_store.base_policy_store_client import BasePolicyStoreClient
from opal_client.policy_store.policy_store_client_factory import (
    DEFAULT_POLICY_STORE_GETTER,
)
from opal_client.utils import proxy_response
from pydantic import parse_obj_as
from starlette.responses import JSONResponse

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
    UserTenantsQuery,
    UserTenantsResult,
)
from horizon.enforcer.schemas_kong import (
    KongAuthorizationInput,
    KongAuthorizationQuery,
    KongAuthorizationResult,
    KongWrappedAuthorizationQuery,
)
from horizon.enforcer.schemas_v1 import AuthorizationQueryV1
from horizon.enforcer.utils.mapping_rules_utils import MappingRulesUtils
from horizon.enforcer.utils.statistics_utils import StatisticsManager
from horizon.state import PersistentStateHandler

AUTHZ_HEADER = "Authorization"
MAIN_POLICY_PACKAGE = "permit.root"
BULK_POLICY_PACKAGE = "permit.bulk"
ALL_TENANTS_POLICY_PACKAGE = "permit.any_tenant"
USER_PERMISSIONS_POLICY_PACKAGE = "permit.user_permissions"
USER_TENANTS_POLICY_PACKAGE = USER_PERMISSIONS_POLICY_PACKAGE + ".tenants"
KONG_ROUTES_TABLE_FILE = "/config/kong_routes.json"

stats_manager = StatisticsManager(
    interval_seconds=sidecar_config.OPA_CLIENT_FAILURE_THRESHOLD_INTERVAL,
    failures_threshold_percentage=sidecar_config.OPA_CLIENT_FAILURE_THRESHOLD_PERCENTAGE,
)


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


async def post_to_opa(request: Request, path: str, data: dict | None):
    headers = transform_headers(request)
    url = f"{opal_client_config.POLICY_STORE_URL}/v1/data/{path}"
    exc = None
    _set_use_debugger(data)
    try:
        logger.debug(f"calling OPA at '{url}' with input: {data}")
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                data=json.dumps(data) if data is not None else None,
                headers=headers,
                timeout=sidecar_config.OPA_CLIENT_QUERY_TIMEOUT,
                raise_for_status=True,
            ) as opa_response:
                stats_manager.report_success()
                return await proxy_response(opa_response)
    except asyncio.exceptions.TimeoutError:
        stats_manager.report_failure()
        exc = HTTPException(
            status.HTTP_504_GATEWAY_TIMEOUT,
            detail="OPA request timed out (url: {url}, timeout: {timeout}s)".format(
                url=url,
                timeout=sidecar_config.OPA_CLIENT_QUERY_TIMEOUT,
            ),
        )
    except aiohttp.ClientResponseError as e:
        stats_manager.report_failure()
        exc = HTTPException(
            status.HTTP_502_BAD_GATEWAY,  # 502 indicates server got an error from another server
            detail="OPA request failed (url: {url}, status: {status}, message: {message})".format(
                url=url, status=e.status, message=e.message
            ),
        )
    except aiohttp.ClientError as e:
        stats_manager.report_failure()
        exc = HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            detail="OPA request failed (url: {url}, error: {error}".format(
                url=url, error=str(e)
            ),
        )
    logger.warning(exc.detail)
    raise exc


def _set_use_debugger(data: dict | None) -> None:
    if data is not None and data.get("input") is not None:
        if "use_debugger" not in data["input"]:
            if sidecar_config.IS_DEBUG_MODE is not None:
                data["input"]["use_debugger"] = sidecar_config.IS_DEBUG_MODE


async def _is_allowed(query: BaseSchema, request: Request, policy_package: str):
    opa_input = {"input": query.dict()}
    path = policy_package.replace(".", "/")
    return await post_to_opa(request, path, opa_input)


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

    @router.get("/health", status_code=status.HTTP_200_OK, include_in_schema=False)
    async def health():
        if await stats_manager.status():
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unavailable"},
            )

        return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "ok"})

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
        data = await post_to_opa(request, "mapping_rules", None)

        mapping_rules = []
        data_result = json.loads(data.body).get("result")
        if data_result is None:
            mapping_rules_json = []
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
        response = await _is_allowed(query, request, USER_PERMISSIONS_POLICY_PACKAGE)
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
        "/user-tenants",
        response_model=UserTenantsResult,
        name="Get User Tenants",
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        dependencies=[Depends(enforce_pdp_token)],
    )
    async def user_tenants(
        request: Request,
        query: UserTenantsQuery,
        x_permit_sdk_language: Optional[str] = Depends(notify_seen_sdk),
    ):
        response = await _is_allowed(query, request, USER_TENANTS_POLICY_PACKAGE)
        log_query_result(query, response)
        try:
            raw_result = json.loads(response.body).get("result", {})
            if isinstance(raw_result, dict):
                tenants = raw_result.get("tenants", {})
            elif isinstance(raw_result, list):
                tenants = raw_result
            else:
                raise TypeError(
                    f"Expected raw result to be dict or list, got {type(raw_result)}"
                )
            result = parse_obj_as(UserTenantsResult, tenants)
        except:
            result = parse_obj_as(UserTenantsResult, [])
            logger.warning(
                "get user tenants (fallback response)",
                reason="cannot decode opa response",
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
        response = await _is_allowed(query, request, ALL_TENANTS_POLICY_PACKAGE)
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
        bulk_query = BulkAuthorizationQuery(checks=queries)
        response = await _is_allowed(bulk_query, request, BULK_POLICY_PACKAGE)
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
            raise HTTPException(
                status_code=status.HTTP_421_MISDIRECTED_REQUEST,
                detail="Mismatch between client version and PDP version,"
                " required v2 request body, got v1. "
                "hint: try to update your client version to v2",
            )
        query = cast(AuthorizationQuery, query)

        response = await _is_allowed(query, request, MAIN_POLICY_PACKAGE)
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
            raise HTTPException(
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

        response = await _is_allowed(
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
