import asyncio
import json
import re
from pathlib import Path
from typing import Annotated, cast

import aiohttp
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from opal_client.config import opal_client_config
from opal_client.logger import logger
from opal_client.policy_store.base_policy_store_client import BasePolicyStoreClient
from opal_client.policy_store.policy_store_client_factory import (
    DEFAULT_POLICY_STORE_GETTER,
)
from opal_client.utils import proxy_response
from pydantic import parse_obj_as
from starlette.responses import JSONResponse

from horizon.config import sidecar_config
from horizon.enforcer.schemas import (
    AllTenantsAuthorizationResult,
    AuthorizationQuery,
    AuthorizationResult,
    AuthorizedUsersAuthorizationQuery,
    AuthorizedUsersResult,
    BaseSchema,
    BulkAuthorizationQuery,
    BulkAuthorizationResult,
    MappingRuleData,
    Resource,
    UrlAuthorizationQuery,
    User,
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
AUTHORIZED_USERS_POLICY_PACKAGE = "permit.authorized_users.authorized_users"
USER_TENANTS_POLICY_PACKAGE = USER_PERMISSIONS_POLICY_PACKAGE + ".tenants"
KONG_ROUTES_TABLE_FILE = "/config/kong_routes.json"

stats_manager = StatisticsManager(
    interval_seconds=sidecar_config.OPA_CLIENT_FAILURE_THRESHOLD_INTERVAL,
    failures_threshold_percentage=sidecar_config.OPA_CLIENT_FAILURE_THRESHOLD_PERCENTAGE,
)

AUTHZ_HEADER_PARTS = 2  # "<scheme> <token>"


def extract_pdp_api_key(request: Request) -> str:
    authorization: str = request.headers.get(AUTHZ_HEADER, "")
    parts = authorization.split(" ")
    if len(parts) != AUTHZ_HEADER_PARTS:
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


def _opa_result(response: Response) -> dict | None:
    """The ``result`` object of an OPA response, or None if the body is not a JSON object holding one."""
    try:
        body = json.loads(bytes(response.body))
    except ValueError:  # not JSON, or not UTF-8
        return None
    result = body.get("result", {}) if isinstance(body, dict) else None
    return result if isinstance(result, dict) else None


def _log_raw_query_result(params: str, query: dict, response: Response) -> None:
    """Log a decision with the OPA response body as it came, for a result with no decision to show."""
    try:
        body = str(response.body, "utf-8")
    except ValueError:
        body = None
    data = {} if body is None else {"response_body": body}
    logger.info(
        "is allowed",
        params=params,
        query=query,
        response_status=response.status_code,
        **data,
    )


def log_query_result(query: BaseSchema, response: Response):
    """
    formats a nice log to default logger with the results of permit.check()
    """
    params = repr(query)
    result = _opa_result(response)
    # /user-permissions, /user-tenants and /authorized_users results carry neither "allow" nor
    # "allowed_tenants". A body that is not JSON is logged with its traceback by the endpoint's fallback.
    if result is None or (result.get("allow") is None and "allowed_tenants" not in result):
        _log_raw_query_result(params, query.dict(), response)
        return
    try:
        allowed: bool | list[dict] | None = result.get("allow")
        color = "<red>"
        allow_output = False
        if isinstance(allowed, bool):
            allow_output = allowed
            if allowed:
                color = "<green>"
        elif isinstance(allowed, list):
            if any(a.get("allow", False) for a in allowed):
                color = "<green>"

        if allowed is None:
            allowed_tenants = result["allowed_tenants"]
            allow_output = [f"({a.get('tenant', {}).get('key')}, {a.get('allow', False)})" for a in allowed_tenants]
            if len(allow_output) > 0:
                color = "<green>"

        debug = result.get("debug", {})

        template = color + "is allowed = {allowed} </>"
        template += " | <cyan>{api_params}</>"
        if sidecar_config.DECISION_LOG_DEBUG_INFO:
            template += " | full_input=<fg #fff980>{input}</> | debug=<fg #f7e0c1>{debug}</>"
        logger.opt(colors=True).info(
            template,
            allowed=allow_output,
            api_params=params,
            input=query.dict(),
            debug=debug,
        )
    except Exception:  # noqa: BLE001 - log-only: the decision is answered even if its log line fails
        logger.opt(exception=True).warning("Could not format the decision log line; logging the OPA response raw")
        _log_raw_query_result(params, query.dict(), response)


def log_query_result_kong(kong_input: KongAuthorizationInput, response: Response):
    """
    formats a nice log to default logger with the results of permit.check()
    """
    username = None if kong_input.consumer is None else kong_input.consumer.username
    params = f"({username}, {kong_input.request.http.method}, {kong_input.request.http.path})"
    result = _opa_result(response)
    if result is None:
        _log_raw_query_result(params, kong_input.dict(), response)
        return
    try:
        allowed = result.get("allow", False)
        debug = result.get("debug", {})

        color = "<green>"
        if not allowed:
            color = "<red>"
        template = color + "is allowed = {allowed} </>"
        template += " | <cyan>{api_params}</>"
        if sidecar_config.DECISION_LOG_DEBUG_INFO:
            template += " | full_input=<fg #fff980>{input}</> | debug=<fg #f7e0c1>{debug}</>"
        logger.opt(colors=True).info(
            template,
            allowed=allowed,
            api_params=params,
            input=kong_input.dict(),
            debug=debug,
        )
    except Exception:  # noqa: BLE001 - log-only: the decision is answered even if its log line fails
        logger.opt(exception=True).warning("Could not format the decision log line; logging the OPA response raw")
        _log_raw_query_result(params, kong_input.dict(), response)


def get_v1_processed_query(result: dict) -> dict | None:
    if "authorization_query" not in result:
        return None  # not a v1 query result

    processed_input = result.get("authorization_query", {})
    return {
        "user": processed_input.get("user", {}),
        "action": processed_input.get("action", ""),
        "resource": processed_input.get("resource", {}),
    }


def get_v2_processed_query(result: dict) -> dict | None:
    return (result.get("debug") or {}).get("input", None)


async def notify_seen_sdk(
    x_permit_sdk_language: str | None = Header(default=None),
) -> str | None:
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
        async with aiohttp.ClientSession(trust_env=True) as session:  # noqa: SIM117
            async with session.post(
                url,
                data=json.dumps(data) if data is not None else None,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=sidecar_config.OPA_CLIENT_QUERY_TIMEOUT),
                raise_for_status=True,
            ) as opa_response:
                stats_manager.report_success()
                return await proxy_response(opa_response)
    except asyncio.exceptions.TimeoutError:
        stats_manager.report_failure()
        exc = HTTPException(
            status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"OPA request timed out (url: {url}, timeout: {sidecar_config.OPA_CLIENT_QUERY_TIMEOUT}s)",
        )
    except aiohttp.ClientResponseError as e:
        stats_manager.report_failure()
        exc = HTTPException(
            status.HTTP_502_BAD_GATEWAY,  # 502 indicates server got an error from another server
            detail=f"OPA request failed (url: {url}, status: {e.status}, message: {e.message})",
        )
    except aiohttp.ClientError as e:
        stats_manager.report_failure()
        exc = HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            detail=f"OPA request failed (url: {url}, error: {e!s}",
        )
    logger.warning(exc.detail)
    raise exc


def _set_use_debugger(data: dict | None) -> None:
    if (
        data is not None
        and data.get("input") is not None
        and "use_debugger" not in data["input"]
        and sidecar_config.IS_DEBUG_MODE is not None
    ):
        data["input"]["use_debugger"] = sidecar_config.IS_DEBUG_MODE


async def _is_allowed(query: BaseSchema, request: Request, policy_package: str):
    opa_input = {"input": query.dict()}
    path = policy_package.replace(".", "/")
    return await post_to_opa(request, path, opa_input)


def init_enforcer_health_router():
    """
    The health check route lives on its own router, mounted without authentication:
    k8s/LB liveness probes cannot attach the PDP token, so it must not be part of the
    enforcer router, which requires the PDP token at include time.
    """
    router = APIRouter()

    @router.get("/health", status_code=status.HTTP_200_OK, include_in_schema=False)
    async def health():
        if await stats_manager.status():
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unavailable"},
            )

        return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "ok"})

    return router


# Registers every enforcer endpoint as a nested function, so their statements all count here.
def init_enforcer_api_router(policy_store: BasePolicyStoreClient | None = None):  # noqa: C901, PLR0915
    policy_store = policy_store or DEFAULT_POLICY_STORE_GETTER()
    router = APIRouter()
    if sidecar_config.KONG_INTEGRATION:
        with Path(KONG_ROUTES_TABLE_FILE).open() as f:
            kong_routes_table_raw = json.load(f)
        kong_routes_table = [(re.compile(regex), resource) for regex, resource in kong_routes_table_raw]
        logger.info(f"Kong integration: Loaded {len(kong_routes_table)} translation rules.")

    @router.post(
        "/authorized_users",
        response_model=AuthorizedUsersResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
    )
    async def authorized_users(request: Request, query: AuthorizedUsersAuthorizationQuery):
        response = await _is_allowed(query, request, AUTHORIZED_USERS_POLICY_PACKAGE)
        log_query_result(query, response)
        response_json = None
        try:
            response_json = json.loads(response.body)
            raw_result = response_json.get("result", {}).get("result", {})
            result = parse_obj_as(AuthorizedUsersResult, raw_result)
        except Exception as e:  # noqa: BLE001 - fallback no users: OPA output is untrusted and must not 500
            result = AuthorizedUsersResult.empty(query.resource)
            logger.opt(exception=True).warning(
                "authorized users (fallback response), response: {res}",
                reason=f"cannot decode opa response: {e}",
                res=response_json,
            )
        return result

    @router.post(
        "/allowed_url",
        response_model=AuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        dependencies=[Depends(notify_seen_sdk)],
    )
    async def is_allowed_url(
        request: Request,
        query: UrlAuthorizationQuery,
    ):
        data = await post_to_opa(request, "mapping_rules", None)

        data_result = json.loads(data.body).get("result") or {}
        mapping_rules_json = data_result.get("all") or []
        mapping_rules = [parse_obj_as(MappingRuleData, mapping_rule) for mapping_rule in mapping_rules_json]
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
        # Extract attributes based on the mapping rule type
        if matched_mapping_rule.url_type == "regex":
            # For regex patterns, use only named capture groups
            pattern = re.compile(matched_mapping_rule.url)
            match = pattern.match(query.url)
            path_attributes = match.groupdict() if match else {}
        else:
            # Use existing logic for traditional {var} style patterns
            path_attributes = MappingRulesUtils.extract_attributes_from_url(matched_mapping_rule.url, query.url)

        # Query params handling remains the same for both types
        query_params_attributes = MappingRulesUtils.extract_attributes_from_query_params(
            matched_mapping_rule.url, query.url
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
        return await is_allowed(request, allowed_query)

    @router.post(
        "/user-permissions",
        response_model=UserPermissionsResult,
        name="Get User Permissions",
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        dependencies=[Depends(notify_seen_sdk)],
    )
    async def user_permissions(
        request: Request,
        query: UserPermissionsQuery,
    ):
        response = await _is_allowed(query, request, USER_PERMISSIONS_POLICY_PACKAGE)
        log_query_result(query, response)
        try:
            raw_result = json.loads(response.body).get("result", {})
            return parse_obj_as(UserPermissionsResult, raw_result.get("permissions", {}))
        except Exception as e:  # noqa: BLE001 - fallback no permissions: OPA output is untrusted and must not 500
            logger.opt(exception=True).warning(
                "is allowed (fallback response)", reason=f"cannot decode opa response: {e}"
            )
            return parse_obj_as(UserPermissionsResult, {})

    @router.post(
        "/user-tenants",
        response_model=UserTenantsResult,
        name="Get User Tenants",
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        dependencies=[Depends(notify_seen_sdk)],
    )
    async def user_tenants(
        request: Request,
        query: UserTenantsQuery,
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
                # Caught below on purpose: every malformed OPA result gets the same fallback.
                raise TypeError(f"Expected raw result to be dict or list, got {type(raw_result)}")  # noqa: TRY301
            return parse_obj_as(UserTenantsResult, tenants)
        except Exception as e:  # noqa: BLE001 - fallback no tenants: OPA output is untrusted and must not 500
            logger.opt(exception=True).warning(
                "get user tenants (fallback response)",
                reason=f"cannot decode opa response: {e}",
            )
            return parse_obj_as(UserTenantsResult, [])

    @router.post(
        "/allowed/all-tenants",
        response_model=AllTenantsAuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        dependencies=[Depends(notify_seen_sdk)],
    )
    async def is_allowed_all_tenants(
        request: Request,
        query: AuthorizationQuery,
    ):
        response = await _is_allowed(query, request, ALL_TENANTS_POLICY_PACKAGE)
        log_query_result(query, response)
        try:
            raw_result = json.loads(response.body).get("result", {})
            return AllTenantsAuthorizationResult(
                allowed_tenants=raw_result.get("allowed_tenants", []),
            )
        except Exception as e:  # noqa: BLE001 - fallback no tenants: OPA output is untrusted and must not 500
            logger.opt(exception=True).warning(
                "is allowed (fallback response)", reason=f"cannot decode opa response: {e}"
            )
            return AllTenantsAuthorizationResult(allowed_tenants=[])

    @router.post(
        "/allowed/bulk",
        response_model=BulkAuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        dependencies=[Depends(notify_seen_sdk)],
    )
    async def is_allowed_bulk(
        request: Request,
        queries: list[AuthorizationQuery],
    ):
        bulk_query = BulkAuthorizationQuery(checks=queries)
        response = await _is_allowed(bulk_query, request, BULK_POLICY_PACKAGE)
        log_query_result(bulk_query, response)
        try:
            raw_result = json.loads(response.body).get("result", {})
            return BulkAuthorizationResult(
                allow=raw_result.get("allow", []),
            )
        except Exception as e:  # noqa: BLE001 - fallback empty bulk: OPA output is untrusted and must not 500
            logger.opt(exception=True).warning(
                "is allowed (fallback response)", reason=f"cannot decode opa response: {e}"
            )
            return BulkAuthorizationResult(
                allow=[],
            )

    @router.post(
        "/allowed",
        response_model=AuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        dependencies=[Depends(notify_seen_sdk)],
    )
    async def is_allowed(
        request: Request,
        query: AuthorizationQuery | AuthorizationQueryV1,
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
            processed_query = get_v1_processed_query(raw_result) or get_v2_processed_query(raw_result) or {}
            return {
                "allow": raw_result.get("allow", False),
                "result": raw_result.get("allow", False),  # fallback for older sdks (TODO: remove)
                "query": processed_query,
                "debug": raw_result.get("debug", {}),
            }
        except Exception as e:  # noqa: BLE001 - fallback deny: OPA output is untrusted and must not 500
            logger.opt(exception=True).warning(
                "is allowed (fallback response)", reason=f"cannot decode opa response: {e}"
            )
            return {"allow": False, "result": False}

    @router.post(
        "/nginx_allowed",
        response_model=AuthorizationResult,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
    )
    async def is_allowed_nginx(
        request: Request,
        permit_user_key: Annotated[str, Header()],
        permit_action: Annotated[str, Header()],
        permit_resource_type: Annotated[str, Header()],
        permit_tenant_id: Annotated[str | None, Header()] = None,
    ):
        query = AuthorizationQuery(
            user=User(key=permit_user_key),
            action=permit_action,
            resource=Resource(type=permit_resource_type, tenant=permit_tenant_id),
        )

        response = await _is_allowed(query, request, MAIN_POLICY_PACKAGE)
        log_query_result(query, response)
        try:
            raw_result = json.loads(response.body).get("result", {})
            processed_query = get_v1_processed_query(raw_result) or get_v2_processed_query(raw_result) or {}
            return {
                "allow": raw_result.get("allow", False),
                "result": raw_result.get("allow", False),  # fallback for older sdks (TODO: remove)
                "query": processed_query,
                "debug": raw_result.get("debug", {}),
            }
        except Exception as e:  # noqa: BLE001 - fallback deny: OPA output is untrusted and must not 500
            logger.opt(exception=True).warning(
                "is allowed (fallback response)", reason=f"cannot decode opa response: {e}"
            )
            return {"allow": False, "result": False}

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
                "Got request from Kong with no consumer "
                "(perhaps you forgot to check 'Config.include Consumer In Opa Input' in the Kong OPA plugin config?), "
                "returning allowed=False"
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
            return {
                "result": raw_result.get("allow", False),
            }
        except Exception as e:  # noqa: BLE001 - fallback deny: OPA output is untrusted and must not 500
            logger.opt(exception=True).warning(
                "is allowed (fallback response)",
                reason=f"cannot decode opa response: {e}",
            )
            return {"allow": False, "result": False}

    return router
