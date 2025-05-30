import logging
import os
import sys
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, status
from fastapi.responses import RedirectResponse
from loguru import logger
from logzio.handler import LogzioHandler
from opal_client.client import OpalClient
from opal_client.config import (
    ConnRetryOptions,
    EngineLogFormat,
    PolicyStoreAuth,
    opal_client_config,
    opal_common_config,
)
from opal_client.engine.options import OpaServerOptions
from opal_common.confi import Confi
from opal_common.fetcher.providers.http_fetch_provider import (
    HttpFetcherConfig,
    HttpMethods,
)
from opal_common.logging_utils.formatter import Formatter
from scalar_fastapi import get_scalar_api_reference

from horizon.authentication import enforce_pdp_token
from horizon.config import MOCK_API_KEY, sidecar_config
from horizon.enforcer.api import init_enforcer_api_router, stats_manager
from horizon.enforcer.opa.config_maker import (
    get_opa_authz_policy_file_path,
    get_opa_config_file_path,
)
from horizon.facts.router import facts_router
from horizon.local.api import init_local_cache_api_router
from horizon.opal_relay_api import OpalRelayAPIClient
from horizon.proxy.api import router as proxy_router
from horizon.startup.api_keys import get_env_api_key
from horizon.startup.exceptions import InvalidPDPTokenError
from horizon.startup.remote_config import get_remote_config
from horizon.state import PersistentStateHandler
from horizon.system.api import init_system_api_router
from horizon.system.consts import GUNICORN_EXIT_APP

OPA_LOGGER_MODULE = "opal_client.opa.logger"


def set_process_niceness(target_nice: int) -> None:
    """
    Attempts to set the current process's niceness value to `target_nice`.
    This operation is performed only once during the call.

    This function is idempotent if the current niceness already equals `target_nice`.
    Setting a lower niceness value (increasing priority) may require CAP_SYS_NICE
    capabilities and could fail if the process lacks sufficient privileges.
    """
    if target_nice < -20 or target_nice > 19:
        raise ValueError(f"Target niceness must be between -20 and 19, got {target_nice}")

    try:
        current_niceness = os.nice(0)  # Read current niceness without changing it
        delta = target_nice - current_niceness
        if delta != 0:
            os.nice(delta)  # Apply the change
            new_niceness = os.nice(0)  # Read the new niceness to confirm
            logging.info(
                "Changed the process niceness by %d from %d to %d (target was %d).",
                delta,
                current_niceness,
                new_niceness,
                target_nice,
            )
        else:
            logging.debug("Process niceness is already %d, which matches the target; no change made.", current_niceness)
    except OSError as exc:
        logging.warning("Failed to change process niceness to %d: %s", target_nice, exc)


def apply_config(overrides_dict: dict, config_object: Confi):
    """
    apply config values from dict into a confi object
    """
    for key, value in overrides_dict.items():
        prefixed_key = config_object._prefix_key(key)
        if key in config_object.entries:
            try:
                setattr(
                    config_object,
                    key,
                    config_object.entries[key].cast_from_json(value),
                )
            except Exception:  # noqa BLE001
                logger.opt(exception=True).warning(f"Unable to set config key {prefixed_key} from overrides:")
                continue
            logger.info(f"Overriden config key: {prefixed_key}")
            continue
        logger.warning(f"Ignored non-existing config key: {prefixed_key}")


class PermitPDP:
    """
    Permit.io PDP (Policy Decision Point)

    This process acts as a policy agents that is automatically configured by Permit.io cloud.
    You only need an API key to configure this correctly.

    -----
    Implementation details:
    The PDP is a thin wrapper on top of opal client.

    By extending opal client, it runs:
    - a subprocess running the OPA agent (with opal client's opa runner)
    - policy updater
    - data updater

    It also run directly Permit.io specific apis:
    - proxy api (proxies the REST api at api.permit.io to the sdks)
    - local api (wrappers on top of opa cache)
    - enforcer api (implementation of is_allowed())
    """

    def __init__(self):
        self._setup_temp_logger()
        PersistentStateHandler.initialize(get_env_api_key())
        # fetch and apply config override from cloud control plane
        try:
            remote_config = get_remote_config()
        except InvalidPDPTokenError as e:
            logger.critical("An invalid API key was specified. Please verify the PDP_API_KEY environment variable.")
            raise SystemExit(GUNICORN_EXIT_APP) from e

        if not remote_config:
            logger.critical("No cloud configuration found. Exiting.")
            raise SystemExit(GUNICORN_EXIT_APP)

        logger.info("Applying config overrides from cloud control plane...")

        apply_config(remote_config.opal_common or {}, opal_common_config)
        apply_config(remote_config.opal_client or {}, opal_client_config)
        apply_config(remote_config.pdp or {}, sidecar_config)

        self._log_environment(remote_config.context)

        if sidecar_config.OPA_BEARER_TOKEN_REQUIRED or sidecar_config.OPA_DECISION_LOG_ENABLED:
            # we need to pass to OPAL a custom inline OPA config to enable these features
            self._configure_inline_opa_config()

        self._configure_opal_data_updater()
        self._configure_opal_offline_mode()

        if sidecar_config.PRINT_CONFIG_ON_STARTUP:
            logger.info(
                "sidecar is loading with the following config:\n\n"
                "{sidecar_config}\n\n"
                "{opal_client_config}\n\n"
                "{opal_common_config}",
                sidecar_config=sidecar_config.debug_repr(),
                opal_client_config=opal_client_config.debug_repr(),
                opal_common_config=opal_common_config.debug_repr(),
            )

        if sidecar_config.ENABLE_MONITORING:
            self._configure_monitoring()

        if sidecar_config.HORIZON_NICENESS:
            set_process_niceness(sidecar_config.HORIZON_NICENESS)

        self._opal = OpalClient(shard_id=sidecar_config.SHARD_ID, data_topics=self._fix_data_topics())
        self._inject_extra_callbacks()
        # remove default data update callbacks that are not needed and might be managed by the control plane
        self._remove_ignored_default_callbacks_urls()
        self._configure_cloud_logging(remote_config.context)

        self._opal_relay = OpalRelayAPIClient(remote_config.context, self._opal)
        self._opal.data_updater.callbacks_reporter.set_user_data_handler(
            PersistentStateHandler.get_instance().reporter_user_data_handler
        )

        # use opal client app and add sidecar routes on top
        app: FastAPI = self._opal.app
        app.state.opal_client = self._opal
        self._override_app_metadata(app)
        self._configure_api_routes(app)

        self._app: FastAPI = app

        @app.on_event("startup")
        async def _initialize_opal_relay():
            await self._opal_relay.initialize()

        @app.get("/scalar", include_in_schema=False)
        async def scalar_html():
            return get_scalar_api_reference(
                openapi_url="/openapi.json",
                title="Permit.io PDP API",
            )

    def _setup_temp_logger(self):
        """
        until final config is set, we need to make sure sane defaults are in place
        """
        # Clean slate
        logger.remove()
        # Logger configuration
        logger.add(
            sys.stdout,
            format=sidecar_config.TEMP_LOG_FORMAT,
            level="INFO",
            backtrace=False,
            diagnose=False,
            colorize=True,
            serialize=False,
        )

    def _log_environment(self, pdp_context: dict[str, str]):
        if "org_id" not in pdp_context or "project_id" not in pdp_context or "env_id" not in pdp_context:
            logger.warning("Didn't get org_id, project_id, or env_id context from backend.")
            return
        logger.info("PDP started at: ")
        logger.info("  org_id:     {}", UUID(pdp_context["org_id"]))
        logger.info("  project_id: {}", UUID(pdp_context["project_id"]))
        logger.info("  env_id:     {}", UUID(pdp_context["env_id"]))

    def _configure_monitoring(self):
        """
        patch fastapi to enable tracing and monitoring
        """
        from ddtrace import config, patch

        # Datadog APM
        patch(fastapi=True)
        # Override service name
        config.fastapi["service_name"] = "permit-pdp"
        config.fastapi["request_span_name"] = "permit-pdp"

    def _configure_cloud_logging(self, remote_context: dict | None = None):
        if not sidecar_config.CENTRAL_LOG_ENABLED:
            return

        if not sidecar_config.CENTRAL_LOG_TOKEN or len(sidecar_config.CENTRAL_LOG_TOKEN) == 0:
            logger.warning("Centralized log is enabled, but token is not valid. Disabling sink.")
            return

        logzio_handler = LogzioHandler(
            token=sidecar_config.CENTRAL_LOG_TOKEN,
            logs_drain_timeout=sidecar_config.CENTRAL_LOG_DRAIN_TIMEOUT,
            url=sidecar_config.CENTRAL_LOG_DRAIN_URL,
        )
        formatter = Formatter(opal_common_config.LOG_FORMAT)

        # adds extra context to all loggers, helps identify between different sidecars.
        extra_context = {}
        extra_context["run_id"] = uuid4().hex
        extra_context.update(remote_context or {})

        logger.info(f"Adding the following context to all loggers: {extra_context}")

        logger.configure(extra=extra_context)
        logger.add(
            logzio_handler,
            serialize=True,
            level=logging.INFO,
            format=formatter.format,
            colorize=False,  # no colors
            enqueue=True,  # make sure logging to cloud is done asyncronously and thread-safe
            catch=True,  # if sink throws exceptions, swallow them as not critical
        )

    def _configure_inline_opa_config(self):
        # Start from the existing config
        inline_opa_config = opal_client_config.INLINE_OPA_CONFIG.dict()

        logger.debug(f"existing OPAL_INLINE_OPA_CONFIG={inline_opa_config}")

        if sidecar_config.OPA_DECISION_LOG_ENABLED:
            # decision logs needs to be configured via the config file
            config_file_path = get_opa_config_file_path(sidecar_config)

            # append the config file to inline OPA config
            inline_opa_config.update({"config_file": config_file_path})

        if sidecar_config.OPA_BEARER_TOKEN_REQUIRED:
            # overrides OPAL client config so that OPAL passes the bearer token in requests
            opal_client_config.POLICY_STORE_AUTH_TOKEN = get_env_api_key()
            opal_client_config.POLICY_STORE_AUTH_TYPE = PolicyStoreAuth.TOKEN

            # append the bearer token authz policy to inline OPA config
            auth_policy_file_path = get_opa_authz_policy_file_path(sidecar_config)
            inline_opa_config.update(
                {
                    "authorization": "basic",
                    "authentication": "token",
                    "files": [auth_policy_file_path],
                }
            )

        logger.debug(f"setting OPAL_INLINE_OPA_CONFIG={inline_opa_config}")

        # apply inline OPA config to OPAL client config var
        opal_client_config.INLINE_OPA_CONFIG = OpaServerOptions(**inline_opa_config)

        # override OPAL client default config to show OPA logs
        if sidecar_config.OPA_DECISION_LOG_CONSOLE:
            opal_client_config.INLINE_OPA_LOG_FORMAT = EngineLogFormat.FULL
            exclude_list: list[str] = opal_common_config.LOG_MODULE_EXCLUDE_LIST.copy()
            if OPA_LOGGER_MODULE in exclude_list:
                exclude_list.remove(OPA_LOGGER_MODULE)
                opal_common_config.LOG_MODULE_EXCLUDE_LIST = exclude_list

    def _configure_opal_data_updater(self):
        # Retry 10 times with (random) exponential backoff (wait times up to 1, 2, 4, 6, 8, 16, 32, 64, 128, 256 secs),
        # and overall timeout of 64 seconds
        opal_client_config.DATA_UPDATER_CONN_RETRY = ConnRetryOptions(
            wait_strategy="random_exponential",
            attempts=14,
            wait_time=1,
        )

    def _configure_opal_offline_mode(self):
        """
        configure opal to use offline mode when enabled
        """
        opal_client_config.OFFLINE_MODE_ENABLED = sidecar_config.ENABLE_OFFLINE_MODE
        opal_client_config.STORE_BACKUP_PATH = (
            Path(sidecar_config.OFFLINE_MODE_BACKUP_DIR) / sidecar_config.OFFLINE_MODE_POLICY_BACKUP_FILENAME
        )

    def _fix_data_topics(self) -> list[str]:
        """
        This is a worksaround for the following issue:
        Permit backend services use the topic 'policy_data/{client_id}' to configure PDPs and to publish data updates.
        However, opal-server is configured to return DataSourceConfig with the topic 'policy_data'
         (without the client_id suffix) from `/scope/{client_id}/data` endpoint.
        In the new OPAL client, this is an issue since data updater validates DataSourceConfig's topics
        against its configured data topics.

        Simply fixing the backend to use the shorter topic everywhere is problematic since it would require a breaking
        change / migration for all clients.
        The shorter version logically includes the longer version so it's fine having OPAL listen to the
        shorter version when updates are still published to the longer one.

        We don't edit `opal_client_config.DATA_TOPICS` directly because relay's ping reports it -
        and reported subscribed topics are expected to match the topics used in publish.
            (relay ignores the hierarchical structure of topics - this could be fixed in the future)
        """
        if opal_client_config.SCOPE_ID == "default":
            return opal_client_config.DATA_TOPICS

        return [
            topic.removesuffix(f"/{opal_client_config.SCOPE_ID}")  # Only remove suffix if it's of the expected form
            for topic in opal_client_config.DATA_TOPICS
        ]

    def _override_app_metadata(self, app: FastAPI):
        app.title = "Permit.io PDP"
        app.description = (
            "The PDP (Policy decision point) container wraps Open Policy Agent (OPA) with a higher-level API intended "
            "for fine grained application-level authorization. The PDP automatically handles pulling policy updates in "
            "real-time from a centrally managed cloud-service (api.permit.io)."
        )
        app.version = "0.2.0"
        app.openapi_tags = sidecar_config.OPENAPI_TAGS_METADATA
        return app

    def _configure_api_routes(self, app: FastAPI):
        """
        mounts the api routes on the app object
        """

        # Init api routers with required dependencies
        app.on_event("startup")(stats_manager.run)
        app.on_event("shutdown")(stats_manager.stop_tasks)

        enforcer_router = init_enforcer_api_router(policy_store=self._opal.policy_store)
        local_router = init_local_cache_api_router(policy_store=self._opal.policy_store)
        # Init system router
        system_router = init_system_api_router()

        # include the api routes
        app.include_router(
            enforcer_router,
            tags=["Authorization API"],
        )

        app.include_router(
            local_router,
            prefix="/local",
            tags=["Local Queries"],
            dependencies=[Depends(enforce_pdp_token)],
        )
        app.include_router(
            system_router,
            include_in_schema=False,
        )
        app.include_router(
            proxy_router,
            tags=["Cloud API Proxy"],
            dependencies=[Depends(enforce_pdp_token)],
        )
        app.include_router(
            facts_router,
            prefix="/facts",
            tags=["Local Facts API"],
            dependencies=[Depends(enforce_pdp_token)],
        )
        app.include_router(
            facts_router,
            prefix="/v2/facts/{proj_id}/{env_id}",
            tags=["Local Facts API (compat)"],
            include_in_schema=False,
            dependencies=[Depends(enforce_pdp_token)],
        )

        # TODO: remove this when clients update sdk version (legacy routes)
        @app.post(
            "/update_policy",
            status_code=status.HTTP_200_OK,
            include_in_schema=False,
            dependencies=[Depends(enforce_pdp_token)],
        )
        async def legacy_trigger_policy_update():
            response = RedirectResponse(url="/policy-updater/trigger")
            return response

        @app.post(
            "/update_policy_data",
            status_code=status.HTTP_200_OK,
            include_in_schema=False,
            dependencies=[Depends(enforce_pdp_token)],
        )
        async def legacy_trigger_data_update():
            response = RedirectResponse(url="/data-updater/trigger")
            return response

    @property
    def app(self):
        return self._app

    def _verify_config(self):
        if get_env_api_key() == MOCK_API_KEY:
            logger.critical("No API key specified. Please specify one with the PDP_API_KEY environment variable.")
            raise SystemExit(GUNICORN_EXIT_APP)

    def _inject_extra_callbacks(self) -> None:
        register = self._opal._callbacks_register  # type: ignore
        default_config = HttpFetcherConfig(
            method=HttpMethods.POST,
            headers={"content-type": "application/json"},
            process_data=False,
            fetcher=None,
        )
        for entry in sidecar_config.DATA_UPDATE_CALLBACKS:
            entry.config = entry.config or default_config
            entry.key = entry.key or register.calc_hash(entry.url, entry.config)

            if register.get(entry.key):
                raise RuntimeError(f"Callback with key '{entry.key}' already exists. Please specify a different key.")

            logger.info(f"Registering data update callback to url '{entry.url}' with key '{entry.key}'")
            register.put(entry.url, entry.config, entry.key)

    def _remove_ignored_default_callbacks_urls(self) -> None:
        register = self._opal._callbacks_register  # type: ignore
        if not sidecar_config.IGNORE_DEFAULT_DATA_UPDATE_CALLBACKS_URLS:
            return
        # we convert the generator to a list because we are modifying the register while iterating over it
        for callback in list(register.all()):
            if callback.url in sidecar_config.IGNORE_DEFAULT_DATA_UPDATE_CALLBACKS_URLS:
                logger.info(f"Removing callback '{callback.url}' from the register")
                register.remove(callback.key)
