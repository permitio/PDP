from typing import Any

from opal_common.confi import Confi, confi
from opal_common.schemas.data import CallbackEntry
from pydantic import parse_obj_as, parse_raw_as

MOCK_API_KEY = "MUST BE DEFINED"


# scopes enum
class ApiKeyLevel(str):
    ORGANIZATION = "organization"
    PROJECT = "project"
    ENVIRONMENT = "environment"


class SidecarConfig(Confi):
    def __new__(cls, *, prefix=None, is_model=True):  # noqa: ARG004
        """creates a singleton object, if it is not created,
        or else returns the previous singleton object"""
        if not hasattr(cls, "instance"):
            cls.instance = super().__new__(cls)
        return cls.instance

    SHARD_ID = confi.str(
        "SHARD_ID",
        None,
        description="The shard id of this PDP, used to identify the PDP in the control plane",
    )

    CONTROL_PLANE = confi.str(
        "CONTROL_PLANE",
        "http://localhost:8000",
        description="URL to the control plane that manages this PDP, typically Permit.io cloud (api.permit.io)",
    )

    CONTROL_PLANE_PDP_DELTAS_API = confi.str(
        "CONTROL_PLANE_PDP_DELTAS_API",
        "http://localhost:8000",
        description="URL to the control plane's PDP deltas API",
    )

    CONTROL_PLANE_RELAY_API = confi.str(
        "CONTROL_PLANE_RELAY_API",
        "http://localhost:8001",
    )

    CONTROL_PLANE_RELAY_JWT_TIER = confi.str(
        "CONTROL_PLANE_RELAY_JWT_TIER",
        "http://localhost:8000",
        description="the backend tier that will be used to generate relay API JWTs",
    )

    # backend api url, where proxy requests go
    BACKEND_SERVICE_URL = confi.str("BACKEND_SERVICE_URL", confi.delay("{CONTROL_PLANE}/v1"))
    BACKEND_LEGACY_URL = confi.str("BACKEND_LEGACY_URL", confi.delay("{CONTROL_PLANE}/sdk"))

    # backend route to fetch policy data topics
    REMOTE_CONFIG_ENDPOINT = confi.str("REMOTE_CONFIG_ENDPOINT", "/v2/pdps/me/config")

    # backend route to push state changes
    REMOTE_STATE_ENDPOINT = confi.str("REMOTE_STATE_ENDPOINT", "/v2/pdps/me/state")

    # access token to access backend api
    API_KEY = confi.str(
        "API_KEY",
        MOCK_API_KEY,
        description="set this to your environment's API key if you prefer to use the environment level API key.",
    )

    # access token to your organization
    ORG_API_KEY = confi.str(
        "ORG_API_KEY",
        None,
        description="set this to your organization's API key if you prefer to use the organization level API key. "
        "By default, the PDP will use the project level API key",
    )

    # access token to your project
    PROJECT_API_KEY = confi.str(
        "PROJECT_API_KEY",
        None,
        description="set this to your project's API key if you prefer to use the project level API key. "
        "By default, the PDP will use the default project API key",
    )

    # chosen project id/key to use for the PDP
    ACTIVE_PROJECT = confi.str("ACTIVE_PROJECT", None, description="the project id/key to use for the PDP")

    # chosen environment id/key to use for the PDP
    ACTIVE_ENV = confi.str("ACTIVE_ENV", None, description="the environment id/key to use for the PDP")

    # access token to perform system control operations
    CONTAINER_CONTROL_KEY = confi.str("CONTAINER_CONTROL_KEY", MOCK_API_KEY)

    # if enabled, will output to log more data for each "is allowed" decision
    DECISION_LOG_DEBUG_INFO = confi.bool("DECISION_LOG_DEBUG_INFO", True)

    # if enabled, sidecar will output its full config when it first loads
    PRINT_CONFIG_ON_STARTUP = confi.bool("PRINT_CONFIG_ON_STARTUP", False)

    # enable datadog APM tracing
    ENABLE_MONITORING = confi.bool("ENABLE_MONITORING", False)

    ENABLE_OFFLINE_MODE = confi.bool(
        "ENABLE_OFFLINE_MODE",
        False,
        description="When true, sidecar will use a file backup to restore configuration and policy data when "
        "cloud services are unavailable",
    )

    OFFLINE_MODE_BACKUP_DIR = confi.str(
        "OFFLINE_MODE_BACKUP_DIR",
        "/app/backup",
        description="Dir path where pdp would backup its cloud configuration when in offline mode",
    )
    OFFLINE_MODE_BACKUP_FILENAME = confi.str(
        "OFFLINE_MODE_BACKUP_FILENAME",
        "pdp_cloud_config_backup.json",
        description="Filename for offline mode's cloud configuration backup",
    )
    OFFLINE_MODE_POLICY_BACKUP_FILENAME = confi.str(
        "OFFLINE_MODE_POLICY_BACKUP_FILENAME",
        "policy_store_backup.json",
        description="Filename for offline mode's policy backup (OPAL's offline mode backup)",
    )

    CONFIG_FETCH_MAX_RETRIES = confi.int(
        "CONFIG_FETCH_MAX_RETRIES",
        6,
        description="Number of times to retry fetching the sidecar configuration from control plane",
    )

    # centralized logging
    CENTRAL_LOG_DRAIN_URL = confi.str("CENTRAL_LOG_DRAIN_URL", "https://listener.logz.io:8071")
    CENTRAL_LOG_DRAIN_TIMEOUT = confi.int("CENTRAL_LOG_DRAIN_TIMEOUT", 5)
    CENTRAL_LOG_TOKEN = confi.str("CENTRAL_LOG_TOKEN", None)
    CENTRAL_LOG_ENABLED = confi.bool("CENTRAL_LOG_ENABLED", False)

    PING_INTERVAL = confi.int(
        "PING_INTERVAL",
        10,
    )

    OPA_CLIENT_QUERY_TIMEOUT = confi.float(
        "OPA_CLIENT_QUERY_TIMEOUT",
        1,  # aiohttp's default timeout is 5m, we want to be more aggressive
        description="the timeout for querying OPA for an allow decision, in seconds. 0 means no timeout",
    )
    OPA_CLIENT_FAILURE_THRESHOLD_PERCENTAGE = confi.float(
        "OPA_CLIENT_FAILURE_THRESHOLD",
        0.1,
        description="the percentage of failed requests to OPA that will trigger a failure threshold",
    )
    OPA_CLIENT_FAILURE_THRESHOLD_INTERVAL = confi.float(
        "OPA_CLIENT_FAILURE_THRESHOLD_INTERVAL",
        60,
        description="the interval (in seconds) to calculate the failure threshold",
    )

    # internal OPA config
    OPA_CONFIG_FILE_PATH = confi.str(
        "OPA_CONFIG_FILE_PATH",
        "~/opa/config.yaml",
        description="the path on the container for OPA config file",
    )
    OPA_AUTH_POLICY_FILE_PATH = confi.str(
        "OPA_AUTH_POLICY_FILE_PATH",
        "~/opa/basic-authz.rego",
        description="the path on the container for OPA authorization policy (rego file)",
    )
    OPA_BEARER_TOKEN_REQUIRED = confi.bool(
        "OPA_BEARER_TOKEN_REQUIRED",
        True,
        description="if true, all API calls to OPA must provide a bearer token (the value of CLIENT_TOKEN)",
    )
    OPA_DECISION_LOG_ENABLED = confi.bool(
        "OPA_DECISION_LOG_ENABLED",
        True,
        description="if true, OPA decision logs will be uploaded to the Permit.io cloud console",
    )
    OPA_DECISION_LOG_CONSOLE = confi.bool(
        "OPA_DECISION_LOG_CONSOLE",
        False,
        description="if true, OPA decision logs will also be printed to console "
        "(only relevant if `OPA_DECISION_LOG_ENABLED` is true)",
    )
    OPA_DECISION_LOG_INGRESS_ROUTE = confi.str(
        "OPA_DECISION_LOG_INGRESS_ROUTE",
        "/v1/decision_logs/ingress",
        description="the route on the backend the decision logs will be uploaded to",
    )
    OPA_DECISION_LOG_INGRESS_BACKEND_TIER_URL = confi.str(
        "OPA_DECISION_LOG_INGRESS_BACKEND_TIER_URL",
        None,
        description="the backend tier that decision logs will be uploaded to",
    )
    OPA_DECISION_LOG_MIN_DELAY = confi.int(
        "OPA_DECISION_LOG_MIN_DELAY",
        1,
        description="min amount of time (in seconds) to wait between decision log uploads",
    )
    OPA_DECISION_LOG_MAX_DELAY = confi.int(
        "OPA_DECISION_LOG_MAX_DELAY",
        10,
        description="max amount of time (in seconds) to wait between decision log uploads",
    )
    OPA_DECISION_LOG_UPLOAD_SIZE_LIMIT = confi.int(
        "OPA_DECISION_LOG_UPLOAD_SIZE_LIMIT",
        65536,  # This is twice as much the default OPA value (32768)
        description="log upload size limit in bytes. OPA will chunk uploads to cap message body to this limit",
    )

    # allow access to metrics endpoint without auth
    ALLOW_METRICS_UNAUTHENTICATED = confi.bool(
        "ALLOW_METRICS_UNAUTHENTICATED",
        False,
        description="if true, the /metrics endpoint will be accessible without authentication",
    )

    # temp log format (until cloud config is received)
    TEMP_LOG_FORMAT = confi.str(
        "TEMP_LOG_FORMAT",
        "<green>{time}</green> | {process} | <blue>{name: <40}</blue>|<level>{level:^6} | {message}</level>",
    )

    IS_DEBUG_MODE = confi.bool("DEBUG", None)

    # enables the Kong integration endpoint. This shouldn't be enabled unless needed, as it's unauthenticated
    KONG_INTEGRATION = confi.bool("KONG_INTEGRATION", False)
    # enables debug ouptut for the Kong integration endpoint
    KONG_INTEGRATION_DEBUG = confi.bool("KONG_INTEGRATION_DEBUG", False)

    LOCAL_FACTS_WAIT_TIMEOUT = confi.float(
        "LOCAL_FACTS_WAIT_TIMEOUT",
        10,
        description="The amount of time in seconds to wait for the local facts to be synced before timing out",
    )
    VERSION_FILE_PATH = confi.str(
        "VERSION_FILE_PATH",
        "/permit_pdp_version",
        description="The path to the file that contains the PDP version",
    )

    @staticmethod
    def parse_callbacks(value: Any) -> list[CallbackEntry]:
        if isinstance(value, str):
            return parse_raw_as(list[CallbackEntry], value)
        else:
            return parse_obj_as(list[CallbackEntry], value)

    DATA_UPDATE_CALLBACKS: list[CallbackEntry] = confi.str(
        "DATA_UPDATE_CALLBACKS",
        [],
        description="List of callbacks to be triggered when data is updated",
        cast=parse_callbacks,
        cast_from_json=parse_callbacks,
    )

    # Cache configuration
    CACHE_ENABLED = confi.bool(
        "CACHE_ENABLED",
        False,
        description="If true, enables caching for specific PDP endpoints",
    )

    CACHE_TTL_SEC = confi.int(
        "CACHE_TTL_SEC",
        3600,  # 1 hour default
        description="TTL for cached PDP responses in seconds",
    )

    # non configurable values -------------------------------------------------

    # redoc configuration (openapi schema)
    OPENAPI_TAGS_METADATA = [  # noqa: RUF012
        {
            "name": "Authorization API",
            "description": "Authorization queries to OPA. These queries are answered locally by OPA "
            + "and do not require the cloud service. Latency should be very low (< 20ms per query)",
        },
        {
            "name": "Local Queries",
            "description": "These queries are done locally against the sidecar and do not "
            + "involve a network round-trip to Permit.io cloud API. Therefore they are safe "
            + "to use with reasonable performance (i.e: with negligible latency) in the context of a user request.",
        },
        {
            "name": "Policy Updater",
            "description": "API to manually trigger and control the local policy caching and refetching.",
        },
        {
            "name": "Cloud API Proxy",
            "description": (
                "These endpoints proxy the Permit.io cloud api, and therefore **incur high-latency**. "
                "You should not use the cloud API in the standard request flow of users, i.e in places "
                "where the incurred added latency will affect your entire api. "
                "A good place to call the cloud API will be in one-time user events such as user registration "
                "(i.e: calling sync user, assigning initial user roles, etc.). "
                "The sidecar will proxy to the cloud every request prefixed with '/sdk'."
            ),
            "externalDocs": {
                "description": "The cloud api complete docs are located here:",
                "url": "https://api.permit.io/redoc",
            },
        },
    ]


sidecar_config = SidecarConfig(prefix="PDP_")
