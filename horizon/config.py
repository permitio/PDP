import json
import re
from enum import StrEnum
from typing import Any, ClassVar

from opal_common.confi import Confi, confi
from opal_common.schemas.data import CallbackEntry
from pydantic import parse_obj_as, parse_raw_as

# One-way import edge, config -> debounce: the default lives beside the clamp that falls back
# to it, so a value this module declares and a value the debouncer substitutes can never drift.
# horizon.debounce must never import this module back (it takes its window as a parameter).
from horizon.debounce import DEFAULT_DEBOUNCE_SECONDS

MOCK_API_KEY = "MUST BE DEFINED"

IGNORED_CALLBACK_URLS_SETTING = "PDP_IGNORE_DEFAULT_DATA_UPDATE_CALLBACKS_URLS"
_SHOWN_VALUE_MAX_CHARS = 200


def _invalid_ignored_callback_urls(raw: Any, reason: str) -> ValueError:
    """Build the startup error for a malformed ignored-callback-URLs setting.

    It names the problem, shows the value, and lists every accepted form, so the operator can fix
    the configuration from the error alone.
    """
    shown = raw if isinstance(raw, str) else json.dumps(raw, default=str)
    if len(shown) > _SHOWN_VALUE_MAX_CHARS:
        shown = shown[:_SHOWN_VALUE_MAX_CHARS] + "..."
    return ValueError(
        f"{IGNORED_CALLBACK_URLS_SETTING} is invalid: {reason}.\n"
        f"  Got: {shown}\n"
        "  Set it to one of:\n"
        '    - a JSON list of double-quoted URLs: ["http://localhost:8181/v1/data/permit/rebac/cache_rebuild"]\n'
        "    - URLs separated by commas or spaces: http://host-a/callback, http://host-b/callback\n"
        "    - an empty value, to keep every default data-update callback\n"
        "  Each URL must equal a registered data-update callback URL exactly."
    )


def _json_syntax_reason(raw: str, error: json.JSONDecodeError) -> str:
    """Explain why JSON-shaped text did not parse, naming the usual mistakes."""
    reason = f"it starts like JSON but is not valid JSON ({error.msg} at character {error.pos})"
    if "'" in raw and '"' not in raw:
        return f"{reason}: JSON needs double quotes around each URL; single quotes (a Python-style list) are not JSON"
    if re.search(r",\s*[\]}]", raw):
        return f"{reason}: remove the trailing comma before the closing bracket"
    if re.search(r"\[\s*[^\s\"\[\]{}]", raw):
        return f"{reason}: put each URL in double quotes"
    return reason


class ApiKeyLevel(StrEnum):
    ORGANIZATION = "organization"
    PROJECT = "project"
    ENVIRONMENT = "environment"


class SidecarConfig(Confi):
    # Declared, not assigned: __new__ below sets it on first construction (hasattr is False until then).
    instance: ClassVar["SidecarConfig"]

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

    CONTROL_PLANE_TIMEOUT = confi.float(
        "CONTROL_PLANE_TIMEOUT",
        75,
        description="Timeout in seconds for control plane requests",
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
        description="set this to your organization's API key if you prefer to use the organization level API key; "
        "it needs PDP_ACTIVE_PROJECT and PDP_ACTIVE_ENV. Ignored when PDP_API_KEY or PDP_PROJECT_API_KEY is set",
    )

    # access token to your project
    PROJECT_API_KEY = confi.str(
        "PROJECT_API_KEY",
        None,
        description="set this to your project's API key if you prefer to use the project level API key; "
        "it needs PDP_ACTIVE_ENV, and the project comes from the key's own scope. Ignored when PDP_API_KEY is set",
    )

    # chosen project id/key, used with an organization API key
    ACTIVE_PROJECT = confi.str(
        "ACTIVE_PROJECT",
        None,
        description="the project id/key to use with PDP_ORG_API_KEY; ignored with PDP_PROJECT_API_KEY, "
        "whose scope names the project, and with PDP_API_KEY, which is already an environment's key",
    )

    # chosen environment id/key to use for the PDP
    ACTIVE_ENV = confi.str(
        "ACTIVE_ENV",
        None,
        description="the environment id/key to use with PDP_ORG_API_KEY or PDP_PROJECT_API_KEY; "
        "ignored with PDP_API_KEY, which is already an environment's key",
    )

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

    CONTROL_PLANE_CONNECTIVITY_DISABLED = confi.bool(
        "CONTROL_PLANE_CONNECTIVITY_DISABLED",
        False,
        description="When true (and ENABLE_OFFLINE_MODE is true), the PDP starts disconnected from the control plane "
        "and serves from a local backup. Can be toggled at runtime via the /control-plane/connectivity endpoints.",
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

    @staticmethod
    def parse_plugins(value: Any) -> dict[str, dict[str, int | bool | str]]:
        if isinstance(value, str):
            return parse_raw_as(dict[str, dict[str, int | bool | str]], value)
        return parse_obj_as(dict[str, dict[str, int | bool | str]], value)

    OPA_PLUGINS: dict[str, dict[str, int | bool | str]] = confi.str(  # ty: ignore[invalid-assignment]  # cast= sets the type
        "OPA_PLUGINS",
        {},
        description="List of plugins to be loaded into OPA, "
        "the key is the plugin name, the value is the plugin config. "
        "notice that the plugin MUST be registered in OPA for it to work, "
        "if it is not registered, OPA will fail to start",
        cast=parse_plugins,
        cast_from_json=parse_plugins,
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
    LOCAL_FACTS_TIMEOUT_POLICY = confi.str(
        "LOCAL_FACTS_TIMEOUT_POLICY",
        "ignore",
        description="The policy to use when the local facts wait timeout is reached. ",
    )
    VERSION_FILE_PATH = confi.str(
        "VERSION_FILE_PATH",
        "/permit_pdp_version",
        description="The path to the file that contains the PDP version",
    )

    HORIZON_NICENESS = confi.int(
        "HORIZON_NICENESS",
        10,
        description=(
            "The niceness value for the PDP Horizon process (Python process). "
            "Niceness values range from -20 (highest priority) to 19 (lowest priority) with 0 is neutral. "
            "Adjusting this can help manage CPU resource allocation. "
        ),
    )

    TRIGGER_DEBOUNCE_SECONDS = confi.float(
        "TRIGGER_DEBOUNCE_SECONDS",
        DEFAULT_DEBOUNCE_SECONDS,
        description=(
            "Debounce window, in seconds, for forced full reloads triggered via the API trigger routes "
            "(/policy-updater/trigger, /data-updater/trigger and their legacy /update_policy* aliases). "
            "A trigger arriving within this many seconds of the last one - or while a forced reload is "
            "already in flight - is coalesced instead of amplifying load onto the control plane, so data "
            "served by this PDP may lag a forced trigger by up to this many seconds. A coalesced trigger "
            "is never dropped: the PDP arms a background trailing reload that runs once the window "
            "expires, so staleness is bounded by this value rather than by whenever a client happens to "
            "trigger again. Under a sustained hammer that converges to one reload per window. Set to 0 to "
            "disable the time window; concurrent triggers are still collapsed into a single in-flight "
            "reload. Clamped to at most 300s. Values that cannot be interpreted as a non-negative number "
            "(null, a typo, a non-finite) FAIL SAFE to the default rather than disabling the mitigation - "
            "only an explicit, parseable 0 disables it. The effective value is logged at startup whenever "
            "it differs from what was configured. Remote-config overridable fleet-wide, so ops can raise "
            "it (e.g. to 30-60s under a degraded control plane) without shipping a release - but the "
            "remote config is fetched once during startup, so a change needs a PDP restart to take effect."
        ),
    )

    @staticmethod
    def parse_callbacks(value: Any) -> list[CallbackEntry]:
        if isinstance(value, str):
            return parse_raw_as(list[CallbackEntry], value)
        return parse_obj_as(list[CallbackEntry], value)

    DATA_UPDATE_CALLBACKS: list[CallbackEntry] = confi.str(  # ty: ignore[invalid-assignment]  # cast= sets the type
        "DATA_UPDATE_CALLBACKS",
        [],
        description="List of callbacks to be triggered when data is updated",
        cast=parse_callbacks,
        cast_from_json=parse_callbacks,
    )

    @staticmethod
    def parse_url_list(value: Any) -> list[str]:
        """Read the callback URLs to ignore, from the environment or a control-plane override.

        The Dockerfile sets a JSON list. Plain text is read as URLs separated by commas or
        whitespace, because the setting used to be a raw string and plain text worked then: an
        empty value is how a deployment clears the Dockerfile default and keeps every default
        callback, and a single URL was matched as well. ``None`` from the control plane is no URL.

        Quotes around a plain-text URL are dropped (``"http://host/path"`` reads as the URL), since
        a quoted URL could never equal a registered callback URL.

        Raises:
            ValueError: The value is JSON-shaped (it starts with ``[`` or ``{``) but is not a list
                of URL strings, or the control plane sent something other than a list. The
                message says what is wrong, shows the value and lists the accepted forms.
        """
        if value is None:
            return []
        parsed = value
        if isinstance(value, str):
            if not value.lstrip().startswith(("[", "{")):
                return [url.strip("\"'") for url in value.replace(",", " ").split() if url.strip("\"'")]
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as e:
                raise _invalid_ignored_callback_urls(value, _json_syntax_reason(value, e)) from e
        if not isinstance(parsed, list):
            kind = "a JSON object" if isinstance(parsed, dict) else f"a {type(parsed).__name__}"
            raise _invalid_ignored_callback_urls(value, f"it is {kind}, not a list of URLs")
        for index, item in enumerate(parsed):
            if not isinstance(item, str):
                raise _invalid_ignored_callback_urls(
                    value, f"item {index} is {json.dumps(item, default=str)}, which is not a URL in double quotes"
                )
        return [url.strip() for url in parsed if url.strip()]

    IGNORE_DEFAULT_DATA_UPDATE_CALLBACKS_URLS: list[str] = confi.str(  # ty: ignore[invalid-assignment]  # cast= sets the type
        "IGNORE_DEFAULT_DATA_UPDATE_CALLBACKS_URLS",
        [],
        description=(
            "Callback URLs to drop from the defaults, even if the control plane registers them: a JSON list, "
            "or URLs separated by commas. Each URL must equal a registered callback URL exactly. Empty drops none."
        ),
        cast=parse_url_list,
        cast_from_json=parse_url_list,
    )

    # non configurable values -------------------------------------------------

    # redoc configuration (openapi schema)
    OPENAPI_TAGS_METADATA = [  # noqa: RUF012
        {
            "name": "Authorization API",
            "description": "Authorization queries to OPA. These queries are answered locally by OPA "
            "and do not require the cloud service. Latency should be very low (< 20ms per query)",
        },
        {
            "name": "Local Queries",
            "description": "These queries are done locally against the sidecar and do not "
            "involve a network round-trip to Permit.io cloud API. Therefore they are safe "
            "to use with reasonable performance (i.e: with negligible latency) in the context of a user request.",
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
