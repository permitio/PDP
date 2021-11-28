import os

from opal_common.confi import Confi, confi


class SidecarConfig(Confi):
    BACKEND_URL = confi.str("BACKEND_URL", "http://localhost:8000")

    # backend api url, where proxy requests go
    BACKEND_SERVICE_URL = confi.str("BACKEND_SERVICE_URL", confi.delay("{BACKEND_URL}/v1"))
    BACKEND_LEGACY_URL = confi.str("BACKEND_LEGACY_URL", confi.delay("{BACKEND_URL}/sdk"))

    # backend route to fetch policy data topics
    PDP_CONFIG_ROUTE = confi.str("PDP_CONFIG_ROUTE", "pdps/me/config")

    # access token to access backend api
    CLIENT_TOKEN = confi.str("CLIENT_TOKEN", "PJUKkuwiJkKxbIoC4o4cguWxB_2gX6MyATYKc2OCM")

    # if enabled, will output to log more data for each "is allowed" decision
    DECISION_LOG_DEBUG_INFO = confi.bool("DECISION_LOG_DEBUG_INFO", True)

    # if enabled, sidecar will output its full config when it first loads
    PRINT_CONFIG_ON_STARTUP = confi.bool("PRINT_CONFIG_ON_STARTUP", False)

    # enable datadog APM tracing
    ENABLE_MONITORING = confi.bool("ENABLE_MONITORING", False)

    # centralized logging
    CENTRAL_LOG_DRAIN_URL = confi.str("CENTRAL_LOG_DRAIN_URL", "https://listener.logz.io:8071")
    CENTRAL_LOG_DRAIN_TIMEOUT = confi.int("CENTRAL_LOG_DRAIN_TIMEOUT", 5)
    CENTRAL_LOG_TOKEN = confi.str("CENTRAL_LOG_TOKEN", None)
    CENTRAL_LOG_ENABLED = confi.bool("CENTRAL_LOG_ENABLED", True)

    # internal OPA config
    OPA_CONFIG_FILE_PATH = confi.str("OPA_CONFIG_FILE_PATH", "~/opa/config.yaml", description="the path on the container for OPA config file")
    OPA_AUTH_POLICY_FILE_PATH = confi.str("OPA_AUTH_POLICY_FILE_PATH", "~/opa/basic-authz.rego", description="the path on the container for OPA authorization policy (rego file)")
    OPA_BEARER_TOKEN_REQUIRED = confi.bool("OPA_BEARER_TOKEN_REQUIRED", True, description="if true, all API calls to OPA must provide a bearer token (the value of CLIENT_TOKEN)")
    OPA_DECISION_LOG_ENABLED = confi.bool("OPA_DECISION_LOG_ENABLED", True, description="if true, OPA decision logs will be uploaded to the authorizon cloud console")
    OPA_DECISION_LOG_INGRESS_ROUTE = confi.str("OPA_DECISION_LOG_INGRESS_ROUTE", "/v1/decision_logs/ingress", description="the route on the backend the decision logs will be uploaded to")
    OPA_DECISION_LOG_MIN_DELAY = confi.int("OPA_DECISION_LOG_MIN_DELAY", 1, description="min amount of time (in seconds) to wait between decision log uploads")
    OPA_DECISION_LOG_MAX_DELAY = confi.int("OPA_DECISION_LOG_MAX_DELAY", 10, description="max amount of time (in seconds) to wait between decision log uploads")

    # non configurable values -------------------------------------------------

    # redoc configuration (openapi schema)
    OPENAPI_TAGS_METADATA = [
        {
            "name": "Authorization API",
            "description": "Authorization queries to OPA. These queries are answered locally by OPA " + \
                "and do not require the cloud service. Latency should be very low (< 20ms per query)"
        },
        {
            "name": "Local Queries",
            "description": "These queries are done locally against the sidecar and do not " + \
                "involve a network round-trip to Authorizon cloud API. Therefore they are safe " + \
                "to use with reasonable performance (i.e: with negligible latency) in the context of a user request.",
        },
        {
            "name": "Policy Updater",
            "description": "API to manually trigger and control the local policy caching and refetching."
        },
        {
            "name": "Cloud API Proxy",
            "description": "These endpoints proxy the Authorizon cloud api, and therefore **incur high-latency**. " + \
                "You should not use the cloud API in the standard request flow of users, i.e in places where the incurred " + \
                "added latency will affect your entire api. A good place to call the cloud API will be in one-time user events " + \
                "such as user registration (i.e: calling sync user, assigning initial user roles, etc.). " + \
                "The sidecar will proxy to the cloud every request prefixed with '/sdk'.",
            "externalDocs": {
                "description": "The cloud api complete docs are located here:",
                "url": "https://api.authorizon.com/redoc",
            },
        }
    ]

sidecar_config = SidecarConfig(prefix="HORIZON_")