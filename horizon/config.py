import os

from opal_common.confi import Confi

confi = Confi(prefix="HORIZON_")

# Authorizon Sidecar configuration --------------------------------------------
_acalla_backend_url = confi.str("BACKEND_SERVICE_URL", "http://localhost:8000")

# backend api url, where proxy requests go
BACKEND_SERVICE_URL = f"{_acalla_backend_url}/v1"
BACKEND_SERVICE_LEGACY_URL = f"{_acalla_backend_url}/sdk"

# access token to access backend api
CLIENT_TOKEN = confi.str("CLIENT_TOKEN", "PJUKkuwiJkKxbIoC4o4cguWxB_2gX6MyATYKc2OCM")

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