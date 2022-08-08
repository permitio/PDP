#!/bin/sh

printf '\x1b]0;%s\x07' "Sidecar"
PDP_API_KEY=$1 PDP_REMOTE_CONFIG_ENDPOINT=/v2/pdps/me/config uvicorn horizon.main:app --reload --port=7000
