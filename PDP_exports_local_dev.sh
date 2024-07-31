export UVICORN_NUM_WORKERS=1
export UVICORN_ASGI_APP=horizon.main:app
export UVICORN_PORT=7000
export OPAL_SERVER_URL=https://opal.permit.io
export OPAL_LOG_DIAGNOSE=false
export OPAL_LOG_TRACEBACK=false
export OPAL_LOG_MODULE_EXCLUDE_LIST="[]"
export OPAL_INLINE_OPA_ENABLED=true
export OPAL_INLINE_OPA_LOG_FORMAT=http
export PDP_CONTROL_PLANE=https://api.permit.io
export PDP_API_KEY="permit_key_5Kpnc7qzbsHrPRXyAPfIf6huhX7kqeXqc2uhMtXGQX8dz8Fyo0fOBCjAlTBH9CETLDWs0Ct1ihPgH6hzx4A5Ik"
export PDP_REMOTE_CONFIG_ENDPOINT=/v2/pdps/me/config
export PDP_REMOTE_STATE_ENDPOINT=/v2/pdps/me/stateps aux | grep nginx
export PDP_VERSION_FILENAME="1.0.0"

