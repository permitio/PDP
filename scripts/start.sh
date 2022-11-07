#!/bin/bash
set -e

export GUNICORN_CONF=${GUNICORN_CONF:-/gunicorn_conf.py}
ddtrace=""
if [ "${PDP_ENABLE_MONITORING}" == "true" ]
then
    ddtrace=ddtrace-run
fi
exec $ddtrace gunicorn -b 0.0.0.0:${UVICORN_PORT} -k uvicorn.workers.UvicornWorker --workers=${UVICORN_NUM_WORKERS} -c ${GUNICORN_CONF} ${UVICORN_ASGI_APP}
