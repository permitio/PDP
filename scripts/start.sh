#!/bin/bash

export GUNICORN_CONF=${GUNICORN_CONF:-/gunicorn_conf.py}
export GUNICORN_TIMEOUT=${GUNICORN_TIMEOUT:-600}
ddtrace=""
if [ "${PDP_ENABLE_MONITORING}" == "true" ]
then
    ddtrace=ddtrace-run
fi
$ddtrace gunicorn -b 0.0.0.0:${UVICORN_PORT} -k uvicorn.workers.UvicornWorker --workers=${UVICORN_NUM_WORKERS} -c ${GUNICORN_CONF} ${UVICORN_ASGI_APP} --timeout ${GUNICORN_TIMEOUT}
return_code=$?

if [ "$return_code" == 3 ]
then
	# The _exit route was used, change the 3 to a 0
	exit 0
fi

exit $return_code
