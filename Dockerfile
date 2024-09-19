# OPA BUILD STAGE -----------------------------------
# build opa from source or download precompiled binary
# ---------------------------------------------------
FROM golang:bullseye AS opa_build

COPY custom* /custom

RUN if [ -f /custom/custom_opa.tar.gz ]; \
    then \
      cd /custom && \
      tar xzf custom_opa.tar.gz && \
      go build -o /opa && \
      rm -rf /custom ; \
    else \
      case $(uname -m) in \
      	x86_64) \
      		curl -L -o /opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static ; \
      		;; \
      	aarch64) \
      		curl -L -o /opa https://openpolicyagent.org/downloads/latest/opa_linux_arm64_static ; \
      		;; \
      	*) \
      		echo "Unknown architecture." ; \
      		exit 1 ; \
      		;; \
      esac ; \
    fi

# MAIN IMAGE ----------------------------------------
# most of the time only this image should be built
# ---------------------------------------------------
FROM python:3.10-alpine

WORKDIR /app

RUN addgroup -S permit -g 1001
RUN adduser -S -s /bin/bash -u 1000 -G permit -h /home/permit permit

# install linux libraries necessary to compile some python packages
RUN apk update && \
    apk add --no-cache bash build-base libffi-dev libressl-dev musl-dev zlib-dev gcompat

# Copy custom opa binary
RUN mkdir /app/bin
RUN chown -R permit:permit /app/bin
COPY --from=opa_build --chmod=755 /opa /app/bin/opa

# bash is needed for ./start/sh script
COPY scripts ./

RUN mkdir -p /config
RUN chown -R permit:permit /config

# copy wait-for-it (use only for development! e.g: docker compose)
COPY scripts/wait-for-it.sh /usr/wait-for-it.sh
RUN chmod +x /usr/wait-for-it.sh

# copy startup script
COPY ./scripts/start.sh ./start.sh
RUN chmod +x ./start.sh

RUN chown -R permit:permit /home/permit
RUN chown -R permit:permit /usr/
USER permit

# copy Kong route-to-resource translation table
COPY kong_routes.json /config/kong_routes.json

# copy gunicorn_config
COPY ./scripts/gunicorn_conf.py ./gunicorn_conf.py

# install python dependencies
COPY ./requirements.txt ./requirements.txt
RUN pip install -r requirements.txt
RUN python -m pip uninstall -y pip setuptools
RUN rm -r /usr/local/lib/python3.10/ensurepip

# copy app code
COPY ./horizon ./horizon

# Make sure scripts in .local are usable:
ENV PATH="/:/app/bin:/home/permit/.local/bin:$PATH"
# uvicorn config ------------------------------------

# WARNING: do not change the number of workers on the opal client!
# only one worker is currently supported for the client.

# number of uvicorn workers
ENV UVICORN_NUM_WORKERS=1
# uvicorn asgi app
ENV UVICORN_ASGI_APP="horizon.main:app"
# uvicorn port
ENV UVICORN_PORT=7000

# opal configuration --------------------------------
ENV OPAL_SERVER_URL="https://opal.permit.io"
ENV OPAL_LOG_DIAGNOSE="false"
ENV OPAL_LOG_TRACEBACK="false"
ENV OPAL_LOG_MODULE_EXCLUDE_LIST="[]"
ENV OPAL_INLINE_OPA_ENABLED="true"
ENV OPAL_INLINE_OPA_LOG_FORMAT="http"

# horizon configuration -----------------------------
# by default, the backend is at port 8000 on the docker host
# in prod, you must pass the correct url
ENV PDP_CONTROL_PLANE="https://api.permit.io"
ENV PDP_API_KEY="MUST BE DEFINED"
ENV PDP_REMOTE_CONFIG_ENDPOINT="/v2/pdps/me/config"
ENV PDP_REMOTE_STATE_ENDPOINT="/v2/pdps/me/state"
ENV PDP_VERSION_FILE_PATH="/app/permit_pdp_version"
# expose sidecar port
EXPOSE 7000
# expose opa directly
EXPOSE 8181
# run gunicorn
CMD ["/app/start.sh"]
