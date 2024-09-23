# OPA BUILD STAGE -----------------------------------
# build opa from source or download precompiled binary
# ---------------------------------------------------
FROM golang:bullseye AS opa_build

COPY custom* /custom
COPY datasync* /datasync

RUN if [ -f /custom/custom_opa.tar.gz ]; \
  then \
  cd /custom && \
  tar xzf custom_opa.tar.gz && \
  go build -ldflags="-extldflags=-static" -o /opa && \
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

RUN if [ -f /datasync/datasync.tar.gz ]; \
  then \
  cd /datasync && \
  tar xzf datasync.tar.gz && \
  go build -ldflags="-extldflags=-static" -o /factstore ./cmd/factstore_server && \
  rm -rf /datasync ; \
  else \
  case $(uname -m) in \
  x86_64) \
    if [ -f /datasync/factstore_server-linux-amd64 ]; then \
      cp /datasync/factstore_server-linux-amd64 /factstore; \
    else \
      echo "factstore_server-linux-amd64 not found." ; \
      if [ "$ALLOW_MISSING_FACTSTORE" = "false" ]; then \
        echo "Missing Factstore is not allowed, exiting..."; exit 1; \
      else \
        echo "Missing Factstore is allowed, continuing..."; \
        touch /factstore ; \
      fi \
    fi \
  ;; \
  aarch64) \
    if [ -f /datasync/factstore_server-linux-arm64 ]; then \
      cp /datasync/factstore_server-linux-arm64 /factstore; \
    else \
      echo "factstore_server-linux-arm64 not found." ; \
      if [ "$ALLOW_MISSING_FACTSTORE" = "false" ]; then \
        echo "Missing Factstore is not allowed, exiting..."; exit 1; \
      else \
        echo "Missing Factstore is allowed, continuing..."; \
        touch /factstore ; \
      fi \
    fi \
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

# create backup directory
RUN mkdir -p /app/backup && chmod -R 777 /app/backup

# install linux libraries necessary to compile some python packages
RUN apk update && \
    apk add --no-cache bash build-base libffi-dev libressl-dev musl-dev zlib-dev gcompat

# Copy custom opa binary
RUN mkdir /app/bin
RUN chown -R permit:permit /app/bin
COPY --from=opa_build --chmod=755 /opa /app/bin/opa
COPY --from=opa_build --chmod=755 /factstore /app/bin/factstore

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

# copy version file
COPY ./permit_pdp_version /app/permit_pdp_version

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
ENV PDP_DATA_MANAGER_BINARY_PATH="/app/bin/factstore"
# This is a default PUBLIC (not secret) key,
# and it is here as a safety measure on purpose.
ENV OPAL_AUTH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDe2iQ+/E01P2W5/EZwD5NpRiSQ8/r/k18pFnym+vWCSNMWpd9UVpgOUWfA9CAX4oEo5G6RfVVId/epPH/qVSL87uh5PakkLZ3E+PWVnYtbzuFPs/lHZ9HhSqNtOQ3WcPDTcY/ST2jyib2z0sURYDMInSc1jnYKqPQ6YuREdoaNdPHwaTFN1tEKhQ1GyyhL5EDK97qU1ejvcYjpGm+EeE2sjauHYn2iVXa2UA9fC+FAKUwKqNcwRTf3VBLQTE6EHGWbxVzXv1Feo8lPZgL7Yu/UPgp7ivCZhZCROGDdagAfK9sveYjkKiWCLNUSpado/E5Vb+/1EVdAYj6fCzk45AdQzA9vwZefP0sVg7EuZ8VQvlz7cU9m+XYIeWqduN4Qodu87rtBYtSEAsru/8YDCXBDWlLJfuZb0p/klbte3TayKnQNSWD+tNYSJHrtA/3ZewP+tGDmtgLeB38NLy1xEsgd31v6ISOSCTHNS8ku9yWQXttv0/xRnuITr8a3TCLuqtUrNOhCx+nKLmYF2cyjYeQjOWWpn/Z6VkZvOa35jhG1ETI8IwE+t5zXqrf2s505mh18LwA1DhC8L/wHk8ZG7bnUe56QwxEo32myUBN8nHdu7XmPCVP8MWQNLh406QRAysishWhXVs/+0PbgfBJ/FxKP8BXW9zqzeIG+7b/yk8tRHQ=="
# expose sidecar port
EXPOSE 7000
# expose opa directly
EXPOSE 8181

# run gunicorn
CMD ["/app/start.sh"]
