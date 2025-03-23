# OPA BUILD STAGE -----------------------------------
# Build OPA from source or download precompiled binary
# ---------------------------------------------------
FROM golang:bullseye AS opa_build

COPY custom* /custom

# Build OPA binary if custom_opa.tar.gz is provided
RUN if [ -f /custom/custom_opa.tar.gz ]; \
  then \
    cd /custom && \
    tar xzf custom_opa.tar.gz && \
    go build -ldflags="-extldflags=-static" -o /opa && \
    rm -rf /custom; \
  else \
    case $(uname -m) in \
      x86_64) curl -L -o /opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static ;; \
      aarch64) curl -L -o /opa https://openpolicyagent.org/downloads/latest/opa_linux_arm64_static ;; \
      *) echo "Unknown architecture." && exit 1 ;; \
    esac; \
  fi

# MAIN IMAGE ----------------------------------------
# Main image setup (optimized)
# ---------------------------------------------------
FROM python:3.10-alpine

WORKDIR /app

# Create necessary user and group in a single step
RUN addgroup -S permit -g 1001 && \
    adduser -S -s /bin/bash -u 1000 -G permit -h /home/permit permit

# Create backup directory with permissions
RUN mkdir -p /app/backup && chmod -R 777 /app/backup

# Install necessary libraries in a single RUN command
RUN apk update && \
    apk add --no-cache bash build-base libffi-dev libressl-dev musl-dev zlib-dev gcompat re2

# Install abseil-cpp needed for google-re2
RUN git clone https://github.com/abseil/abseil-cpp.git /tmp/abseil-cpp && \
    cd /tmp/abseil-cpp && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_CXX_STANDARD=17 -DCMAKE_POSITION_INDEPENDENT_CODE=ON .. && \
    make && \
    make install && \
    rm -rf /tmp/abseil-cpp

# Copy OPA binary from the build stage
COPY --from=opa_build --chmod=755 /opa /app/bin/opa

# Environment variables for OPA
ENV OPAL_INLINE_OPA_EXEC_PATH="/app/bin/opa"

# Copy required scripts
COPY scripts /app/scripts

# Set permissions and ownership for the application
RUN mkdir -p /config && chown -R permit:permit /config
RUN chmod +x /app/scripts/wait-for-it.sh && \
    chmod +x /app/scripts/start.sh

# Ensure the `permit` user has the correct permissions for home directory and binaries
RUN chown -R permit:permit /home/permit /app /usr/local/bin

# Switch to permit user
USER permit

# Copy Kong routes and Gunicorn config
COPY kong_routes.json /config/kong_routes.json
COPY ./scripts/gunicorn_conf.py ./gunicorn_conf.py

USER root

# Install python dependencies in one command to optimize layer size
COPY ./requirements.txt ./requirements.txt
RUN pip install --upgrade pip setuptools && \
    CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib" pip install -r requirements.txt && \
    python -m pip uninstall -y pip setuptools && \
    rm -r /usr/local/lib/python3.10/ensurepip

USER permit

# Copy the application code
COPY ./horizon /app/horizon

# Version file for the application
COPY ./permit_pdp_version /app/permit_pdp_version

# Set the PATH to ensure the local binary paths are used
ENV PATH="/app/bin:/home/permit/.local/bin:$PATH"

# Uvicorn configuration
ENV UVICORN_NUM_WORKERS=1
ENV UVICORN_ASGI_APP="horizon.main:app"
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
# This is a default PUBLIC (not secret) key,
# and it is here as a safety measure on purpose.
ENV OPAL_AUTH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDe2iQ+/E01P2W5/EZwD5NpRiSQ8/r/k18pFnym+vWCSNMWpd9UVpgOUWfA9CAX4oEo5G6RfVVId/epPH/qVSL87uh5PakkLZ3E+PWVnYtbzuFPs/lHZ9HhSqNtOQ3WcPDTcY/ST2jyib2z0sURYDMInSc1jnYKqPQ6YuREdoaNdPHwaTFN1tEKhQ1GyyhL5EDK97qU1ejvcYjpGm+EeE2sjauHYn2iVXa2UA9fC+FAKUwKqNcwRTf3VBLQTE6EHGWbxVzXv1Feo8lPZgL7Yu/UPgp7ivCZhZCROGDdagAfK9sveYjkKiWCLNUSpado/E5Vb+/1EVdAYj6fCzk45AdQzA9vwZefP0sVg7EuZ8VQvlz7cU9m+XYIeWqduN4Qodu87rtBYtSEAsru/8YDCXBDWlLJfuZb0p/klbte3TayKnQNSWD+tNYSJHrtA/3ZewP+tGDmtgLeB38NLy1xEsgd31v6ISOSCTHNS8ku9yWQXttv0/xRnuITr8a3TCLuqtUrNOhCx+nKLmYF2cyjYeQjOWWpn/Z6VkZvOa35jhG1ETI8IwE+t5zXqrf2s505mh18LwA1DhC8L/wHk8ZG7bnUe56QwxEo32myUBN8nHdu7XmPCVP8MWQNLh406QRAysishWhXVs/+0PbgfBJ/FxKP8BXW9zqzeIG+7b/yk8tRHQ=="

# 7000 sidecar port
# 8181 opa port
EXPOSE 7000 8181

# Run the application using the startup script
CMD ["/app/scripts/start.sh"]
