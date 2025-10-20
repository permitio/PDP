ARG OPA_BUILD=permit
# RUST BUILD STAGE -----------------------------------
# Build the Rust PDP binary for all targets
# ----------------------------------------------------
# BIG thanks to
# - https://medium.com/@vladkens/fast-multi-arch-docker-build-for-rust-projects-a7db42f3adde
# - https://stackoverflow.com/questions/70561544/rust-openssl-could-not-find-directory-of-openssl-installation
# couldn't get this to work without the help of those two sources
# (1) this stage will be run always on current arch
# zigbuild & Cargo targets added
FROM --platform=$BUILDPLATFORM rust:1.85-alpine AS rust_chef
WORKDIR /app
ENV PKGCONFIG_SYSROOTDIR=/
RUN apk add --no-cache musl-dev openssl-dev zig pkgconf perl make

RUN cargo install --locked cargo-zigbuild cargo-chef
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# (2) nothing changed
FROM rust_chef AS rust_planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# (3) building project deps: need to specify all targets; zigbuild used
FROM rust_chef AS rust_builder
COPY --from=rust_planner /app/recipe.json recipe.json
ENV OPENSSL_DIR=/usr
RUN cargo chef cook --recipe-path recipe.json --release --zigbuild \
  --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl

# (4) actuall project build for all targets
# binary renamed to easier copy in runtime stage
COPY . .
RUN cargo zigbuild -r --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl && \
  mkdir -p /app/linux/arm64/ && \
  mkdir -p /app/linux/amd64/ && \
  cp target/aarch64-unknown-linux-musl/release/pdp-server /app/linux/arm64/pdp && \
  cp target/x86_64-unknown-linux-musl/release/pdp-server /app/linux/amd64/pdp


# OPA BUILD STAGE -----------------------------------
# Build OPA from source or download precompiled binary
# ---------------------------------------------------
FROM golang:bullseye AS opa_build

ARG TARGETARCH

COPY custom* /custom

# Build OPA binary if custom_opa.tar.gz is provided
RUN if [ -f /custom/custom_opa.tar.gz ]; \
  then \
    cd /custom && \
    tar xzf custom_opa.tar.gz && \
    GOOS=linux GOARCH=${TARGETARCH} go build -ldflags="-extldflags=-static" -o /opa && \
    rm -rf /custom; \
  else \
    case ${TARGETARCH} in \
      amd64) curl -L -o /opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static ;; \
      arm64) curl -L -o /opa https://openpolicyagent.org/downloads/latest/opa_linux_arm64_static ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" && exit 1 ;; \
    esac; \
  fi

# MAIN IMAGE ----------------------------------------
# Main image setup (optimized)
# ---------------------------------------------------
FROM python:3.10-alpine3.22 AS main

WORKDIR /app

# Create necessary user and group in a single step
RUN addgroup -S permit -g 1001 && \
    adduser -S -s /bin/bash -u 1000 -G permit -h /home/permit permit

# Create backup directory with permissions
RUN mkdir -p /app/backup && chmod -R 777 /app/backup

# Install necessary libraries and delete SQLite in a single RUN command
RUN apk update && \
    apk upgrade && \
    apk add --no-cache bash build-base libffi-dev libressl-dev musl-dev zlib-dev gcompat wget && \
    apk del sqlite


# Copy OPA binary from the build stage
COPY --from=opa_build --chmod=755 /opa /app/bin/opa

# Copy the Rust PDP binary from the builder stage
ARG TARGETPLATFORM
COPY --from=rust_builder --chmod=755 /app/${TARGETPLATFORM}/pdp /app/pdp

# Environment variables for OPA
ENV OPAL_INLINE_OPA_EXEC_PATH="/app/bin/opa"

# Set permissions and ownership for the application
RUN mkdir -p /config && chown -R permit:permit /config

# Ensure the `permit` user has the correct permissions for home directory and binaries
RUN chown -R permit:permit /home/permit /app /usr/local/bin

# Switch to permit user
USER permit

# Copy Kong routes and Gunicorn config
COPY kong_routes.json /config/kong_routes.json

USER root

# Install python dependencies in one command to optimize layer size
COPY ./requirements.txt ./requirements.txt
RUN pip install --upgrade pip setuptools && \
    pip install -r requirements.txt && \
    python -m pip uninstall -y pip setuptools && \
    rm -r /usr/local/lib/python3.10/ensurepip

USER permit

# Copy the application code
COPY ./horizon /app/horizon

USER permit

# Version file for the application
COPY ./permit_pdp_version /app/permit_pdp_version

# Set the PATH to ensure the local binary paths are used
ENV PATH="/app/bin:/home/permit/.local/bin:$PATH"

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

# We ignore this callback because we are sunsetting this feature in favor of the new inline OPA data updater
ENV PDP_IGNORE_DEFAULT_DATA_UPDATE_CALLBACKS_URLS='["http://localhost:8181/v1/data/permit/rebac/cache_rebuild"]'
# We need to set v0_compatible to true to make sure the PDP works with the OPA v0
# syntax.
ENV OPAL_INLINE_OPA_CONFIG='{"v0_compatible": true}'
# if we are using the custom OPA binary, we need to load the permit plugin,
# if we don't then we MUST not add a non existing plugin
FROM main AS main-vanilla
# if we are using the vanilla OPA binary, we don't need to load the permit plugin
ENV PDP_OPA_PLUGINS='{}'

FROM main AS main-permit
# if we are using the custom OPA binary, we need to load the permit plugin,
ENV PDP_OPA_PLUGINS='{"permit_graph":{}}'

FROM main-${OPA_BUILD} AS application

# Environment variables with defaults
ENV PDP_HORIZON_HOST=0.0.0.0
ENV PDP_HORIZON_PORT=7001
ENV PDP_PORT=7000
ENV PDP_PYTHON_PATH=python3
ENV NO_PROXY=localhost,127.0.0.1,::1

# 7000 pdp port
# 7001 horizon port
# 8181 opa port
EXPOSE 7000 7001 8181

# Run the application using the startup script
CMD ["/app/pdp"]
