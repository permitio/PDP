# OPA BUILD STAGE -----------------------------------
FROM golang:alpine AS opa_build

WORKDIR /build

COPY custom* /custom
COPY factdb* /factdb

RUN apk add --no-cache curl

RUN if [ -f /custom/custom_opa.tar.gz ]; then \
    cd /custom && \
    tar xzf custom_opa.tar.gz && \
    CGO_ENABLED=0 go build -ldflags="-s -w -extldflags=-static" -o /opa && \
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
    esac ; \
  fi

RUN if [ -f /factdb/factdb.tar.gz ]; then \
    cd /factdb && \
    tar xzf factdb.tar.gz && \
    CGO_ENABLED=0 go build -ldflags="-s -w -extldflags=-static" -o /factdb ./cmd/factstore_server && \
    rm -rf /factdb ; \
  else \
    case $(uname -m) in \
    x86_64) \
      if [ -f /factdb/factstore_server-linux-amd64 ]; then \
        cp /factdb/factstore_server-linux-amd64 /factdb; \
      else \
        touch /factdb ; \
      fi \
    ;; \
    aarch64) \
      if [ -f /factdb/factstore_server-linux-arm64 ]; then \
        cp /factdb/factstore_server-linux-arm64 /factdb; \
      else \
        touch /factdb ; \
      fi \
    ;; \
    *) \
      echo "Unknown architecture." ; \
      exit 1 ; \
    esac ; \
  fi

# MAIN IMAGE ----------------------------------------
FROM python:3.10-alpine3.18

WORKDIR /app

# Create user and group with minimal permissions
RUN addgroup -S permit -g 1001 && \
    adduser -S -s /bin/sh -u 1000 -G permit -h /home/permit permit

# Install system dependencies for Python package compilation
RUN apk add --no-cache \
    bash \
    build-base \
    python3-dev \
    linux-headers \
    libffi-dev \
    openssl-dev \
    libffi \
    libressl \
    zlib \
    gcompat \
    # Add additional dependencies for aiokafka
    musl-dev \
    gcc \
    python3 \
    py3-pip \
    librdkafka-dev \
    && rm -rf /var/cache/apk/*

# Create necessary directories with correct permissions
RUN mkdir -p /app/backup /app/bin /config && \
    chmod -R 777 /app/backup && \
    chown -R permit:permit /app/bin /config

# Copy binaries from build stage
COPY --from=opa_build --chmod=755 /opa /app/bin/opa
COPY --from=opa_build --chmod=755 /factdb /app/bin/factdb

# Copy only essential scripts and configs
COPY --chmod=755 scripts/start.sh scripts/wait-for-it.sh /app/
COPY scripts/gunicorn_conf.py /app/
COPY kong_routes.json /config/
# COPY permit_pdp_version /app/

# Install Python dependencies with comprehensive approach
COPY requirements.txt /app/
RUN pip install --upgrade pip && \
    pip install --no-cache-dir \
    wheel \
    setuptools \
    # Add kafka-python as an alternative to aiokafka if needed
    kafka-python && \
    # Try multiple installation strategies for aiokafka
    pip install --no-cache-dir \
    --use-deprecated=legacy-resolver \
    --no-use-pep517 \
    --no-build-isolation \
    -r requirements.txt || \
    VERBOSE=1 pip install --no-cache-dir \
    --use-deprecated=legacy-resolver \
    --no-use-pep517 \
    --no-build-isolation \
    -v -r requirements.txt || \
    # If still failing, try to install specific dependencies first
    (pip install --no-cache-dir cython && \
     pip install --no-cache-dir aiokafka) && \
    pip cache purge && \
    find /usr/local \
        \( -type d -a -name test -o -name tests \) \
        -o \( -type f -a -name '*.pyc' -o -name '*.pyo' \) \
        -exec rm -rf '{}' + && \
    rm -f requirements.txt

# Copy application code
COPY horizon /app/horizon

# Set environment variables
ENV PATH="/:/app/bin:/home/permit/.local/bin:$PATH" \
    UVICORN_NUM_WORKERS=1 \
    UVICORN_ASGI_APP="horizon.main:app" \
    UVICORN_PORT=7000 \
    OPAL_SERVER_URL="https://opal.permit.io" \
    OPAL_LOG_DIAGNOSE="false" \
    OPAL_LOG_TRACEBACK="false" \
    OPAL_LOG_MODULE_EXCLUDE_LIST="[]" \
    OPAL_INLINE_OPA_ENABLED="true" \
    OPAL_INLINE_OPA_LOG_FORMAT="http" \
    PDP_CONTROL_PLANE="https://api.permit.io" \
    PDP_API_KEY="MUST BE DEFINED" \
    PDP_REMOTE_CONFIG_ENDPOINT="/v2/pdps/me/config" \
    PDP_REMOTE_STATE_ENDPOINT="/v2/pdps/me/state" \
    # PDP_VERSION_FILE_PATH="/app/permit_pdp_version" \
    PDP_FACTDB_BINARY_PATH="/app/bin/factdb" \
    OPAL_INLINE_OPA_EXEC_PATH="/app/bin/opa" \
    OPAL_AUTH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDe2iQ+/E01P2W5/EZwD5NpRiSQ8/r/k18pFnym+vWCSNMWpd9UVpgOUWfA9CAX4oEo5G6RfVVId/epPH/qVSL87uh5PakkLZ3E+PWVnYtbzuFPs/lHZ9HhSqNtOQ3WcPDTcY/ST2jyib2z0sURYDMInSc1jnYKqPQ6YuREdoaNdPHwaTFN1tEKhQ1GyyhL5EDK97qU1ejvcYjpGm+EeE2sjauHYn2iVXa2UA9fC+FAKUwKqNcwRTf3VBLQTE6EHGWbxVzXv1Feo8lPZgL7Yu/UPgp7ivCZhZCROGDdagAfK9sveYjkKiWCLNUSpado/E5Vb+/1EVdAYj6fCzk45AdQzA9vwZefP0sVg7EuZ8VQvlz7cU9m+XYIeWqduN4Qodu87rtBYtSEAsru/8YDCXBDWlLJfuZb0p/klbte3TayKnQNSWD+tNYSJHrtA/3ZewP+tGDmtgLeB38NLy1xEsgd31v6ISOSCTHNS8ku9yWQXttv0/xRnuITr8a3TCLuqtUrNOhCx+nKLmYF2cyjYeQjOWWpn/Z6VkZvOa35jhG1ETI8IwE+t5zXqrf2s505mh18LwA1DhC8L/wHk8ZG7bnUe56QwxEo32myUBN8nHdu7XmPCVP8MWQNLh406QRAysishWhXVs/+0PbgfBJ/FxKP8BXW9zqzeIG+7b/yk8tRHQ=="

# Switch to non-root user
USER permit

# Expose ports
EXPOSE 7000 8181

# Run startup script
CMD ["/app/start.sh"]