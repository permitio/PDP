# OPA BUILD STAGE -----------------------------------
# Build opa from source or download precompiled binary
# ---------------------------------------------------
FROM golang:alpine AS opa_build

RUN apk add --no-cache git curl tar

COPY custom* /custom/
COPY factdb* /factdb/

# Build or download OPA binary
RUN if [ -f /custom/custom_opa.tar.gz ]; then \
      cd /custom && \
      tar xzf custom_opa.tar.gz && \
      go build -ldflags="-extldflags=-static" -o /opa && \
      rm -rf /custom; \
    else \
      ARCH=$(uname -m); \
      case "$ARCH" in \
        x86_64)   curl -L -o /opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static ;; \
        aarch64)  curl -L -o /opa https://openpolicyagent.org/downloads/latest/opa_linux_arm64_static ;; \
        *)        echo "Unknown architecture." && exit 1 ;; \
      esac; \
    fi

# Build or handle FactDB binary
RUN if [ -f /factdb/factdb.tar.gz ]; then \
      cd /factdb && \
      tar xzf factdb.tar.gz && \
      go build -ldflags="-extldflags=-static" -o /bin/factdb ./cmd/factstore_server && \
      rm -rf /factdb; \
    else \
      ARCH=$(uname -m); \
      case "$ARCH" in \
        x86_64)  [ -f /factdb/factstore_server-linux-amd64 ] && cp /factdb/factstore_server-linux-amd64 /bin/factdb ;; \
        aarch64) [ -f /factdb/factstore_server-linux-arm64 ] && cp /factdb/factstore_server-linux-arm64 /bin/factdb ;; \
        *)       echo "Unknown architecture." && exit 1 ;; \
      esac; \
    fi

# MAIN IMAGE ----------------------------------------
# Use Python slim or alpine for final image
# ---------------------------------------------------
FROM python:3.10-slim

WORKDIR /app

# Add dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev libssl-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Add a non-root user# OPA BUILD STAGE -----------------------------------
FROM golang:alpine AS opa_build

# Install necessary tools for building
RUN apk add --no-cache bash curl tar build-base

COPY custom* /custom
COPY factdb* /factdb

RUN if [ -f /custom/custom_opa.tar.gz ]; then \
  cd /custom && \
  tar xzf custom_opa.tar.gz && \
  go build -ldflags="-extldflags=-static" -o /opa && \
  rm -rf /custom; \
else \
  ARCH=$(uname -m); \
  case $ARCH in \
    x86_64) OPA_URL=https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static ;; \
    aarch64) OPA_URL=https://openpolicyagent.org/downloads/latest/opa_linux_arm64_static ;; \
    *) echo "Unknown architecture."; exit 1 ;; \
  esac; \
  curl -L -o /opa $OPA_URL; \
fi && chmod +x /opa

RUN if [ -f /factdb/factdb.tar.gz ]; then \
  cd /factdb && \
  tar xzf factdb.tar.gz && \
  go build -ldflags="-extldflags=-static" -o /bin/factdb ./cmd/factstore_server && \
  rm -rf /factdb; \
else \
  ARCH=$(uname -m); \
  FACTDB_BINARY=/factdb/factstore_server-linux-${ARCH#x86_64:amd64}; \
  if [ -f $FACTDB_BINARY ]; then \
    cp $FACTDB_BINARY /bin/factdb; \
  elif [ "$ALLOW_MISSING_FACTSTORE" = "false" ]; then \
    echo "Missing Factstore is not allowed, exiting..."; exit 1; \
  else \
    echo "Missing Factstore is allowed, creating empty binary."; touch /bin/factdb; \
  fi; \
fi && chmod +x /bin/factdb

# MAIN IMAGE ----------------------------------------
FROM python:3.10-alpine

WORKDIR /app

# Add user and group
RUN addgroup -S permit -g 1001 && \
    adduser -S -s /bin/bash -u 1000 -G permit -h /home/permit permit

# Install dependencies and required libraries
RUN apk add --no-cache bash build-base libffi-dev libressl-dev musl-dev zlib-dev gcompat && \
    mkdir -p /app/backup /app/bin /config && \
    chown -R permit:permit /app /config /app/bin /app/backup /home/permit && \
    chmod -R 777 /app/backup

# Copy binaries
COPY --from=opa_build /opa /app/bin/opa
COPY --from=opa_build /bin/factdb /app/bin/factdb

# Copy scripts and configuration
COPY scripts/start.sh ./start.sh
COPY scripts/wait-for-it.sh /usr/wait-for-it.sh
COPY kong_routes.json /config/kong_routes.json
COPY scripts/gunicorn_conf.py ./gunicorn_conf.py
COPY ./requirements.txt ./requirements.txt

RUN chmod +x /app/start.sh /usr/wait-for-it.sh && \
    pip install --no-cache-dir -r requirements.txt && \
    python -m pip uninstall -y pip setuptools && \
    rm -r /usr/local/lib/python3.10/ensurepip

# Copy application code and version file
COPY ./horizon ./horizon
COPY ./permit_pdp_version /app/permit_pdp_version

# Set environment variables
ENV OPAL_INLINE_OPA_EXEC_PATH="/app/bin/opa" \
    PDP_FACTDB_BINARY_PATH="/app/bin/factdb" \
    PATH="/:/app/bin:/home/permit/.local/bin:$PATH" \
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
    PDP_VERSION_FILE_PATH="/app/permit_pdp_version" \
    OPAL_AUTH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDe2iQ+/E01P2W5/EZwD5NpRiSQ8/r/k18pFnym+vWCSNMWpd9UVpgOUWfA9CAX4oEo5G6RfVVId/epPH/qVSL87uh5PakkLZ3E+PWVnYtbzuFPs/lHZ9HhSqNtOQ3WcPDTcY/ST2jyib2z0sURYDMInSc1jnYKqPQ6YuREdoaNdPHwaTFN1tEKhQ1GyyhL5EDK97qU1ejvcYjpGm+EeE2sjauHYn2iVXa2UA9fC+FAKUwKqNcwRTf3VBLQTE6EHGWbxVzXv1Feo8lPZgL7Yu/UPgp7ivCZhZCROGDdagAfK9sveYjkKiWCLNUSpado/E5Vb+/1EVdAYj6fCzk45AdQzA9vwZefP0sVg7EuZ8VQvlz7cU9m+XYIeWqduN4Qodu87rtBYtSEAsru/8YDCXBDWlLJfuZb0p/klbte3TayKnQNSWD+tNYSJHrtA/3ZewP+tGDmtgLeB38NLy1xEsgd31v6ISOSCTHNS8ku9yWQXttv0/xRnuITr8a3TCLuqtUrNOhCx+nKLmYF2cyjYeQjOWWpn/Z6VkZvOa35jhG1ETI8IwE+t5zXqrf2s505mh18LwA1DhC8L/wHk8ZG7bnUe56QwxEo32myUBN8nHdu7XmPCVP8MWQNLh406QRAysishWhXVs/+0PbgfBJ/FxKP8BXW9zqzeIG+7b/yk8tRHQ=="


EXPOSE 7000 8181

USER permit

CMD ["/app/start.sh"]

RUN groupadd -g 1001 permit && \
    useradd -m -u 1000 -g permit permit && \
    mkdir -p /app/backup && \
    chmod -R 777 /app/backup

# Copy OPA and FactDB binaries
COPY --from=opa_build /opa /app/bin/opa
COPY --from=opa_build /bin/factdb /app/bin/factdb
RUN chmod +x /app/bin/opa /app/bin/factdb

# Set environment variables
ENV OPAL_INLINE_OPA_EXEC_PATH="/app/bin/opa" \
    PDP_FACTDB_BINARY_PATH="/app/bin/factdb"

# Copy scripts and make executable
COPY scripts/start.sh /app/start.sh
COPY scripts/wait-for-it.sh /usr/local/bin/wait-for-it.sh
RUN chmod +x /app/start.sh /usr/local/bin/wait-for-it.sh

# Copy remaining files
COPY kong_routes.json /config/kong_routes.json
COPY scripts/gunicorn_conf.py /app/gunicorn_conf.py
COPY requirements.txt /app/requirements.txt
COPY permit_pdp_version /app/permit_pdp_version
COPY horizon /app/horizon

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt && \
    pip uninstall -y pip setuptools && \
    rm -rf /usr/local/lib/python3.10/ensurepip

# Set permissions for non-root user
RUN chown -R permit:permit /app /config /home/permit

# Switch to non-root user
USER permit

# Expose ports
EXPOSE 7000 8181

# Run application
CMD ["/app/start.sh"]
