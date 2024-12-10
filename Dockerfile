# OPA BUILD STAGE -----------------------------------
FROM golang:1.22-alpine AS opa_build

# Use alpine base to reduce image size
WORKDIR /build

# Copy only necessary files and use multi-stage optimization
COPY custom* /build/custom/
COPY factdb* /build/factdb/

RUN apk add --no-cache curl && \
    if [ -f /build/custom/custom_opa.tar.gz ]; then \
        cd /build/custom && \
        tar xzf custom_opa.tar.gz && \
        CGO_ENABLED=0 go build -ldflags="-s -w" -o /opa && \
        rm -rf /build/custom ; \
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

RUN if [ -f /build/factdb/factdb.tar.gz ]; then \
        cd /build/factdb && \
        tar xzf factdb.tar.gz && \
        CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/factdb ./cmd/factstore_server && \
        rm -rf /build/factdb ; \
    else \
        case $(uname -m) in \
        x86_64) \
            if [ -f /build/factdb/factstore_server-linux-amd64 ]; then \
                cp /build/factdb/factstore_server-linux-amd64 /bin/factdb; \
            else \
                echo "factstore_server-linux-amd64 not found." ; \
                if [ "$ALLOW_MISSING_FACTSTORE" = "false" ]; then \
                    echo "Missing Factstore is not allowed, exiting..."; exit 1; \
                else \
                    echo "Missing Factstore is allowed, continuing..."; \
                    touch /bin/factdb ; \
                fi \
            fi \
        ;; \
        aarch64) \
            if [ -f /build/factdb/factstore_server-linux-arm64 ]; then \
                cp /build/factdb/factstore_server-linux-arm64 /bin/factdb; \
            else \
                echo "factstore_server-linux-arm64 not found." ; \
                if [ "$ALLOW_MISSING_FACTSTORE" = "false" ]; then \
                    echo "Missing Factstore is not allowed, exiting..."; exit 1; \
                else \
                    echo "Missing Factstore is allowed, continuing..."; \
                    touch /bin/factdb ; \
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
FROM python:3.10-alpine3.19

WORKDIR /app

# Combine RUN commands and reduce layers
RUN addgroup -S permit -g 1001 && \
    adduser -S -s /bin/bash -u 1000 -G permit -h /home/permit permit && \
    mkdir -p /app/backup && \
    chmod -R 777 /app/backup && \
    apk update && \
    apk add --no-cache \
        bash \
        build-base \
        libffi-dev \
        libressl-dev \
        musl-dev \
        zlib-dev \
        gcompat && \
    rm -rf /var/cache/apk/*

# Create and set permissions in fewer steps
RUN mkdir -p /app/bin /config && \
    chown -R permit:permit /app/bin /config /home/permit /usr/

# Copy binaries with fewer layers
COPY --from=opa_build --chmod=755 /opa /app/bin/opa
COPY --from=opa_build --chmod=755 /bin/factdb /app/bin/factdb

# Environment variables
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

# Copy scripts efficiently
COPY --chown=permit:permit scripts/ ./scripts/
COPY --chown=permit:permit scripts/wait-for-it.sh /usr/wait-for-it.sh
COPY --chown=permit:permit scripts/start.sh ./start.sh
COPY --chown=permit:permit scripts/gunicorn_conf.py ./gunicorn_conf.py

# Prepare scripts
RUN chmod +x /usr/wait-for-it.sh ./start.sh

# Copy configuration files
COPY --chown=permit:permit kong_routes.json /config/kong_routes.json

# Install Python dependencies in fewer steps
COPY --chown=permit:permit requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && \
    python -m pip uninstall -y pip setuptools && \
    rm -rf /usr/local/lib/python3.10/ensurepip && \
    rm requirements.txt

# Copy application code
COPY --chown=permit:permit ./horizon ./horizon
COPY --chown=permit:permit ./permit_pdp_version /app/permit_pdp_version

# Switch to non-root user
USER permit

# Expose ports
EXPOSE 7000 8181

# Run startup script
CMD ["/app/start.sh"]