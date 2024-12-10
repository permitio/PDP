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

# Add a non-root user
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
