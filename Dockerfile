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

FROM --platform=$BUILDPLATFORM rust:1.94-alpine AS rust_chef
WORKDIR /app
ENV PKGCONFIG_SYSROOTDIR=/
RUN apk add --no-cache musl-dev openssl-dev zig pkgconf perl make

# Cache cargo installations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install --locked cargo-zigbuild cargo-chef
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# (2) nothing changed
FROM rust_chef AS rust_planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# (3) building project deps: need to specify all targets; zigbuild used
FROM rust_chef AS rust_builder
COPY --from=rust_planner /app/recipe.json recipe.json
ENV OPENSSL_DIR=/usr
# Enable incremental compilation and use cache mounts
ENV CARGO_INCREMENTAL=1
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo chef cook --recipe-path recipe.json --release --zigbuild \
    --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl

# (4) actual project build for all targets
# binary renamed to easier copy in runtime stage
COPY . .
# Use cache mounts for incremental builds - this is the key optimization!
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo zigbuild -r --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl && \
    mkdir -p /app/linux/arm64/ && \
    mkdir -p /app/linux/amd64/ && \
    cp target/aarch64-unknown-linux-musl/release/pdp-server /app/linux/arm64/pdp && \
    cp target/x86_64-unknown-linux-musl/release/pdp-server /app/linux/amd64/pdp


# OPA BUILD STAGE -----------------------------------
# Build OPA from source or download precompiled binary
# ---------------------------------------------------
# Go 1.26 is required ahead of permit-opa moving its `go` directive to 1.26.0.
# That move is forced by golang.org/x/crypto v0.56.0 (the version that clears
# CVE-2026-78662 / CVE-2026-56855 / CVE-2026-56854), whose own go.mod declares
# `go 1.26.0`.
#
# This bump lands BEFORE the permit-opa change on purpose. tests.yml and
# release.yml both check out permitio/permit-opa at `ref: main` with no pin, so
# the moment that directive moves, every PDP build here compiles a `go 1.26.0`
# module. The official golang images ship `ENV GOTOOLCHAIN=local`, so a
# golang:1.25 builder does not quietly fetch a newer toolchain - it hard-fails:
#
#   go: go.mod requires go >= 1.26.0 (running go 1.25.13; GOTOOLCHAIN=local)
#
# That breaks build-pdp-image on every PDP PR, every push to main and every
# release cut until this lands. A golang:1.26 builder compiling today's
# `go 1.25.0` module is forward-compatible, so the ordering is safe in one
# direction only.
#
# Floats the patch version deliberately; the tag currently serves 1.26.8. Do not
# pin below 1.26.6 - that is the floor carrying the toolchain-level fixes for
# GO-2026-6090 (crypto/tls), GO-2026-5856 (ECH) and GO-2026-4918 (http2).
# See PER-15358.
FROM golang:1.26-bookworm AS opa_build

COPY custom* /custom

# Build OPA binary if custom_opa.tar.gz is provided

# Fix for ARM64 compatibility issue (#289): Build fully static binary to avoid dynamic linking issues
# Problem: Dynamic linking creates dependencies on system libc (glibc), but Alpine Linux uses musl libc
# Result: Binary fails with "/lib/ld-musl-aarch64.so.1: /app/bin/opa: Not a valid dynamic program"
# Solution: Build a truly static binary with no external libc dependencies
# - CGO_ENABLED=0: Disables CGO to ensure pure Go compilation (eliminates glibc dependency)
# - -a: Forces rebuilding of all packages to ensure clean static build
# - -tags netgo: Uses pure Go network stack instead of C-based libc resolver
# - -s -w: Strips debug info and symbol table to reduce binary size
# - -extldflags=-static: Ensures static linking if CGO were enabled (defense in depth)

# Use BuildKit cache mounts for Go modules and build cache for MUCH faster incremental builds
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    if [ -f /custom/custom_opa.tar.gz ]; \
  then \
    cd /custom && \
    tar xzf custom_opa.tar.gz && \
    # permit-opa moved its main package from the repo root to ./cmd/opa
    # (cmd/ + pkg/ layout); build whichever location the tarball provides
    if [ -d cmd/opa ]; then main_pkg=./cmd/opa; else main_pkg=.; fi && \
    CGO_ENABLED=0 go build -a -ldflags="-s -w -extldflags=-static" -tags netgo -installsuffix netgo -o /opa $main_pkg && \
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
# Python 3.13 (>= 3.13.14) on Alpine 3.23. Moved off python:3.10-alpine3.22 to clear four
# CPython CVEs a customer CPE scan raised against pdp-v2 0.9.14-rc1 (PER-15358):
#   CVE-2026-6019  (http.cookies Morsel.js_output escaping) - fixed in 3.13.14
#   CVE-2026-7210  (expat hash-flooding entropy)            - fixed in 3.13.14 AND needs
#                                                             libexpat >= 2.8.0; this image
#                                                             ships expat 2.8.1
#   CVE-2023-36632 (email.utils.parseaddr recursion)        - DISPUTED by PSF and never
#                                                             fixed, but its CPE range is
#                                                             < 3.11.4, so 3.13 is out of it
# PSF fixed these only on the 3.13/3.14/3.15 branches - there is no 3.10/3.11/3.12 backport -
# so the vulnerable code really was present in 3.10.20 and an upgrade was the only fix.
# CVE-2026-15308 (html.parser DoS) is NOT cleared by this bump: it is patched only in
# 3.15.0b4 and NVD's range is < 3.15.0, so no released Python satisfies it. It is waived in
# .docker/scout/pdp-v2.vex.json as unreachable (nothing in the image imports html.parser).
#
# The patch version floats deliberately (see the previous python:3.10-alpine3.22 base and
# the rebuild-picks-it-up posture in PER-15532): when 3.13.15 ships it will clear
# CVE-2026-15308 automatically and that waiver can then be dropped. Do not drop below
# 3.13.14 - that is the floor for the fixes above.
#
# Python 3.10 also reaches end of life in October 2026, so this move was due regardless.
FROM python:3.13-alpine3.23 AS main

WORKDIR /app

# Create necessary user and group in a single step
RUN addgroup -S permit -g 1001 && \
    adduser -S -s /bin/bash -u 1000 -G permit -h /home/permit permit

# Create backup directory with permissions
RUN mkdir -p /app/backup && chmod -R 777 /app/backup

# Install runtime libraries and remove sqlite-libs.
# Build deps (build-base, *-dev) are installed and removed in the pip install
# layer to avoid persisting binutils CVEs (CVE-2025-69649, CVE-2025-69650).
#
# The PDP never uses SQLite, but its FTS5/zipfile CVEs (CVE-2026-11822,
# CVE-2026-11824, CVE-2025-70873) are still reported against sqlite-libs, which
# the official python:alpine image pins via the .python-rundeps virtual package.
# A plain `apk del sqlite-libs` is refused (that pin), and deleting the virtual
# cascade-purges the whole python runtime. So re-pin every OTHER python runtime
# shared object under a fresh virtual (derived dynamically, so it is
# arch-agnostic), then drop the original pin together with sqlite-libs.
RUN --mount=type=cache,target=/var/cache/apk \
    ln -s /var/cache/apk /etc/apk/cache && \
    apk update && \
    apk upgrade && \
    apk add bash libffi libressl gcompat && \
    apk add --no-cache --virtual .python-rundeps-nosqlite \
        $(apk info -qR .python-rundeps | grep '^so:' | grep -v 'libsqlite3') && \
    apk del .python-rundeps sqlite-libs


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
# Use cache mount for pip to speed up incremental builds
COPY ./requirements.txt ./requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    apk add --no-cache --virtual .build-deps build-base libffi-dev libressl-dev musl-dev zlib-dev && \
    pip install --upgrade pip setuptools && \
    pip install -r requirements.txt && \
    python -m pip uninstall -y pip setuptools wheel && \
    rm -r /usr/local/lib/python3.13/ensurepip && \
    apk del .build-deps

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

# datadog / ddtrace configuration -------------------
# Drop "baggage" from ddtrace's default extract styles ("datadog,tracecontext,baggage").
# CVE-2026-50271: ddtrace's W3C baggage propagator does not enforce
# DD_TRACE_BAGGAGE_MAX_ITEMS / DD_TRACE_BAGGAGE_MAX_BYTES on the *extract* path, so an
# unauthenticated caller can force unbounded CPU/memory use with an oversized baggage
# header. The fix is only in ddtrace >= 4.8.2, which opal-common's `ddtrace<4,>=3.0.0`
# cap forbids, so we remove the vulnerable parser from the request path instead.
#
# This only matters when PDP_ENABLE_MONITORING=true (default false) - that is what calls
# patch(fastapi=True) and puts ddtrace on the inbound request path at all. Injection is
# left at its default, so outbound baggage propagation is unaffected. Remove this once
# OPAL relaxes its ddtrace<4 bound and ddtrace moves to >= 4.8.2. See PER-15358.
ENV DD_TRACE_PROPAGATION_STYLE_EXTRACT="datadog,tracecontext"

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
