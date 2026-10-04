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

# Keep this stage free of COPY/ADD. CI caches every layer of it (tests.yml, "Cache
# the rust_chef stage") in a cache that every ref, forks included, can restore, so
# nothing from the build context may enter it.
FROM --platform=$BUILDPLATFORM rust:1.98-alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS rust_chef
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
# Go 1.27 builder. It first moved to 1.26 (from golang:1.25-bookworm) AHEAD of permit-opa
# raising its `go` directive to 1.26 (permitio/permit-opa#52). That move is forced by
# golang.org/x/crypto >= 0.56.0 - the version that clears CVE-2026-78662 /
# CVE-2026-56855 (x/crypto/ssh) - whose own go.mod declares `go 1.26.0`. The permit-opa
# commit pinned in tests.yml/release.yml includes it, so the permit build no longer needs
# those two waivers; the vanilla download carries upstream OPA's own x/crypto. With
# GOTOOLCHAIN=local (set below; the official golang images set it too) an older builder
# facing a newer `go` directive does not fetch a toolchain, it hard-fails:
#
#   go: go.mod requires go >= 1.26.0 (running go 1.25.x; GOTOOLCHAIN=local)
#
# tests.yml and release.yml check permit-opa out at a pinned commit (the `ref:` of
# their permit-opa checkout), so which permit-opa ships changes only in a PDP commit
# that moves that pin, and a release or `v*` hotfix builds the pin its own commit
# carries. Moving the pin to a permit-opa commit whose `go` directive this builder
# cannot compile fails that PR's build-pdp-image job, not a later release. Commits from
# before the pin still take permit-opa `main`: a release or hotfix cut from one builds
# whatever permit-opa main is that day, and one cut from v0.9.15 or older (a
# golang:1.25 builder) fails in this stage, since permit-opa#52 is merged. Cut releases and
# hotfixes from a commit that has the pin.
#
# What changes in /app/bin/opa: changes that come with the builder's toolchain land with
# it (e.g. the Green Tea GC, on by default since 1.26). GODEBUG-gated defaults do not:
# they follow permit-opa's go.mod at the pinned commit (after permit-opa#52, a
# `godebug default=go1.25` line).
# The binary is CGO_ENABLED=0 (below), so the builder's glibc does not reach the image.
#
# The FROM line is digest-pinned, so a rebuild of the same commit gets the same
# toolchain. The `docker` entry in .github/dependabot.yml moves tag and digest together
# daily, so a Go security release (a new go1.27.x behind the same tag) arrives as a
# reviewable PR instead of silently on the next build.
#
# This stage pins nothing beyond that floor, and that is a statement about THIS builder
# only. permit-opa builds its own artifacts (its own Dockerfile and release workflow)
# with its own toolchain policy: permit-opa#51 pinned its release toolchain and #52
# moved its image onto this floor. Read permit-opa's own tree for what it does today.
#
# Auditability: the toolchain is recorded in the binary's build info, survives `-s -w`,
# and is readable with `go version` on an extracted copy - extracted, because the
# runtime base is python:3.13-alpine3.23 and ships no Go. That is an after-the-fact
# audit, not a gate. The gates are the Docker Scout and Trivy scans in tests.yml and
# release.yml, and scheduled-security-scan.yml re-scans published tags (PER-15358).
#
# The floor is go1.26.6, the first 1.26 release with the crypto/tls fix for
# GO-2026-6090, and the RUN below fails the build on anything older (e.g. a stale local
# image). It prints the version it accepted, but it is a GATE, not a record: a local
# build can serve it from cache until the pinned digest moves. (CI exports no
# opa_build layers, so there it re-runs every build.) The compile RUN
# below echoes the toolchain too, and that one is reliable: `COPY custom* /custom` sees
# a tarball the workflow regenerates every run, so the stage re-executes from that COPY
# on and the echo is always in the log of the build that produced the binary.
#
# The stage runs on the BUILD host's architecture and cross-compiles for $TARGETARCH
# (pure Go, CGO_ENABLED=0), so release.yml's arm64 leg compiles natively instead of
# under QEMU. That is also why the vanilla download below keys on $TARGETARCH, not
# `uname -m`.
#
# KEEP THE SHAPE OF THE FROM LINE: permit-opa's `pdp-builder` check (permit-opa#52)
# fetches this Dockerfile from main and greps this line for a literal
# `golang:<major>.<minor>` on a line ending in `AS opa_build` (a `-bookworm@sha256:...`
# suffix after it is fine; its regex allows one). Setting the version from
# an ARG, splitting the FROM across lines or renaming the stage turns permit-opa's CI
# red with "cannot compare go.mod's directive" - which is a fail-closed by design, but
# it will look like an unrelated repo breaking for no reason.
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS opa_build
ENV GOTOOLCHAIN=local
RUN v=$(go env GOVERSION) && \
    [ "$(printf '%s\n' go1.26.6 "$v" | sort -V | head -n1)" = go1.26.6 ] || \
    { echo "opa_build: $v is below the go1.26.6 floor (GO-2026-6090)"; exit 1; } && \
    echo "opa_build: building with $v"

COPY custom* /custom

# OPA_BUILD (declared before the first FROM) picks BOTH the binary built here and the
# plugin config set in main-${OPA_BUILD} below, so the two cannot disagree:
#   permit  (default) - compile permit-opa from custom/custom_opa.tar.gz, which must
#                       exist (the workflows and build_opal_bundle.sh create it)
#   vanilla           - download upstream OPA ${OPA_VERSION}, checked against the
#                       sha256 below. Bump the version and both sums together; the
#                       sums are https://openpolicyagent.org/downloads/v<version>/opa_linux_<arch>_static.sha256
ARG OPA_BUILD
ARG TARGETARCH
ARG OPA_VERSION=1.20.2
ARG OPA_SHA256_amd64=69da5179ee403d10fa11bab6cfb4ffb0d23dba5f9b682fa977db772a1da5670f
ARG OPA_SHA256_arm64=431bed5a365578241ab06c7cc1c7d0cdff8c11dcbc6f12c3488590deb8b8d66d

# Fix for ARM64 compatibility issue (#289): Build fully static binary to avoid dynamic linking issues
# Problem: Dynamic linking creates dependencies on system libc (glibc), but Alpine Linux uses musl libc
# Result: Binary fails with "/lib/ld-musl-aarch64.so.1: /app/bin/opa: Not a valid dynamic program"
# Solution: Build a truly static binary with no external libc dependencies
# - CGO_ENABLED=0: Disables CGO to ensure pure Go compilation (eliminates glibc dependency)
# - -tags netgo: Uses pure Go network stack instead of C-based libc resolver
# - -s -w: Strips debug info and symbol table to reduce binary size
# - -extldflags=-static: Ensures static linking if CGO were enabled (defense in depth)
# No `-a`: with CGO_ENABLED=0 it adds nothing to the above, and it would bypass the
# go-build cache mount below by recompiling every package, stdlib included.

# Use BuildKit cache mounts for Go modules and build cache for MUCH faster incremental builds
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    case "$OPA_BUILD" in \
  permit) \
    [ -f /custom/custom_opa.tar.gz ] || \
      { echo "opa_build: OPA_BUILD=permit needs custom/custom_opa.tar.gz (run build_opal_bundle.sh without PDP_VANILLA=true, or build with --build-arg OPA_BUILD=vanilla)"; exit 1; } && \
    cd /custom && \
    tar xzf custom_opa.tar.gz && \
    # This RUN never comes from cache - `COPY custom* /custom` above sees a tarball the
    # workflow regenerates every build - so this echo is the toolchain record for THIS
    # build. The floor check above is the gate, and may read CACHED locally.
    echo "opa_build: compiling permit-opa with $(go env GOVERSION) for linux/$TARGETARCH" && \
    # permit-opa moved its main package from the repo root to ./cmd/opa
    # (cmd/ + pkg/ layout); build whichever location the tarball provides
    if [ -d cmd/opa ]; then main_pkg=./cmd/opa; else main_pkg=.; fi && \
    CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w -extldflags=-static" -tags netgo -installsuffix netgo -o /opa $main_pkg && \
    rm -rf /custom ;; \
  vanilla) \
    case "$TARGETARCH" in \
      amd64) sum=$OPA_SHA256_amd64 ;; \
      arm64) sum=$OPA_SHA256_arm64 ;; \
      *) echo "opa_build: no OPA checksum for '$TARGETARCH'"; exit 1 ;; \
    esac && \
    curl --fail --show-error --silent --location -o /opa \
      "https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_${TARGETARCH}_static" && \
    echo "$sum  /opa" | sha256sum -c - ;; \
  *) echo "opa_build: OPA_BUILD must be permit or vanilla, got '$OPA_BUILD'"; exit 1 ;; \
    esac

# MAIN IMAGE ----------------------------------------
# Main image setup (optimized)
# ---------------------------------------------------
# Python 3.13 (>= 3.13.14) on Alpine 3.23. Moved off python:3.10-alpine3.22 to clear four
# CPython CVEs that CPE-based scanners raise against the 3.10 interpreter (PER-15358):
#   CVE-2026-6019  (http.cookies Morsel.js_output escaping) - fixed in 3.13.14
#   CVE-2026-7210  (expat hash-flooding entropy)            - fixed in 3.13.14 AND needs
#                                                             libexpat >= 2.8.0; this image
#                                                             ships expat 2.8.1
#   CVE-2023-36632 (email.utils.parseaddr recursion)        - DISPUTED by PSF and never
#                                                             fixed, but its CPE range is
#                                                             < 3.11.4, so 3.13 is out of it
# PSF fixed these only on the 3.13/3.14/3.15 branches - there is no 3.10/3.11/3.12 backport -
# so the vulnerable code really was present in 3.10.20 and an upgrade was the only fix.
# CVE-2026-15308 (html.parser CPU-exhaustion DoS) is now cleared too: it was waived here as
# unreachable while it was patched only in 3.15.0b4, but CPython backported the fix and it
# landed in 3.13.15 (also 3.14.7). The base digest below carries 3.13.15, so the waiver has
# been REMOVED from .docker/scout/pdp-v2.vex.json.
# Do not drop below the patched floor for whichever branch the base resolves to: 3.13.15 on
# the 3.13 line, 3.14.7 on 3.14. The apk layer below enforces exactly that, per branch -
# a flat `>= (3,13,15)` would have passed 3.14.0 through 3.14.6, which are the versions the
# line above says still lack the backport.
#
# Removing the CVE-2026-15308 waiver is NOT what enforces it. Scout indexes the interpreter
# - `docker scout sbom` reports `pkg:generic/python@3.13.15` for this base - but it does not
# match CPython advisories against it the way a CPE-based scanner does (see the NOTE in
# tests.yml). The gate no longer skips releases - this change removes that condition - but
# that closes a COVERAGE gap, not this one: catching a stale interpreter through a scanner
# still needs a CPE-based one, which neither gate is. The plain reason the waiver could go
# is simply that 3.13.15 carries the fix.
#
# The check imports the C extension modules DIRECTLY - `_ssl`, `_hashlib`, `_decimal` and
# friends rather than `ssl`, `hashlib`, `decimal` - and that is the point, not decoration.
# `sys` is a builtin, so `import sys` alone loads no extension modules at all and a
# version-only check would pass on an interpreter whose lib-dynload is unresolvable. But
# the public wrappers are not reliable either: decimal.py and hashlib.py both fall back
# silently to pure Python when their .so is missing, so importing them detects nothing,
# while ssl/zlib/lzma/bz2/ctypes/pyexpat do propagate. Importing the underscore modules
# removes that asymmetry. Between them these nine cover libssl, libcrypto, libz, liblzma,
# libbz2, libffi, libuuid and lib-dynload itself - i.e. the `so:` deps the .python-rundeps
# rework above could strip if its `grep '^so:'` list ever comes back short. Deliberately
# NOT extended to readline/_curses/_gdbm: they guard libs the PDP never uses, and `_gdbm`
# is absent from some perfectly good CPython builds, so requiring it would fail the build
# for no security reason.
#
# It uses sys.exit rather than `assert`, which -O / PYTHONOPTIMIZE strips. A cached `main`
# layer skips the check, but a cache hit implies an unchanged parent and so an unchanged
# base digest, so the floor still holds; both workflows pass `no-cache-filters: main`
# regardless. Note the check runs in this apk layer, before the `.build-deps` install and
# removal around `pip install` further down - so it proves the interpreter survived the
# sqlite surgery, not that it survives every later package mutation.
#
# The patch version USED to float (see the previous python:3.10-alpine3.22 base and the
# rebuild-picks-it-up posture in PER-15532). It no longer does - the digest below carries
# 3.13.15 - because "a rebuild will pick it up" only holds if something rebuilds. See the
# pinning note below.
#
# Python 3.10 also reaches end of life in October 2026, so this move was due regardless.
# Base images are pinned by DIGEST, and Dependabot's docker ecosystem
# (.github/dependabot.yml, daily) bumps them. The digest is the manifest-LIST digest, so
# multi-arch is preserved - `docker buildx imagetools inspect <tag>` reports it, and
# pinning a per-arch digest instead would break the linux/amd64 + linux/arm64 build.
#
# Why pin at all, when floating the tag sounds strictly fresher: upstream rebuilds these
# tags IN PLACE. `python:3.13-alpine3.23` can silently gain a new digest with patched
# OpenSSL, and because the tag string never changes there is nothing for anyone - human
# or bot - to notice. A floating tag is only fresh at the instant of a build, and nothing
# triggers builds. Pinning inverts that: the drift arrives as a digest-bump PR that CI
# validates before it ships (PER-15358).
#
# Do NOT hand-edit these digests to chase a CVE. Let the Dependabot PR do it, so the
# change is reviewed and tested. `apk upgrade` still floats the Alpine package set at
# build time, so pinning costs no package freshness on a rebuild - only the base layer
# becomes deterministic.
FROM python:3.13-alpine3.23@sha256:6438599575cca0d1df94aeee0d2ae088d4d8846eab554b2ee7784a3a6df0d516 AS main

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
# `apk upgrade` here is the ONLY thing that keeps the OS package set current, and it is
# only as fresh as the build that ran it: a published tag keeps the libcrypto3/libssl3 and
# util-linux versions current on its build day. When Alpine later publishes fixes, a scan
# of the UNCHANGED tag reports CVEs that are not source defects at all - this Dockerfile is
# already correct, and a rebuild with no edits clears them. See PER-15358.
#
# Two consequences, both load-bearing:
#   1. Release builds MUST NOT serve this layer from cache. release.yml uses
#      `cache-from: type=gha`, and the cache key is this instruction text plus the parent
#      layer - so a release cut months later could replay a months-old apk layer and
#      re-ship packages upstream has since patched. release.yml therefore passes
#      `no-cache-filters: main` to force that stage to re-resolve on every release, and
#      tests.yml passes the same value so the scanned image is not built on a stale
#      package set either. The release itself is scanned per platform from the exact
#      archive it then publishes (release.yml, scan-pdp-release), so what ships is what
#      was scanned (PER-15358).
#   2. A tag that is never rebuilt rots on its own, and no build-time gate can catch that:
#      a gate can only see the CVEs known on the day it ran, whatever events it runs on.
#      Detecting drift therefore REQUIRES re-scanning the PUBLISHED tags on a schedule.
#      .github/workflows/scheduled-security-scan.yml does that every three days (PER-15358).
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
    apk del .python-rundeps sqlite-libs && \
    python3 -c "import sys, _ssl, _hashlib, _decimal, zlib, _lzma, _bz2, _ctypes, pyexpat, _uuid; v = sys.version_info[:3]; v >= {13: (3, 13, 15), 14: (3, 14, 7)}.get(v[1], (3, 15, 0)) or sys.exit('CPython %s is below the patched floor for its branch' % sys.version)"


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

# Copy Kong routes and Gunicorn config
COPY kong_routes.json /config/kong_routes.json

# Install python dependencies in one command to optimize layer size
# Use cache mount for pip to speed up incremental builds
#
# requirements-override.txt pins what a dependency's metadata forbids - today aiofiles, which
# opal-client caps at a 0.8.0 that breaks OPAL's offline-mode backup on CPython >= 3.12 - so it
# is installed after the resolve. That file holds the rationale and the exit condition
# (PER-16234). check_aiofiles_override.py is bind-mounted, so it never ships, and runs last:
# it fails the build if opal-client leaves 0.9.9 or the real backup_store() stops working here.
COPY ./requirements.txt ./requirements.txt
COPY ./requirements-override.txt ./requirements-override.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,source=check_aiofiles_override.py,target=/tmp/check_aiofiles_override.py \
    apk add --no-cache --virtual .build-deps build-base libffi-dev libressl-dev musl-dev zlib-dev && \
    pip install --upgrade pip setuptools && \
    pip install -r requirements.txt && \
    pip install --no-deps --require-hashes -r requirements-override.txt && \
    python -m pip uninstall -y pip setuptools wheel && \
    rm -r "$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["stdlib"])')/ensurepip" && \
    apk del .build-deps && \
    python /tmp/check_aiofiles_override.py

USER permit

# Copy the application code
COPY ./horizon /app/horizon

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
# ddtrace reaches the inbound request path only with monitoring on - that is what calls
# patch(fastapi=True). PDP_ENABLE_MONITORING defaults to false, but horizon/pdp.py applies
# the control plane's remote config before it checks the flag, so monitoring can be turned
# on without touching this image's env. That is why this ENV, not the default, is the
# mitigation the waivers rely on. Injection is
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
