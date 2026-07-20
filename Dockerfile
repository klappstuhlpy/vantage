# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 – builder
#
# Uses the official Rust image.  git is required because several Cargo
# dependencies are pulled directly from public GitHub repositories, including
# the shared kls-core kernel.  No credentials are needed: anyone can build this
# image from a clean checkout, which is the point.
# ─────────────────────────────────────────────────────────────────────────────
FROM rust:1.88-slim-bookworm AS builder

# mold is a fast drop-in linker; .cargo/config.toml points the linux target at
# it via rustflags, which cuts a big chunk off the final link step.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    git \
    mold \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Build with persistent cargo + target cache ────────────────────────────────
# BuildKit cache mounts persist the cargo registry/git checkouts and the
# `target/` dir *across* builds, restoring incremental compilation.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release \
 && cp target/release/vantage /build/vantage


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 – runtime
#
# Minimal Debian image.  Only what is strictly needed at runtime:
#   • ca-certificates  – outbound TLS (health probes, alert webhooks, SMTP)
#   • docker.io        – the container dashboard shells out to Docker via socket
# ─────────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    ufw \
 && rm -rf /var/lib/apt/lists/*

# The Docker CLI and the Compose v2 plugin, copied from Docker's own image.
#
# This used to be Debian's `docker.io` package, which ships the engine *and* the
# CLI but not Compose v2 — Compose v2 is distributed by Docker, not by Debian.
# The self-update helper runs `docker compose`, so that package would have left
# us with a 250 MB image that still could not apply the update it offered. Only
# the client is needed either way: every command here talks to the *host's*
# daemon over the mounted socket, so the bundled daemon was always dead weight.
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:27-cli /usr/local/libexec/docker/cli-plugins/docker-compose \
     /usr/local/libexec/docker/cli-plugins/docker-compose

WORKDIR /app

# Binary (SQLite is bundled in, no separate .so needed).
COPY --from=builder /build/vantage ./vantage

# Static assets served at runtime by tower_http from ./static/
COPY static/ ./static/

# Askama templates (compiled into the binary, but keep for reference/override)
COPY templates/ ./templates/

# ── Persistent data layout ────────────────────────────────────────────────────
# All mutable data is rooted under /data via XDG environment variables:
#
#   /data/config/vantage/config.json    ← application config
#   /data/data/vantage/main.db          ← SQLite database
#   /data/state/vantage/                ← rolling log files
#
ENV XDG_CONFIG_HOME=/data/config \
    XDG_DATA_HOME=/data/data \
    XDG_STATE_HOME=/data/state \
    XDG_CACHE_HOME=/data/cache

VOLUME ["/data"]

# Default port (configurable via VANTAGE_PORT or config.json).
EXPOSE 9090

CMD ["./vantage"]
