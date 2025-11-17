FROM rust:1.90 AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libudev-dev \
    build-essential \
    ca-certificates \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY opensbi.bin ./opensbi.bin
COPY src ./src
COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock
RUN cargo build --release


FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y \
    libssl3 \
    libudev1 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app


COPY --from=builder /app/target/release/core-lane-node .
COPY scripts/entrypoint-rpc.sh /app/entrypoint-rpc.sh
RUN chmod +x /app/entrypoint-rpc.sh

# Expose RPC and bitcoin-cache ports used in rpc entrypoint
EXPOSE 8545 8332

# Default envs for combined rpc entrypoint
ENV HTTP_HOST=0.0.0.0
ENV HTTP_PORT=8545
ENTRYPOINT ["/app/entrypoint-rpc.sh"]
