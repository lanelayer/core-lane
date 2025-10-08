FROM rust:1.86 AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libudev-dev \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY src ./src
COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock
RUN cargo build --release


FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    libssl3 \
    libudev1 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app


COPY --from=builder /app/target/release/core-lane-node .
EXPOSE 8545

ENV RPC_URL=http://127.0.0.1:18443
ENV HTTP_HOST=0.0.0.0
ENV HTTP_PORT=8545

CMD ["./core-lane-node", "start", "--rpc-url", "http://127.0.0.1:18443", "--http-host", "0.0.0.0", "--http-port", "8545"]
