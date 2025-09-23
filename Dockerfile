FROM rust:1.86

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libudev-dev \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN cargo build --release && \
    chmod +x scripts/*.sh

EXPOSE 8545

ENV RPC_URL=http://127.0.0.1:18443
ENV HTTP_HOST=0.0.0.0
ENV HTTP_PORT=8545

CMD ["./target/release/core-mel-node", "start", "--rpc-url", "http://127.0.0.1:18443", "--http-host", "0.0.0.0", "--http-port", "8545"]