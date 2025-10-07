FROM debian:trixie-slim AS build

LABEL maintainer.0="Will Clark (@willcl-ark)"

RUN apt-get update --yes \
  && apt-get install --yes --no-install-recommends \
    build-essential \
    ca-certificates \
    capnproto \
    ccache \
    clang-19 \
    cmake \
    git \
    libboost-dev \
    libcapnp-dev \
    libevent-dev \
    libsqlite3-dev \
    libzmq3-dev \
    pkg-config \
    python3 \
    systemtap-sdt-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV BITCOIN_PREFIX=/opt/bitcoin
ARG COMMIT=feat/snapshot-916200

WORKDIR /src
RUN git clone -b "$COMMIT" --single-branch --depth 1 "https://github.com/lanelayer/bitcoin.git" && \
    cd bitcoin && \
    git fetch origin "$COMMIT" && \
    git checkout "$COMMIT" && \
    git clean -fdx

WORKDIR /src/bitcoin

RUN set -ex \
  && cmake -B build \
    -DBUILD_TESTS=OFF \
    -DBUILD_TX=ON \
    -DBUILD_UTIL=OFF \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_CXX_COMPILER=clang++-19 \
    -DCMAKE_C_COMPILER=clang-19 \
    -DCMAKE_INSTALL_PREFIX:PATH="${BITCOIN_PREFIX}" \
    -DWITH_CCACHE=ON \
  && cmake --build build -j$(nproc) \
  && strip build/bin/bitcoin-cli build/bin/bitcoin-tx build/bin/bitcoind \
  && cmake --install build

# Second stage
FROM debian:trixie-slim AS bitcoin

ARG UID=101
ARG GID=101

ENV BITCOIN_DATA=/home/bitcoin/.bitcoin

RUN groupadd --gid ${GID} bitcoin \
  && useradd --create-home --no-log-init -u ${UID} -g ${GID} bitcoin \
  && apt-get update --yes \
  && apt-get install --yes --no-install-recommends \
    capnproto \
    gosu \
    libboost-dev \
    libevent-dev \
    libsqlite3-dev \
    libzmq3-dev \
    systemtap-sdt-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=build /opt/bitcoin /opt
ENV PATH=/opt/bin:$PATH

COPY docker-entrypoint.sh /entrypoint.sh

VOLUME ["/home/bitcoin/.bitcoin"]
EXPOSE 8332 8333 18332 18333 18443 18444 38333 38332

ENTRYPOINT ["/entrypoint.sh"]
RUN bitcoind -version | grep "Bitcoin Core daemon version"
CMD ["bitcoind"]

FROM bitcoin
# Install required tools for core-lane setup
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    xxd \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Environment variables for RPC auth
ENV RPC_USER=${RPC_USER:-bitcoin}
ENV RPC_PASSWORD=${RPC_PASSWORD}
ENV DATADIR=/home/bitcoin/.bitcoin

# Create data directory
RUN mkdir -p $DATADIR && \
    chown -R bitcoin:bitcoin /home/bitcoin/.bitcoin

# Add startup script for initial setup
COPY --chown=bitcoin:bitcoin startup.sh /home/bitcoin/startup.sh
RUN chmod +x /home/bitcoin/startup.sh

# Switch to bitcoin user
USER bitcoin

# Expose Bitcoin ports
EXPOSE 8332 8333 28332 28333

# Set working directory
WORKDIR /home/bitcoin

# Healthcheck to ensure bitcoind RPC is ready
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
  CMD curl -s --user $RPC_USER:$RPC_PASSWORD \
  --data-binary '{"jsonrpc":"1.0","id":"health","method":"getblockchaininfo","params":[]}' \
  -H 'content-type: text/plain;' http://127.0.0.1:8332/ | jq -e '.result.blocks' > /dev/null || exit 1

# Use startup script instead of direct bitcoind
CMD ["/home/bitcoin/startup.sh"]
