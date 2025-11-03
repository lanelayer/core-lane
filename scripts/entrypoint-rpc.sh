#!/usr/bin/env bash
set -euo pipefail

# run bitcoin-cache and core-lane RPC in one container (read-only)

# Defaults for bitcoin-cache and core-lane RPC
BITCOIN_CACHE_HOST="${BITCOIN_CACHE_HOST:-127.0.0.1}"
BITCOIN_CACHE_PORT="${BITCOIN_CACHE_PORT:-8332}"
BITCOIN_UPSTREAM_RPC_URL="${BITCOIN_UPSTREAM_RPC_URL:-https://bitcoin-rpc.publicnode.com}"
BLOCK_ARCHIVE_URL="${BLOCK_ARCHIVE_URL:-http://144.76.56.210/blocks}"
STARTING_BLOCK_COUNT="${STARTING_BLOCK_COUNT:-916201}"
RPC_USER="${RPC_USER:-bitcoin}"
RPC_PASSWORD="${RPC_PASSWORD:-bitcoin123}"

HTTP_HOST="${HTTP_HOST:-0.0.0.0}"
HTTP_PORT="${HTTP_PORT:-8545}"

DATA_DIR="${DATA_DIR:-/data}"
CACHE_DIR="${CACHE_DIR:-/cache}"

ELECTRUM_URL="${ELECTRUM_URL:-ssl://electrum.blockstream.info:50002}"
CORE_LANE_MNEMONIC="${CORE_LANE_MNEMONIC:-}"

mkdir -p "$DATA_DIR" "$CACHE_DIR"

# Ensure both children are terminated on signals
trap 'kill 0 2>/dev/null || true' TERM INT

echo "[entrypoint] starting bitcoin-cache on ${BITCOIN_CACHE_HOST}:${BITCOIN_CACHE_PORT}"
"/app/core-lane-node" bitcoin-cache \
  --host "${BITCOIN_CACHE_HOST}" \
  --port "${BITCOIN_CACHE_PORT}" \
  --cache-dir "${CACHE_DIR}" \
  --bitcoin-rpc-url "${BITCOIN_UPSTREAM_RPC_URL}" \
  --block-archive "${BLOCK_ARCHIVE_URL}" \
  --starting-block-count "${STARTING_BLOCK_COUNT}" \
  --no-rpc-auth &

# head start for cache
sleep 2

echo "[entrypoint] starting core-lane RPC on ${HTTP_HOST}:${HTTP_PORT}"
if [ -n "${CORE_LANE_MNEMONIC}" ]; then
  "/app/core-lane-node" start \
    --data-dir "${DATA_DIR}" \
    --bitcoin-rpc-read-url "http://${BITCOIN_CACHE_HOST}:${BITCOIN_CACHE_PORT}" \
    --bitcoin-rpc-read-user "${RPC_USER}" \
    --bitcoin-rpc-read-password "${RPC_PASSWORD}" \
    --start-block "${STARTING_BLOCK_COUNT}" \
    --mnemonic "${CORE_LANE_MNEMONIC}" \
    --electrum-url "${ELECTRUM_URL}" \
    --http-host "${HTTP_HOST}" \
    --http-port "${HTTP_PORT}" &
else
  "/app/core-lane-node" start \
    --data-dir "${DATA_DIR}" \
    --bitcoin-rpc-read-url "http://${BITCOIN_CACHE_HOST}:${BITCOIN_CACHE_PORT}" \
    --bitcoin-rpc-read-user "${RPC_USER}" \
    --bitcoin-rpc-read-password "${RPC_PASSWORD}" \
    --start-block "${STARTING_BLOCK_COUNT}" \
    --electrum-url "${ELECTRUM_URL}" \
    --http-host "${HTTP_HOST}" \
    --http-port "${HTTP_PORT}" &
fi

# If any child exits, stop the rest and propagate status
set +e
wait -n
STATUS=$?
kill 0 2>/dev/null || true
wait || true
exit "$STATUS"
