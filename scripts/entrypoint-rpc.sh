#!/usr/bin/env bash
set -euo pipefail


# Defaults for bitcoin-cache and core-lane RPC
# Initialize ONLY_START to prevent "unbound variable" errors with set -u
: "${ONLY_START:=}"
BITCOIN_CACHE_HOST="${BITCOIN_CACHE_HOST:-127.0.0.1}"
BITCOIN_CACHE_PORT="${BITCOIN_CACHE_PORT:-8332}"
BITCOIN_CACHE_PROTOCOL="${BITCOIN_CACHE_PROTOCOL:-http}"
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
NETWORK="${NETWORK:-mainnet}"

# Derived node configuration
CHAIN_ID="${CHAIN_ID:-}"
DERIVED_DA_ADDRESS="${DERIVED_DA_ADDRESS:-}"
START_BLOCK="${START_BLOCK:-0}"


# S3 configuration for uploading cached blocks to S3 storage
DISABLE_ARCHIVE_FETCH="${DISABLE_ARCHIVE_FETCH:-false}"

S3_BUCKET="${S3_BUCKET:-}"
S3_REGION="${S3_REGION:-us-east-1}"
S3_ENDPOINT="${S3_ENDPOINT:-}"
S3_ACCESS_KEY="${S3_ACCESS_KEY:-}"
S3_SECRET_KEY="${S3_SECRET_KEY:-}"

mkdir -p "$DATA_DIR" "$CACHE_DIR"

declare -a child_pids=()
received_signal=""

cleanup_children() {
  local signal="${1:-TERM}"
  for pid in "${child_pids[@]}"; do
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      echo "[entrypoint] Forwarding SIG${signal} to child process ${pid}"
      kill "-$signal" "$pid" 2>/dev/null || true
    fi
  done
}

handle_signal() {
  local signal="${1:-TERM}"
  echo "[entrypoint] Caught ${signal}, shutting down children..."
  received_signal="$signal"
  cleanup_children "$signal"
}

trap 'handle_signal TERM' TERM
trap 'handle_signal INT' INT

# Wait for a service to be ready on a given host:port
wait_for_service() {
  local host="${1:-127.0.0.1}"
  local port="${2:-8332}"
  local timeout="${3:-30}"
  local elapsed=0
  
  echo "[entrypoint] Waiting for service on ${host}:${port} to be ready (timeout: ${timeout}s)..."
  
  while [ $elapsed -lt $timeout ]; do
    # Check if process is still running (if PID was provided)
    if [ -n "${4:-}" ]; then
      if ! kill -0 "${4}" 2>/dev/null; then
        echo "[entrypoint] Service process ${4} is not running!"
        return 1
      fi
    fi
    
    # Try to connect to the port
    local connected=0
    if command -v nc >/dev/null 2>&1; then
      if nc -z -w 1 "$host" "$port" 2>/dev/null; then
        connected=1
      fi
    elif command -v timeout >/dev/null 2>&1; then
      if timeout 1 bash -c "echo > /dev/tcp/${host}/${port}" 2>/dev/null; then
        connected=1
      fi
    else
      # Fallback: try to use /dev/tcp directly
      if (exec 3<>/dev/tcp/${host}/${port}) 2>/dev/null; then
        exec 3<&-
        exec 3>&-
        connected=1
      fi
    fi
    
    if [ "$connected" = "1" ]; then
      echo "[entrypoint] Service on ${host}:${port} is ready! (waited ${elapsed}s)"
      return 0
    fi
    
    # Show progress every 10 seconds
    if [ $((elapsed % 10)) -eq 0 ] && [ $elapsed -gt 0 ]; then
      echo "[entrypoint] Still waiting... (${elapsed}/${timeout}s)"
    fi
    
    sleep 1
    elapsed=$((elapsed + 1))
  done
  
  echo "[entrypoint] Timeout waiting for service on ${host}:${port} after ${timeout} seconds"
  return 1
}


if [ -z "${ONLY_START:-}" ] || [ "${ONLY_START:-}" = "bitcoin-cache" ]; then
  disable_archive_flag=()
  disable_archive_fetch_normalized="${DISABLE_ARCHIVE_FETCH,,}"
  if [ "$disable_archive_fetch_normalized" = "true" ] || [ "$disable_archive_fetch_normalized" = "1" ]; then
    disable_archive_flag=(--disable-archive-fetch)
  fi
  # Always bind to 0.0.0.0 for the cache service, regardless of BITCOIN_CACHE_HOST
  # BITCOIN_CACHE_HOST is used for connecting TO the service, not binding
  CACHE_BIND_HOST="${CACHE_BIND_HOST:-0.0.0.0}"
  echo "[entrypoint] starting bitcoin-cache on ${CACHE_BIND_HOST}:${BITCOIN_CACHE_PORT}"
  # Pass S3 credentials via environment variables (not CLI args) for security
  # This prevents credentials from appearing in process listings and shell history
  S3_ACCESS_KEY="${S3_ACCESS_KEY}" \
  S3_SECRET_KEY="${S3_SECRET_KEY}" \
  "/app/core-lane-node" bitcoin-cache \
    --host "${CACHE_BIND_HOST}" \
    --port "${BITCOIN_CACHE_PORT}" \
    --cache-dir "${CACHE_DIR}" \
    --bitcoin-rpc-url "${BITCOIN_UPSTREAM_RPC_URL}" \
    --block-archive "${BLOCK_ARCHIVE_URL}" \
    --starting-block-count "${STARTING_BLOCK_COUNT}" \
    --s3-bucket "${S3_BUCKET}" \
    --s3-region "${S3_REGION}" \
    --s3-endpoint "${S3_ENDPOINT}" \
    "${disable_archive_flag[@]}" \
    --no-rpc-auth &
  BITCOIN_CACHE_PID=$!
  child_pids+=("$BITCOIN_CACHE_PID")
  
  # Wait for bitcoin-cache to be ready before starting core-lane
  # Use 127.0.0.1 when checking locally (same container), BITCOIN_CACHE_HOST is for remote connections
  if [ -z "${ONLY_START:-}" ] || [ "${ONLY_START:-}" != "bitcoin-cache" ]; then
    if ! wait_for_service "127.0.0.1" "${BITCOIN_CACHE_PORT}" 30 "${BITCOIN_CACHE_PID}"; then
      echo "[entrypoint] Failed to wait for bitcoin-cache, but continuing anyway..."
    fi
  fi
fi

if [ -z "${ONLY_START:-}" ] || [ "${ONLY_START:-}" = "core-lane" ]; then
  # Check if mnemonic is required
  if [ -z "${CORE_LANE_MNEMONIC:-}" ]; then
    if [ "${ONLY_START:-}" = "core-lane" ]; then
      echo "[entrypoint] ERROR: CORE_LANE_MNEMONIC is required when ONLY_START=core-lane"
      exit 1
    else
      echo "[entrypoint] WARNING: CORE_LANE_MNEMONIC not set, skipping core-lane startup"
    fi
  else
    # Ensure wallet exists before starting RPC (creates wallet_<network>.sqlite3 in DATA_DIR)
    echo "[entrypoint] ensuring wallet database exists for network ${NETWORK} in ${DATA_DIR}"
    if ! CORE_LANE_MNEMONIC="${CORE_LANE_MNEMONIC}" NETWORK="${NETWORK}" \
      "/app/core-lane-node" get-address \
      --network "${NETWORK}" \
      --data-dir "${DATA_DIR}" >/tmp/core-lane-get-address.log 2>&1; then
      echo "[entrypoint] WARNING: failed to create wallet during startup; see /tmp/core-lane-get-address.log"
    else
      echo "[entrypoint] wallet ready (see /tmp/core-lane-get-address.log for details)"
    fi

    # Wait for bitcoin-cache service to be available before starting core-lane
    # This is especially important when running in separate Fly.io apps
    if [ -n "${BITCOIN_CACHE_HOST:-}" ] && [ "${BITCOIN_CACHE_HOST}" != "127.0.0.1" ] && [ "${BITCOIN_CACHE_HOST}" != "localhost" ]; then
      echo "[entrypoint] Waiting for bitcoin-cache service at ${BITCOIN_CACHE_HOST}:${BITCOIN_CACHE_PORT} to be available..."
      if ! wait_for_service "${BITCOIN_CACHE_HOST}" "${BITCOIN_CACHE_PORT}" 120; then
        echo "[entrypoint] WARNING: bitcoin-cache service not available, but continuing to start core-lane..."
      else
        echo "[entrypoint] bitcoin-cache service is ready!"
      fi
    fi
    
    echo "[entrypoint] starting core-lane RPC on ${HTTP_HOST}:${HTTP_PORT}"
    CORE_LANE_PID=""
    # This prevents the mnemonic from appearing in process listings and shell history
    CORE_LANE_MNEMONIC="${CORE_LANE_MNEMONIC}" \
    "/app/core-lane-node" start \
      --data-dir "${DATA_DIR}" \
      --bitcoin-rpc-read-url "${BITCOIN_CACHE_PROTOCOL}://${BITCOIN_CACHE_HOST}:${BITCOIN_CACHE_PORT}" \
      --bitcoin-rpc-read-user "${RPC_USER}" \
      --bitcoin-rpc-read-password "${RPC_PASSWORD}" \
      --start-block "${STARTING_BLOCK_COUNT}" \
      --electrum-url "${ELECTRUM_URL}" \
      --http-host "${HTTP_HOST}" \
      --http-port "${HTTP_PORT}" &
    CORE_LANE_PID=$!
    child_pids+=("$CORE_LANE_PID")
    
    # Wait a moment and verify core-lane started successfully
    sleep 2
    if ! kill -0 "$CORE_LANE_PID" 2>/dev/null; then
      echo "[entrypoint] ERROR: core-lane process ${CORE_LANE_PID} exited immediately after start!"
      wait "$CORE_LANE_PID" 2>/dev/null || true
      exit_status=$?
      echo "[entrypoint] core-lane exit status: ${exit_status}"
      # Don't exit here - let bitcoin-cache keep running if ONLY_START is not set
      if [ -z "${ONLY_START:-}" ]; then
        echo "[entrypoint] Continuing with bitcoin-cache only..."
        # Remove from child_pids so we don't wait for it
        remaining_pids=()
        for pid in "${child_pids[@]}"; do
          if [ "$pid" != "$CORE_LANE_PID" ]; then
            remaining_pids+=("$pid")
          fi
        done
        child_pids=("${remaining_pids[@]}")
      else
        echo "[entrypoint] ONLY_START=core-lane was set, exiting..."
        exit "$exit_status"
      fi
    else
      # Wait for core-lane HTTP server to be ready
      echo "[entrypoint] Waiting for core-lane RPC server to be ready on ${HTTP_HOST}:${HTTP_PORT}..."
      if ! wait_for_service "${HTTP_HOST}" "${HTTP_PORT}" 60 "${CORE_LANE_PID}"; then
        echo "[entrypoint] WARNING: core-lane RPC server did not become ready, but process is still running"
      else
        echo "[entrypoint] core-lane RPC server is ready!"
      fi
    fi
  fi
fi

# derive node mode
if [ "${ONLY_START:-}" = "derive-node" ]; then
  # Validate required environment variables for derive-node
  if [ -z "${CHAIN_ID:-}" ] || [ -z "${DERIVED_DA_ADDRESS:-}" ]; then
    echo "[entrypoint] ERROR: CHAIN_ID and DERIVED_DA_ADDRESS must be set for derive-node mode"
    exit 1
  fi

  if [ -f "${DATA_DIR}/vc-cm-snapshot.squashfs" ]; then
    VC_CM_SNAPSHOT_FILE="${DATA_DIR}/vc-cm-snapshot.squashfs"
  else if [ -f "/vc-cm-snapshot.squashfs" ]; then
    VC_CM_SNAPSHOT_FILE="/vc-cm-snapshot.squashfs"
  else
    echo "[entrypoint] ERROR: vc-cm-snapshot.squashfs not found"
    exit 1
  fi

    echo "[entrypoint] mounting vc-cm-snapshot.squashfs from ${DATA_DIR}"
    mkdir -p "${DATA_DIR}/vc-cm-snapshot"
    # mount -o loop won't work in docker but it'll work in fly.io
    
    if mount -t squashfs -o loop "${VC_CM_SNAPSHOT_FILE}" "${DATA_DIR}/vc-cm-snapshot"; then
      echo "[entrypoint] Successfully mounted vc-cm-snapshot.squashfs using mount"
    elif unsquashfs -f -d "${DATA_DIR}/vc-cm-snapshot" "${VC_CM_SNAPSHOT_FILE}"; then
      echo "[entrypoint] Successfully extracted vc-cm-snapshot.squashfs using unsquashfs"
    else
      echo "[entrypoint] WARNING: failed to use vc-cm-snapshot.squashfs"
      exit 1
    fi
  fi

  echo "[entrypoint] starting derive-node on ${HTTP_HOST}:${HTTP_PORT}"
  export LANE_LAYER_SNAPSHOT_DIR="${DATA_DIR}/vc-cm-snapshot"
  CORE_RPC_URL="${CORE_RPC_URL:-https://rpc.lanelayer.com}"
  "/app/core-lane-node" derived-start \
    --data-dir "${DATA_DIR}" \
    --core-rpc-url "${CORE_RPC_URL}" \
    --chain-id "${CHAIN_ID}" \
    --derived-da-address "${DERIVED_DA_ADDRESS}" \
    --start-block "${START_BLOCK}" \
    --http-host "${HTTP_HOST}" \
    --http-port "${HTTP_PORT}" &
  DERIVE_NODE_PID=$!
  child_pids+=("$DERIVE_NODE_PID")

  echo "[entrypoint] waiting for derive-node to be ready on ${HTTP_HOST}:${HTTP_PORT}..."
  if ! wait_for_service "${HTTP_HOST}" "${HTTP_PORT}" 60 "${DERIVE_NODE_PID}"; then
    echo "[entrypoint] WARNING: derive-node did not become ready, but process is still running"
  else
    echo "[entrypoint] derive-node is ready!"
  fi
fi



# Monitor child processes and handle exits gracefully
set +e

if [ "${#child_pids[@]}" -eq 0 ]; then
  echo "[entrypoint] No child processes started; exiting."
  exit 0
fi

wait -n
STATUS=$?
cleanup_children TERM
wait || true

if [ -n "$received_signal" ]; then
  case "$received_signal" in
    TERM) STATUS=143 ;;
    INT) STATUS=130 ;;
  esac
fi

exit "$STATUS"
