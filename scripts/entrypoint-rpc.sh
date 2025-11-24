#!/usr/bin/env bash
set -euo pipefail


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


if [ -z "${ONLY_START:-}" ] || [ "$ONLY_START" = "bitcoin-cache" ]; then
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
  if [ -z "${ONLY_START:-}" ] || [ "$ONLY_START" != "bitcoin-cache" ]; then
    if ! wait_for_service "127.0.0.1" "${BITCOIN_CACHE_PORT}" 30 "${BITCOIN_CACHE_PID}"; then
      echo "[entrypoint] Failed to wait for bitcoin-cache, but continuing anyway..."
    fi
  fi
fi

if [ -z "${ONLY_START:-}" ] || [ "$ONLY_START" = "core-lane" ]; then
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
    CORE_LANE_PID=$!
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
    CORE_LANE_PID=$!
  fi
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
