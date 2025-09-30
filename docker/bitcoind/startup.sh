#!/bin/bash
set -e

DATADIR="/home/bitcoin/.bitcoin"
TAR_URL="http://144.76.56.210/bitcoin-data.22sep.tar"
TAR_FILE="bitcoin-data.22sep.tar"
TAR_CHECKSUM="45676a796cfedc964eb69aba693d5cbb24b764c442c755c88bc7de60090298e5"
# Make sure datadir exists
mkdir -p "$DATADIR"
REINDEX_FLAG=""

# If no blockchain data exists, fetch snapshot
if [ ! -d "$DATADIR/blocks" ]; then
  echo "[*] No blockchain data found. Fetching snapshot..."
  cd /tmp
  curl -O "$TAR_URL"
  echo "$TAR_CHECKSUM  $TAR_FILE" | sha256sum -c -
  if [ $? -ne 0 ]; then
     echo " ERROR: Snapshot checksum mismatch!"
    exit 1
  fi

  echo "[*] Checksum verified." 

  tar -C "$DATADIR" -xf "$TAR_FILE"

  rm "$TAR_FILE"

  echo "[*] Snapshot extracted."
  REINDEX_FLAG="-reindex"
else
  echo "[*] Blockchain data already present, skipping snapshot download."
fi

# Create bitcoin.conf with prune=0 as required
CONF_FILE="$DATADIR/bitcoin.conf"
if [ ! -f "$CONF_FILE" ]; then
  echo "[*] Creating default bitcoin.conf ..."
  cat > "$CONF_FILE" <<'CONF'
server=1
listen=1
prune=0
rpcbind=0.0.0.0:8332
rpcallowip=0.0.0.0/0
rpcuser=${RPC_USER}
rpcpassword=${RPC_PASSWORD}
zmqpubrawblock=tcp://0.0.0.0:28332
zmqpubrawtx=tcp://0.0.0.0:28333
dbcache=2048
txindex=1
CONF
else
  # Ensure prune=0 is set
  if grep -q "^prune=" "$CONF_FILE"; then
      sed -i 's/^prune=.*/prune=0/' "$CONF_FILE"
  else
      echo "prune=0" >> "$CONF_FILE"
  fi

  # Ensure txindex=1 is set
  if grep -q "^txindex=" "$CONF_FILE"; then
      sed -i 's/^txindex=.*/txindex=1/' "$CONF_FILE"
  else
      echo "txindex=1" >> "$CONF_FILE"
  fi
fi

echo "[*] Starting bitcoind "
exec bitcoind -conf="$CONF_FILE" -datadir="$DATADIR" $REINDEX_FLAG -printtoconsole
