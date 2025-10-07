#!/bin/bash
set -e

DATADIR="/home/bitcoin/.bitcoin"
UTXO_URL="http://144.76.56.210/utxo-916200.dat"
# Make sure datadir exists
mkdir -p "$DATADIR"
REINDEX_FLAG=""

# If no blockchain data exists, fetch snapshot
if [ ! -d "$DATADIR/blocks" ]; then
  echo "[*] No blockchain data found. Fetching snapshot..."
  cd /tmp
  curl -O "$UTXO_URL"

  echo "[*] Snapshot extracted."
  REINDEX_FLAG="-reindex"
else
  echo "[*] Blockchain data already present, skipping snapshot download."
fi

# Create bitcoin.conf with prune=0 as required
CONF_FILE="$DATADIR/bitcoin.conf"
if [ ! -f "$CONF_FILE" ]; then
  echo "[*] Creating default bitcoin.conf ..."
  cat > "$CONF_FILE" <<CONF
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
assumevalid=000000000000000000003b57a64583fe0544d3eddd4482f82ad0509fe1b9e7e2
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
bitcoind -conf="$CONF_FILE" -datadir="$DATADIR" $REINDEX_FLAG -printtoconsole &

if [ -e /tmp/utxo-916200.dat ]; then
	echo "Waiting for initial block import"
	while true; do
		INITIAL=`bitcoin-cli -rpcclienttimeout=0 getblockchaininfo | jq -r .headers`
		if [ -n "$INITIAL" ]; then
			if [ "$INITIAL" -gt 916200 ]; then
				echo "initialblockdownload done"
				bitcoin-cli setnetworkactive false
				break
			fi
		fi
		sleep 0.5
	done
	bitcoin-cli -rpcclienttimeout=0 loadtxoutset /tmp/utxo-916200.dat
	rm -f /tmp/utxo-916200.dat
	bitcoin-cli setnetworkactive true
fi

while true; do sleep 86400; done
