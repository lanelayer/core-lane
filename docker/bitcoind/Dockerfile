FROM bitcoin/bitcoin:29.1

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