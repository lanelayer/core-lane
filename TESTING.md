# Core MEL Testing Guide

This guide covers setting up and using the Core MEL test environment for development and testing.

## Quick Start

### Prerequisites

- **Docker**: Required for running Bitcoin regtest network
- **Rust**: Required for building Core MEL node
- **Git**: For cloning repositories

### Setup Test Environment

```bash
# 1. Start Bitcoin regtest network
./test-environment.sh start

# 2. Setup wallet and mine initial blocks
./test-environment.sh setup-wallet

# 3. Build Core MEL node
./test-environment.sh build

# 4. Test connection
./test-environment.sh test
```

## Test Environment Commands

The `test-environment.sh` script provides the following commands:

### Core Commands

| Command | Description |
|---------|-------------|
| `start` | Start Bitcoin regtest network in Docker |
| `stop` | Stop Bitcoin regtest network |
| `reset` | Reset Bitcoin regtest network (clean slate) |
| `setup-wallet` | Setup wallet and mine 101 initial blocks |
| `build` | Build Core MEL node |
| `test` | Test Core MEL connection to Bitcoin |
| `status` | Show current test environment status |
| `help` | Show help information |

### Examples

```bash
# Full setup in one go
./test-environment.sh start setup-wallet build test

# Check current status
./test-environment.sh status

# Reset everything and start fresh
./test-environment.sh reset start setup-wallet build test
```

## Bitcoin Regtest Network

### Configuration

The test environment uses Bitcoin Core 29.0 in regtest mode with the following configuration:

- **Network**: Regtest (private local network)
- **RPC Port**: 18443
- **P2P Port**: 18444
- **RPC User**: `bitcoin`
- **RPC Password**: `bitcoin123`
- **Fallback Fee**: 0.0002 BTC
- **Transaction Index**: Enabled

### Data Persistence

Bitcoin data is stored in `~/bitcoin-regtest/` and persists between container restarts. Use `./test-environment.sh reset` to start with a clean slate.

### Mining

The test environment automatically mines 101 blocks to activate coinbase transactions. You can mine additional blocks manually:

```bash
# Get test address
ADDRESS=$(cat .test-address)

# Mine 10 more blocks
docker exec bitcoin-regtest bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin123 -rpcwallet=mine generatetoaddress 10 "$ADDRESS"
```

## Testing Core MEL Features

### 1. Bitcoin Burn Detection

Test the automatic minting feature by creating Bitcoin burn transactions:

```bash
# 1. Ensure test environment is running
./test-environment.sh status

# 2. Create burn transaction using Core MEL (much easier!)
./target/debug/core-mel-node burn \
    --burn-amount 500000 \
    --chain-id 1 \
    --eth-address "0x1234567890123456789012345678901234567890" \
    --rpc-password bitcoin123

# 3. Test Core MEL scanning to see the automatic minting
./target/debug/core-mel-node scan-blocks \
    --rpc-url "http://127.0.0.1:18443" \
    --rpc-user bitcoin \
    --rpc-password bitcoin123 \
    --blocks 5
```

**Alternative**: You can also use bitcoin-data-layer for more control:

```bash
cd ../bitcoin-data-layer
cargo run -- burn \
    --wif "your_private_key" \
    --prev-txid "previous_txid" \
    --prev-vout 0 \
    --prev-value 1000000 \
    --burn-amount 500000 \
    --fee 1000 \
    --change-address "your_change_address" \
    --chain-id 1 \
    --eth-address "0x1234567890123456789012345678901234567890" \
    --network regtest
```

### 2. Core MEL Transaction Processing

Test Core MEL transaction execution by creating DA envelopes:

```bash
# 1. Create Core MEL transaction data
echo "CORE_LANE_TEST_DATA" > test-transaction.bin

# 2. Create DA envelope using bitcoin-data-layer
cd ../bitcoin-data-layer
cargo run -- create-envelope --data-file ../core-mel/test-transaction.bin --network regtest

# 3. Fund the envelope address and create reveal transaction
# (Follow bitcoin-data-layer instructions)

# 4. Test Core MEL processing
cd ../core-mel
./target/debug/core-mel-node scan-blocks \
    --rpc-url "http://127.0.0.1:18443" \
    --rpc-user bitcoin \
    --rpc-password bitcoin123 \
    --blocks 5
```

### 3. Account State Verification

Check account balances and state after transactions:

```bash
# Start Core MEL node in continuous mode
./target/debug/core-mel-node start \
    --rpc-url "http://127.0.0.1:18443" \
    --rpc-user bitcoin \
    --rpc-password bitcoin123 \
    --start-block 100
```

## Test Scenarios

### Scenario 1: Bitcoin Burn → Core MEL Mint

1. **Setup**: Start test environment and mine blocks
2. **Burn**: Create Bitcoin burn transaction with BRN1 format
3. **Verify**: Check that Core MEL tokens are minted to the specified address
4. **Balance**: Verify account balance in Core MEL state

### Scenario 2: Core MEL Transfer

1. **Setup**: Ensure accounts have tokens (from burns or previous tests)
2. **Transfer**: Create Core MEL transfer transaction
3. **Verify**: Check sender balance decreased, recipient balance increased
4. **Gas**: Verify gas fees were charged correctly

### Scenario 3: Core MEL Exit

1. **Setup**: Account with Core MEL tokens
2. **Exit**: Create exit transaction to withdraw to Bitcoin
3. **Verify**: Check tokens are locked/burned in Core MEL
4. **State**: Verify exit state is properly recorded

## Debugging

### Common Issues

1. **Bitcoin RPC Connection Failed**
   ```bash
   # Check if Bitcoin container is running
   docker ps | grep bitcoin-regtest
   
   # Check Bitcoin logs
   docker logs bitcoin-regtest
   ```

2. **Core MEL Build Failed**
   ```bash
   # Clean and rebuild
   cargo clean
   cargo build
   ```

3. **No Transactions Found**
   ```bash
   # Check if blocks have transactions
   docker exec bitcoin-regtest bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin123 getblockcount
   
   # Mine more blocks
   ./test-environment.sh setup-wallet
   ```

### Logs and Debugging

```bash
# Bitcoin logs
docker logs -f bitcoin-regtest

# Core MEL logs (when running)
./target/debug/core-mel-node start --rpc-url "http://127.0.0.1:18443" --rpc-user bitcoin --rpc-password bitcoin123
```

## Integration with bitcoin-data-layer

The test environment is designed to work with the `bitcoin-data-layer` project for creating burn transactions and DA envelopes:

```bash
# Clone bitcoin-data-layer if not already present
git clone https://github.com/your-org/bitcoin-data-layer.git ../bitcoin-data-layer

# Build bitcoin-data-layer
cd ../bitcoin-data-layer
cargo build

# Use burn and envelope creation tools
cargo run -- burn --help
cargo run -- create-envelope --help
```

## Cleanup

```bash
# Stop everything
./test-environment.sh stop

# Reset everything (destructive)
./test-environment.sh reset

# Remove test files
rm -f .test-address test-transaction.bin
```

## Next Steps

After setting up the test environment:

1. **Test Bitcoin Burn Detection**: Create burn transactions and verify automatic minting
2. **Test Core MEL Transactions**: Create and process Core MEL transactions
3. **Test State Management**: Verify account balances and state transitions
4. **Test Error Handling**: Test various error conditions and edge cases
5. **Performance Testing**: Test with larger numbers of transactions and blocks

## Troubleshooting

### Docker Issues

```bash
# Check Docker status
docker info

# Restart Docker if needed
sudo systemctl restart docker  # Linux
# Or restart Docker Desktop on macOS/Windows
```

### Bitcoin RPC Issues

```bash
# Test RPC connection manually
curl --user bitcoin:bitcoin123 --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblockchaininfo", "params": []}' -H 'content-type: text/plain;' http://127.0.0.1:18443/
```

### Core MEL Issues

```bash
# Check Rust toolchain
rustc --version
cargo --version

# Update dependencies
cargo update

# Clean build
cargo clean && cargo build
```
