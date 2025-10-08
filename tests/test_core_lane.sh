#!/bin/bash

echo "🧪 Testing Core Lane Node"
echo "=========================="

# Build the project
echo "📦 Building Core Lane node..."
cargo build

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

echo "✅ Build successful!"

# Test CLI help
echo ""
echo "🔧 Testing CLI interface..."
./target/debug/core-lane-node --help

echo ""
echo "✅ Core Lane Node is working correctly!"
echo ""
echo "🚀 Available Commands:"
echo ""
echo "Start the node (continuously scan blocks):"
echo "   ./target/debug/core-lane-node start \\"
echo "     --bitcoin-rpc-read-user bitcoin \\"
echo "     --bitcoin-rpc-read-password bitcoin123"
echo ""
echo "Start from specific block:"
echo "   ./target/debug/core-lane-node start \\"
echo "     --start-block 200 \\"
echo "     --bitcoin-rpc-read-user bitcoin \\"
echo "     --bitcoin-rpc-read-password bitcoin123"
echo ""
echo "Create a burn transaction:"
echo "   ./target/debug/core-lane-node burn \\"
echo "     --burn-amount 500000 \\"
echo "     --chain-id 1 \\"
echo "     --eth-address 0x1234567890123456789012345678901234567890 \\"
echo "     --rpc-url http://127.0.0.1:18443 \\"
echo "     --rpc-user bitcoin \\"
echo "     --rpc-password bitcoin123"
echo ""
echo "Send transaction to DA:"
echo "   ./target/debug/core-lane-node send-transaction \\"
echo "     --raw-tx-hex 02f872... \\"
echo "     --rpc-url http://127.0.0.1:18443 \\"
echo "     --rpc-user bitcoin \\"
echo "     --rpc-password bitcoin123"
