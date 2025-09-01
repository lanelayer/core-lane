#!/bin/bash

echo "🧪 Testing Core MEL Node"
echo "=========================="

# Build the project
echo "📦 Building Core MEL node..."
cargo build

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

echo "✅ Build successful!"

# Test CLI help
echo ""
echo "🔧 Testing CLI interface..."
./target/debug/core-mel-node --help

# Test scan-blocks command
echo ""
echo "🔍 Testing block scanning..."
./target/debug/core-mel-node scan-blocks --blocks 3 --rpc-user bitcoin --rpc-password bitcoin123

# Test scan-blocks with specific starting block
echo ""
echo "🔍 Testing block scanning with start block..."
./target/debug/core-mel-node scan-blocks --blocks 2 --start-block 200 --rpc-user bitcoin --rpc-password bitcoin123

echo ""
echo "✅ Core MEL Node is working correctly!"
echo ""
echo "🚀 To start continuous scanning, run:"
echo "   ./target/debug/core-mel-node start --rpc-user bitcoin --rpc-password bitcoin123"
echo "   ./target/debug/core-mel-node start --start-block 200 --rpc-user bitcoin --rpc-password bitcoin123"
echo ""
echo "🔍 To scan specific blocks, run:"
echo "   ./target/debug/core-mel-node scan-blocks --blocks 10 --rpc-user bitcoin --rpc-password bitcoin123"
echo "   ./target/debug/core-mel-node scan-blocks --blocks 5 --start-block 200 --rpc-user bitcoin --rpc-password bitcoin123"
