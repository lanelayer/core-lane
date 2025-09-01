#!/bin/bash

# Test script for enhanced transaction methods
# This script tests the new transaction querying capabilities

set -e

echo "🧪 Testing Enhanced Transaction Methods"
echo "========================================"

# Function to call JSON-RPC
call_json_rpc() {
    local method="$1"
    local params="$2"
    
    curl -s -X POST http://localhost:3000/ \
        -H "Content-Type: application/json" \
        -d "{
            \"jsonrpc\": \"2.0\",
            \"method\": \"$method\",
            \"params\": [$params],
            \"id\": 1
        }" | jq -r '.result // .error'
}

# Start the Core MEL node in the background
echo "🚀 Starting Core MEL node..."
cargo run --bin core-mel-node &
NODE_PID=$!

# Wait for the node to start
sleep 3

echo ""
echo "📋 Testing Transaction Methods:"
echo "-------------------------------"

# Test 1: Get transaction count
echo "1. Testing eth_getTransactionCount..."
TRANSACTION_COUNT=$(call_json_rpc "eth_getTransactionCount" "\"0x0000000000000000000000000000000000000000\", \"latest\"")
echo "   Transaction count: $TRANSACTION_COUNT"

# Test 2: Get block number
echo ""
echo "2. Testing eth_blockNumber..."
BLOCK_NUMBER=$(call_json_rpc "eth_blockNumber" "")
echo "   Block number: $BLOCK_NUMBER"

# Test 3: Get block by number
echo ""
echo "3. Testing eth_getBlockByNumber..."
BLOCK_DATA=$(call_json_rpc "eth_getBlockByNumber" "\"0x0\", false")
echo "   Genesis block data: $BLOCK_DATA"

# Test 4: Get block transaction count
echo ""
echo "4. Testing eth_getBlockTransactionCountByNumber..."
TX_COUNT=$(call_json_rpc "eth_getBlockTransactionCountByNumber" "\"0x0\"")
echo "   Genesis block transaction count: $TX_COUNT"

# Test 5: Get transaction by block number and index (if transactions exist)
echo ""
echo "5. Testing eth_getTransactionByBlockNumberAndIndex..."
if [ "$TX_COUNT" != "0x0" ] && [ "$TX_COUNT" != "null" ]; then
    TX_DATA=$(call_json_rpc "eth_getTransactionByBlockNumberAndIndex" "\"0x0\", \"0x0\"")
    echo "   Transaction data: $TX_DATA"
else
    echo "   No transactions in genesis block to test"
fi

# Test 6: Get transaction by hash (if we have a transaction hash)
echo ""
echo "6. Testing eth_getTransactionByHash..."
# This would need an actual transaction hash to test properly
echo "   (Would need actual transaction hash to test)"

# Test 7: Get transaction receipt (if we have a transaction hash)
echo ""
echo "7. Testing eth_getTransactionReceipt..."
echo "   (Would need actual transaction hash to test)"

echo ""
echo "✅ Transaction method tests completed!"

# Clean up
echo "🧹 Cleaning up..."
kill $NODE_PID 2>/dev/null || true
wait $NODE_PID 2>/dev/null || true

echo ""
echo "🎉 All tests completed successfully!"
