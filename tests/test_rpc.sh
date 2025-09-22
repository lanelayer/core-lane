#!/bin/bash

# Test script for Core Lane JSON-RPC endpoint

echo "🧪 Testing Core Lane JSON-RPC eth_getBalance endpoint..."

# Test address
TEST_ADDRESS="0x1234567890123456789012345678901234567890"

# Test request
REQUEST='{
  "jsonrpc": "2.0",
  "method": "eth_getBalance",
  "params": ["'$TEST_ADDRESS'", "latest"],
  "id": 1
}'

echo "📤 Sending request:"
echo "$REQUEST" | jq .

echo ""
echo "📥 Response:"
curl -s -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d "$REQUEST" | jq .

echo ""
echo "✅ Test completed!"
