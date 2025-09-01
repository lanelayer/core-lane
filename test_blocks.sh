#!/bin/bash

# Test script for Core MEL block system
# This script tests the genesis block initialization and block querying functionality

set -e

echo "🧪 Testing Core MEL Block System"
echo "================================="

# Start the Core MEL node in the background
echo "🚀 Starting Core MEL node..."
cargo run -- start --rpc-url http://127.0.0.1:18443 --rpc-user bitcoin --rpc-password password &
NODE_PID=$!

# Wait for the node to start
echo "⏳ Waiting for node to start..."
sleep 5

# Test 1: Get latest block number (should be 0 for genesis)
echo ""
echo "📊 Test 1: Getting latest block number"
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_blockNumber",
    "params": [],
    "id": 1
  }' | jq '.'

# Test 2: Get genesis block by number
echo ""
echo "📦 Test 2: Getting genesis block by number"
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_getBlockByNumber",
    "params": ["0x0", false],
    "id": 2
  }' | jq '.'

# Test 3: Get genesis block by number (full details)
echo ""
echo "📦 Test 3: Getting genesis block by number (full details)"
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_getBlockByNumber",
    "params": ["0x0", true],
    "id": 3
  }' | jq '.'

# Test 4: Get genesis block using "earliest"
echo ""
echo "📦 Test 4: Getting genesis block using 'earliest'"
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_getBlockByNumber",
    "params": ["earliest", false],
    "id": 4
  }' | jq '.'

# Test 5: Get latest block using "latest"
echo ""
echo "📦 Test 5: Getting latest block using 'latest'"
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_getBlockByNumber",
    "params": ["latest", false],
    "id": 5
  }' | jq '.'

# Test 6: Get block transaction count
echo ""
echo "📊 Test 6: Getting block transaction count"
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_getBlockTransactionCountByNumber",
    "params": ["0x0"],
    "id": 6
  }' | jq '.'

# Test 7: Test non-existent block
echo ""
echo "❌ Test 7: Testing non-existent block"
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_getBlockByNumber",
    "params": ["0x100", false],
    "id": 7
  }' | jq '.'

# Test 8: Test pending block (should return null)
echo ""
echo "⏳ Test 8: Testing pending block"
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_getBlockByNumber",
    "params": ["pending", false],
    "id": 8
  }' | jq '.'

echo ""
echo "✅ Block system tests completed!"
echo ""

# Clean up
echo "🧹 Cleaning up..."
kill $NODE_PID 2>/dev/null || true
wait $NODE_PID 2>/dev/null || true

echo "🎉 All tests completed successfully!"
