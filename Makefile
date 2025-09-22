# Core Lane Makefile
# Provides easy commands for building, testing, and running Core Lane

.PHONY: help build test test-unit test-integration clean start-env stop-env reset-env run-burn run-scan

# Default target
help:
	@echo "Core Lane Development Commands"
	@echo "============================="
	@echo ""
	@echo "Build Commands:"
	@echo "  build          - Build the Core Lane node"
	@echo "  clean          - Clean build artifacts"
	@echo ""
	@echo "Test Commands:"
	@echo "  test           - Run all tests (unit + integration)"
	@echo "  test-unit      - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo ""
	@echo "Environment Commands:"
	@echo "  start-env      - Start Bitcoin regtest environment"
	@echo "  stop-env       - Stop Bitcoin regtest environment"
	@echo "  reset-env      - Reset Bitcoin regtest environment"
	@echo ""
	@echo "Dev Environment Commands (recommended):"
	@echo "  dev-start      - Start complete Core Lane dev environment"
	@echo "  dev-stop       - Stop Core Lane dev environment"
	@echo "  dev-status     - Check dev environment status"
	@echo "  dev-balances   - Check Core Lane balances"
	@echo ""
	@echo "Demo Commands:"
	@echo "  run-burn       - Run a demo burn transaction"
	@echo "  run-node       - Run the Core Lane node"
	@echo ""
	@echo "Development Commands:"
	@echo "  check          - Run cargo check"
	@echo "  fmt            - Format code with rustfmt"
	@echo "  clippy         - Run clippy linter"

# Build commands
build:
	@echo "Building Core Lane node..."
	cargo build

clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -f test_transaction.bin

# Test commands
test: test-unit test-integration

test-unit:
	@echo "Running unit tests..."
	cargo test

test-integration:
	@echo "Running integration tests..."
	@if [ ! -f "target/debug/core-lane-node" ]; then \
		echo "Building Core Lane node first..."; \
		cargo build; \
	fi
	@if [ ! -f "tests/integration_test.sh" ]; then \
		echo "Integration test script not found"; \
		exit 1; \
	fi
	@chmod +x tests/integration_test.sh
	@./tests/integration_test.sh

# Environment commands
start-env:
	@echo "Starting Bitcoin regtest environment..."
	@if [ ! -f "test-environment.sh" ]; then \
		echo "test-environment.sh not found"; \
		exit 1; \
	fi
	@chmod +x test-environment.sh
	@./test-environment.sh start
	@./test-environment.sh setup-wallet

stop-env:
	@echo "Stopping Bitcoin regtest environment..."
	@if [ -f "test-environment.sh" ]; then \
		./test-environment.sh stop; \
	fi

reset-env: stop-env start-env

# Dev Environment commands (recommended for development)
dev-start:
	@echo "Starting Core Lane development environment..."
	@if [ ! -f "scripts/dev-environment.sh" ]; then \
		echo "dev-environment.sh not found"; \
		exit 1; \
	fi
	@chmod +x scripts/dev-environment.sh
	@./scripts/dev-environment.sh start

dev-stop:
	@echo "Stopping Core Lane development environment..."
	@if [ -f "scripts/dev-environment.sh" ]; then \
		./scripts/dev-environment.sh stop; \
	fi

dev-status:
	@echo "Checking Core Lane development environment status..."
	@if [ ! -f "scripts/dev-environment.sh" ]; then \
		echo "dev-environment.sh not found"; \
		exit 1; \
	fi
	@chmod +x scripts/dev-environment.sh
	@./scripts/dev-environment.sh status

dev-balances:
	@echo "Checking Core Lane balances..."
	@if [ ! -f "scripts/dev-environment.sh" ]; then \
		echo "dev-environment.sh not found"; \
		exit 1; \
	fi
	@chmod +x scripts/dev-environment.sh
	@./scripts/dev-environment.sh balances

# Demo commands
run-burn: build
	@echo "Running demo burn transaction..."
	@if [ ! -f "test-environment.sh" ]; then \
		echo "test-environment.sh not found"; \
		exit 1; \
	fi
	@./test-environment.sh status
	@echo ""
	@echo "Creating burn transaction..."
	@./target/debug/core-lane-node burn \
		--burn-amount 500000 \
		--chain-id 1 \
		--eth-address "0x1234567890123456789012345678901234567890" \
		--rpc-password bitcoin123

run-node: build
	@echo "Running Core Lane node with JSON-RPC server..."
	@echo "🚀 Starting Core Lane node with block scanning and JSON-RPC on http://localhost:8545"
	@echo "📡 JSON-RPC endpoints available:"
	@echo "   - eth_getBalance: POST http://localhost:8545"
	@echo ""
	@./scripts/dev-environment.sh start \
		--start-block 100 \
		--rpc-user bitcoin \
		--rpc-password bitcoin123 \
		--http-host 127.0.0.1 \
		--http-port 8545

# Development commands
check:
	@echo "Running cargo check..."
	cargo check

fmt:
	@echo "Formatting code..."
	cargo fmt

clippy:
	@echo "Running clippy..."
	cargo clippy

# Quick test workflow
quick-test: build start-env run-burn run-node
	@echo "Quick test workflow completed!"

# Full test workflow
full-test: clean build test start-env run-burn run-node
	@echo "Full test workflow completed!"
