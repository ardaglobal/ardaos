#!/bin/bash

# Integration test script for compliance compiler
# Runs tests that require schema files

echo "Running integration tests with schema validation..."
go test -v -integration ./internal/schema/

echo ""
echo "Running all tests including integration tests..."
go test -v -integration ./...
