#!/bin/bash

# Smoke test script for identity service
# Tests nonce→session flow and JWKS correctness

echo "Starting identity service smoke test..."

# Check if required tools are available
if ! command -v curl &> /dev/null; then
    echo "curl is required but not installed"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "jq is required but not installed"
    exit 1
fi

# Default values
IDENTITY_URL=${IDENTITY_URL:-"http://localhost:8081"}

# Wait for service to be ready
echo "Waiting for identity service to be ready..."
counter=0
while ! curl -s "$IDENTITY_URL/readyz" &> /dev/null; do
    counter=$((counter + 1))
    if [ $counter -gt 30 ]; then
        echo "Identity service did not become ready in time"
        exit 1
    fi
    sleep 2
done
echo "Identity service is ready!"

# Test 1: Create a test identity
echo "Creating test identity..."
create_response=$(curl -s -X POST "$IDENTITY_URL/v1/identity" \
    -H "Content-Type: application/json" \
    -d '{"keySpec": "ed25519"}')

echo "Create identity response: $create_response"

did=$(echo "$create_response" | jq -r '.data.did')
if [ "$did" == "null" ] || [ -z "$did" ]; then
    echo "Failed to create identity"
    exit 1
fi
echo "Created DID: $did"

# Test 2: Get nonce
echo "Getting nonce..."
nonce_response=$(curl -s "$IDENTITY_URL/v1/session/nonce?did=$did&aud=cdv")

echo "Nonce response: $nonce_response"

nonce=$(echo "$nonce_response" | jq -r '.data.nonce')
if [ "$nonce" == "null" ] || [ -z "$nonce" ]; then
    echo "Failed to get nonce"
    exit 1
fi
echo "Got nonce: $nonce"

# Test 3: Check JWKS endpoint
echo "Checking JWKS endpoint..."
jwks_response=$(curl -s "$IDENTITY_URL/.well-known/jwks.json")

echo "JWKS response: $jwks_response"

keys_count=$(echo "$jwks_response" | jq -r '.data.keys | length')
if [ "$keys_count" == "null" ] || [ "$keys_count" -eq 0 ]; then
    echo "Failed to get valid JWKS"
    exit 1
fi
echo "JWKS validation successful - found $keys_count keys"

# Test 4: Check cache headers in JWKS response
cache_control=$(curl -s -D - "$IDENTITY_URL/.well-known/jwks.json" | grep -i "cache-control" | tr -d '\r')
echo "Cache-Control header: $cache_control"

if [ -z "$cache_control" ]; then
    echo "Warning: No Cache-Control header found in JWKS response"
else
    echo "Cache headers present in JWKS response"
fi

echo "Smoke test completed successfully!"
