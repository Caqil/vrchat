#!/bin/bash

# ==============================================
# Admin Login Test Script
# Tests the admin login endpoint
# ==============================================

# Configuration
SERVER_URL="${SERVER_URL:-http://localhost:8080}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin123}"

echo "🧪 Testing Admin Login Endpoint"
echo "Server: $SERVER_URL"
echo "Username: $ADMIN_USERNAME"

# Test 1: Health check
echo ""
echo "1. Testing server health..."
curl -s "$SERVER_URL/health" | jq . || echo "Health check failed"

# Test 2: Admin login
echo ""
echo "2. Testing admin login..."
RESPONSE=$(curl -s -X POST "$SERVER_URL/admin/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$ADMIN_USERNAME\",
    \"password\": \"$ADMIN_PASSWORD\"
  }")

echo "Response:"
echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"

# Test 3: Extract token and test protected endpoint
echo ""
echo "3. Testing protected endpoint..."
TOKEN=$(echo "$RESPONSE" | jq -r '.data.token // empty' 2>/dev/null)

if [ ! -z "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    echo "Token extracted: ${TOKEN:0:20}..."
    
    # Test dashboard endpoint
    DASHBOARD_RESPONSE=$(curl -s -X GET "$SERVER_URL/admin/api/dashboard/stats" \
      -H "Authorization: Bearer $TOKEN")
    
    echo "Dashboard Response:"
    echo "$DASHBOARD_RESPONSE" | jq . 2>/dev/null || echo "$DASHBOARD_RESPONSE"
else
    echo "❌ No token received - login failed"
fi

echo ""
echo "✅ Test completed"