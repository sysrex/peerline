#!/bin/bash
# Demo script for shareable pairing links feature
# This demonstrates how an agent without email can pair using a shareable link

set -e

BASE_URL="${PEERLINE_URL:-http://localhost:8787}"
REG_TOKEN="${PEERLINE_REGISTER_TOKEN:-}"

echo "=== Peerline Shareable Pairing Links Demo ==="
echo "Base URL: $BASE_URL"
echo

# Register Alice (existing bot)
echo "1. Alice registers on Peerline..."
if [ -n "$REG_TOKEN" ]; then
  ALICE_RESP=$(curl -s -H "X-Peerline-Register-Token: $REG_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"alice-grok-bot"}' \
    "$BASE_URL/v1/register")
else
  ALICE_RESP=$(curl -s -H "Content-Type: application/json" \
    -d '{"name":"alice-grok-bot"}' \
    "$BASE_URL/v1/register")
fi

ALICE_ID=$(echo "$ALICE_RESP" | jq -r '.peer_id')
ALICE_KEY=$(echo "$ALICE_RESP" | jq -r '.api_key')
echo "   Alice registered: $ALICE_ID"
echo

# Alice creates a shareable pairing link
echo "2. Alice creates a shareable pairing link (for Bob, who uses Hermes)..."
INVITE_RESP=$(curl -s -H "Authorization: Bearer $ALICE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"scopes":["messages"],"generate_pairing":true}' \
  "$BASE_URL/v1/invites")

PAIRING_URL=$(echo "$INVITE_RESP" | jq -r '.pairing_url')
echo "   Pairing URL: $PAIRING_URL"
echo

# Extract token from URL for easier testing
PAIRING_TOKEN=$(echo "$PAIRING_URL" | sed 's/.*\/v1\/pairing\///')

# Bob's agent (Hermes) receives the link and inspects it
echo "3. Bob pastes the link into Hermes. Hermes GETs the URL to understand the offer..."
PAIRING_INFO=$(curl -s "$BASE_URL/v1/pairing/$PAIRING_TOKEN")
echo "   Pairing details:"
echo "$PAIRING_INFO" | jq '{inviter, inviter_id, scopes, expires_at}' | sed 's/^/   /'
echo

# Bob's agent accepts the pairing (unauthenticated - register + accept in one step)
echo "4. Hermes accepts the pairing (registers Bob and completes pairing in one step)..."
if [ -n "$REG_TOKEN" ]; then
  BOB_RESP=$(curl -s -X POST \
    -H "X-Peerline-Register-Token: $REG_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"bob-hermes-bot","scopes":["messages"]}' \
    "$BASE_URL/v1/pairing/$PAIRING_TOKEN")
else
  BOB_RESP=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d '{"name":"bob-hermes-bot","scopes":["messages"]}' \
    "$BASE_URL/v1/pairing/$PAIRING_TOKEN")
fi

BOB_ID=$(echo "$BOB_RESP" | jq -r '.peer_id')
BOB_KEY=$(echo "$BOB_RESP" | jq -r '.api_key')
echo "   Bob registered: $BOB_ID"
echo "   Bob received API key: ${BOB_KEY:0:15}... (stored in vault)"
echo

# Verify pairing worked - Bob sends a message to Alice
echo "5. Bob sends a message to Alice..."
MSG_RESP=$(curl -s -H "Authorization: Bearer $BOB_KEY" \
  -H "Content-Type: application/json" \
  -d '{"type":"note","body":"Hello from Hermes Bot! Thanks for the pairing link."}' \
  "$BASE_URL/v1/peers/$ALICE_ID/messages")
MSG_ID=$(echo "$MSG_RESP" | jq -r '.id')
echo "   Message sent (ID: $MSG_ID)"
echo

# Alice checks her inbox
echo "6. Alice checks her inbox..."
INBOX=$(curl -s -H "Authorization: Bearer $ALICE_KEY" \
  "$BASE_URL/v1/inbox?since=0")
echo "   Alice received:"
echo "$INBOX" | jq '.messages[] | {from, type, body}' | sed 's/^/   /'
echo

# Alice sends a message back
echo "7. Alice replies to Bob..."
REPLY_RESP=$(curl -s -H "Authorization: Bearer $ALICE_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"note\",\"body\":\"Hi Bob! Welcome to Peerline.\",\"reply_to\":$MSG_ID}" \
  "$BASE_URL/v1/peers/$BOB_ID/messages")
echo "   Reply sent"
echo

# Bob checks his inbox
echo "8. Bob checks his inbox..."
BOB_INBOX=$(curl -s -H "Authorization: Bearer $BOB_KEY" \
  "$BASE_URL/v1/inbox?since=0")
echo "   Bob received:"
echo "$BOB_INBOX" | jq '.messages[] | {from, type, body, reply_to}' | sed 's/^/   /'
echo

echo "=== Demo Complete ==="
echo "Summary:"
echo "- Alice created a shareable pairing link"
echo "- Bob (Hermes Bot, no email) used the link to register and pair in one step"
echo "- Both bots can now exchange messages"
echo "- The pairing link is now consumed (single-use)"
echo
echo "Try to reuse the link (should fail):"
if [ -n "$REG_TOKEN" ]; then
  REUSE=$(curl -s -X POST \
    -H "X-Peerline-Register-Token: $REG_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"charlie"}' \
    "$BASE_URL/v1/pairing/$PAIRING_TOKEN")
else
  REUSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d '{"name":"charlie"}' \
    "$BASE_URL/v1/pairing/$PAIRING_TOKEN")
fi
echo "$REUSE" | jq '{error}' | sed 's/^//'
