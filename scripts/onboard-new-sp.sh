#!/usr/bin/env bash
# Demo: Onboard a new Service Provider (dynamic client registration)
#
# This shows the Okta-style two-step onboarding flow:
#   Step 1 — Register the client (IdP creates it as "pending", no key yet)
#   Step 2 — Generate a keypair (SP-side, private key stays in the SP)
#   Step 3 — Submit only the public key to the IdP (registration complete)
#   Step 4 — Authorize a group so users can actually SSO in
#
# Run from the project root:
#   export ADMIN=$(podman compose exec idp-internal cat /data/idp/admin_token.txt)
#   bash docs/flows/onboard-new-sp.sh
#
set -euo pipefail

IDP="http://localhost:9410"
CLIENT_ID="sp-c"
DISPLAY_NAME="New App"
REDIRECT_URI="http://sp-c:9403/callback"
LOGOUT_URI="http://sp-c:9403/backchannel-logout"
POST_LOGOUT_URI="http://sp-c:9403"

if [[ -z "${ADMIN:-}" ]]; then
  echo "!! Set ADMIN first:"
  echo "   export ADMIN=\$(podman compose exec idp-internal cat /data/idp/admin_token.txt)"
  exit 1
fi

echo
echo "=== Step 1: Register the new client (pending — no key yet) ==="
curl -s -X POST "$IDP/admin/clients" \
  -H "X-Admin-Token: $ADMIN" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"$CLIENT_ID\",
    \"display_name\": \"$DISPLAY_NAME\",
    \"redirect_uri\": \"$REDIRECT_URI\",
    \"backchannel_logout_uri\": \"$LOGOUT_URI\",
    \"post_logout_redirect_uri\": \"$POST_LOGOUT_URI\"
  }" | python3 -m json.tool

echo
echo "=== Step 2: Generate keypair for $CLIENT_ID (private key stays in the SP) ==="
KEYPAIR=$(python3 scripts/gen_sp_key.py "$CLIENT_ID" 2>/dev/null)
PUBLIC_JWK=$(echo "$KEYPAIR" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['public_jwk']))")

echo "Public JWK (safe to share with IdP):"
echo "$PUBLIC_JWK" | python3 -m json.tool

echo
echo "=== Step 3: Register only the public key with the IdP ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST "$IDP/admin/clients/$CLIENT_ID/register-key" \
  -H "X-Admin-Token: $ADMIN" \
  -H "Content-Type: application/json" \
  -d "{\"public_jwk\": $PUBLIC_JWK}"

echo
echo "=== Step 4: Authorize a group so users can SSO in ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST "$IDP/admin/clients/$CLIENT_ID/groups/engineering/authorize" \
  -H "X-Admin-Token: $ADMIN"

echo
echo "=== Done. Verify via audit log (last 5 events) ==="
curl -s "$IDP/admin/audit?limit=5" \
  -H "X-Admin-Token: $ADMIN" | python3 -m json.tool

echo
echo "Client '$CLIENT_ID' is registered and engineering users can now SSO into it."
echo "To actually serve the SP, deploy a container with the private_jwk stored in its DB."
