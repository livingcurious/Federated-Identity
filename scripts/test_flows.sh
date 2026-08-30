#!/usr/bin/env bash
# Manual end-to-end test pass for every feature this project claims, using curl
# against the real running stack (plus a couple of one-liners for the admin API,
# which has no published port -- see the note above that section).
#
# Prerequisites:
#   1. The fabric is up: ./container-start.sh -d  (or plain `<engine> compose up --build -d`)
#   2. 127.0.0.1 idp sp-a sp-b is in /etc/hosts (container-start.sh tells you the
#      exact line if it's missing)
#   3. Get the admin token once, right after startup:
#        docker compose logs provisioner | grep -A1 'Admin token'
#      (or `podman compose ...` -- whichever engine you're on)
#
# Usage:
#   ADMIN_TOKEN=adm_... ./scripts/test_flows.sh
#
# Everything below is read top-to-bottom, printing what it expects next to what it
# got, so you can eyeball a diff. Nothing here is destructive to seeded data (a
# couple of steps flip a group grant or a client key and then flip it back).
set -uo pipefail  # not -e: we want every section to run even if one assertion fails

: "${ADMIN_TOKEN:?Set ADMIN_TOKEN first -- see 'docker compose logs provisioner'}"

IDP="http://idp:9400"
SPA="http://sp-a:9401"
SPB="http://sp-b:9402"
COMPOSE_EXEC="docker compose exec idp-internal"  # swap for `podman compose exec ...` if that's your engine

pass=0
fail=0
check() {
  # check <label> <expected> <actual>
  if [ "$2" = "$3" ]; then
    pass=$((pass + 1))
    printf "  OK   %-55s expected=%s got=%s\n" "$1" "$2" "$3"
  else
    fail=$((fail + 1))
    printf "  FAIL %-55s expected=%s got=%s\n" "$1" "$2" "$3"
  fi
}

section() { echo; echo "=== $1 ==="; }

# Logs a full browser-style login (POST /login at the IdP, credentials + the 8
# hidden authorize params scraped off the login form) into $2's cookie jar.
# login <sp_base_url> <cookie_jar> <email> <password>
login() {
  local sp_base="$1" jar="$2" email="$3" password="$4"
  rm -f "$jar"
  local body
  body=$(curl -s -c "$jar" -L "$sp_base/login")
  local rt cid ru st no cc ccm sc
  rt=$(echo "$body" | grep -oE 'name="response_type" value="[^"]*"' | sed -E 's/.*value="([^"]*)"/\1/')
  cid=$(echo "$body" | grep -oE 'name="client_id" value="[^"]*"' | sed -E 's/.*value="([^"]*)"/\1/')
  ru=$(echo "$body" | grep -oE 'name="redirect_uri" value="[^"]*"' | sed -E 's/.*value="([^"]*)"/\1/')
  st=$(echo "$body" | grep -oE 'name="state" value="[^"]*"' | sed -E 's/.*value="([^"]*)"/\1/')
  no=$(echo "$body" | grep -oE 'name="nonce" value="[^"]*"' | sed -E 's/.*value="([^"]*)"/\1/')
  cc=$(echo "$body" | grep -oE 'name="code_challenge" value="[^"]*"' | sed -E 's/.*value="([^"]*)"/\1/')
  ccm=$(echo "$body" | grep -oE 'name="code_challenge_method" value="[^"]*"' | sed -E 's/.*value="([^"]*)"/\1/')
  sc=$(echo "$body" | grep -oE 'name="scope" value="[^"]*"' | sed -E 's/.*value="([^"]*)"/\1/')
  curl -s -c "$jar" -b "$jar" -L -o /dev/null -w "%{http_code}" \
    --data-urlencode "email=$email" \
    --data-urlencode "password=$password" \
    --data-urlencode "response_type=$rt" \
    --data-urlencode "client_id=$cid" \
    --data-urlencode "redirect_uri=$ru" \
    --data-urlencode "state=$st" \
    --data-urlencode "nonce=$no" \
    --data-urlencode "code_challenge=$cc" \
    --data-urlencode "code_challenge_method=$ccm" \
    --data-urlencode "scope=$sc" \
    "$IDP/login"
}

JAR_ADA=/tmp/fabric_test_ada.jar
JAR_MARIE=/tmp/fabric_test_marie.jar
JAR_GRACE=/tmp/fabric_test_grace.jar
JAR_DIANA=/tmp/fabric_test_diana.jar

# ---------------------------------------------------------------------------
section "Discovery + JWKS (no auth needed)"
# ---------------------------------------------------------------------------
code=$(curl -s -o /dev/null -w "%{http_code}" "$IDP/.well-known/openid-configuration")
check "GET /.well-known/openid-configuration" 200 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" "$IDP/.well-known/jwks.json")
check "GET /.well-known/jwks.json" 200 "$code"

# ---------------------------------------------------------------------------
section "Login + SSO (ada, engineering group -- authorized at both SPs)"
# ---------------------------------------------------------------------------
code=$(login "$SPA" "$JAR_ADA" "ada@example.com" "correct horse battery!1")
check "login at SP-A" 200 "$code"
code=$(curl -s -c "$JAR_ADA" -b "$JAR_ADA" -L -o /dev/null -w "%{http_code}" "$SPB/login")
check "SSO-resume at SP-B, same cookies, no password" 200 "$code"

# ---------------------------------------------------------------------------
section "Cross-tenant access control (marie, finance-dept -- NOT authorized at SP-B)"
# ---------------------------------------------------------------------------
code=$(login "$SPA" "$JAR_MARIE" "marie@example.com" "curie-radium-1903!")
check "marie logs into SP-A (finance-dept is authorized there)" 200 "$code"
code=$(curl -s -c "$JAR_MARIE" -b "$JAR_MARIE" -L -o /dev/null -w "%{http_code}" "$SPB/login")
check "marie tries SP-B via SSO-resume -- denied by group check" 403 "$code"

# ---------------------------------------------------------------------------
section "Role-gated panels (RBAC)"
# ---------------------------------------------------------------------------
code=$(login "$SPA" "$JAR_GRACE" "grace@example.com" "hopper-admin-2024!")
check "grace logs into SP-A" 200 "$code"
code=$(curl -s -c "$JAR_GRACE" -b "$JAR_GRACE" -o /dev/null -w "%{http_code}" "$SPA/admin")
check "grace (admin at SP-A) -> GET /admin" 200 "$code"
code=$(curl -s -c "$JAR_GRACE" -b "$JAR_GRACE" -L -o /dev/null -w "%{http_code}" "$SPB/login")
code2=$(curl -s -c "$JAR_GRACE" -b "$JAR_GRACE" -o /dev/null -w "%{http_code}" "$SPB/admin")
check "grace (same identity, plain 'user' at SP-B) -> GET /admin" 403 "$code2"

code=$(curl -s -c "$JAR_MARIE" -b "$JAR_MARIE" -o /dev/null -w "%{http_code}" "$SPA/finance")
check "marie (finance role) -> GET /finance" 200 "$code"
code=$(curl -s -c "$JAR_MARIE" -b "$JAR_MARIE" -o /dev/null -w "%{http_code}" "$SPA/admin")
check "marie (no admin role) -> GET /admin" 403 "$code"

code=$(login "$SPA" "$JAR_DIANA" "diana@example.com" "diana-hr-secure-1!")
check "diana logs into SP-A" 200 "$code"
code=$(curl -s -c "$JAR_DIANA" -b "$JAR_DIANA" -o /dev/null -w "%{http_code}" "$SPA/hr")
check "diana (hr role) -> GET /hr" 200 "$code"

# ---------------------------------------------------------------------------
section "HR role management (assign/revoke, both mirrored the same way)"
# ---------------------------------------------------------------------------
alan_sub="user-alan"
code=$(curl -s -c "$JAR_DIANA" -b "$JAR_DIANA" -o /dev/null -w "%{http_code}" \
  --data-urlencode "subject=$alan_sub" --data-urlencode "role=admin" "$SPA/hr/assign-role")
check "diana (hr only) tries to grant admin -- blocked" 403 "$code"
code=$(curl -s -c "$JAR_DIANA" -b "$JAR_DIANA" -o /dev/null -w "%{http_code}" \
  --data-urlencode "subject=user-diana" --data-urlencode "role=hr" "$SPA/hr/assign-role")
check "diana tries to grant a role to herself -- blocked" 403 "$code"
code=$(curl -s -c "$JAR_DIANA" -b "$JAR_DIANA" -o /dev/null -w "%{http_code}" \
  --data-urlencode "subject=$alan_sub" --data-urlencode "role=finance" "$SPA/hr/assign-role")
check "diana tries to grant finance (a role she doesn't hold) -- blocked" 403 "$code"
code=$(curl -s -c "$JAR_DIANA" -b "$JAR_DIANA" -L -o /dev/null -w "%{http_code}" \
  --data-urlencode "subject=$alan_sub" --data-urlencode "role=hr" "$SPA/hr/assign-role")
check "diana grants hr (a role she holds) to alan -- allowed" 200 "$code"
code=$(curl -s -c "$JAR_DIANA" -b "$JAR_DIANA" -o /dev/null -w "%{http_code}" \
  --data-urlencode "subject=$alan_sub" --data-urlencode "role=finance" "$SPA/hr/revoke-role")
check "diana tries to revoke finance (doesn't hold it) -- blocked" 403 "$code"
code=$(curl -s -c "$JAR_DIANA" -b "$JAR_DIANA" -L -o /dev/null -w "%{http_code}" \
  --data-urlencode "subject=$alan_sub" --data-urlencode "role=hr" "$SPA/hr/revoke-role")
check "diana revokes hr from alan again (cleanup) -- allowed" 200 "$code"

# ---------------------------------------------------------------------------
section "Local-only sign-out vs sign-out-everywhere"
# ---------------------------------------------------------------------------
curl -s -c "$JAR_ADA" -b "$JAR_ADA" -o /dev/null "$SPA/logout-local"
code=$(curl -s -c "$JAR_ADA" -b "$JAR_ADA" -o /dev/null -w "%{http_code}" "$SPA/profile")
check "ada's SP-A session is gone after /logout-local" 302 "$code"
code=$(curl -s -c "$JAR_ADA" -b "$JAR_ADA" -L -o /dev/null -w "%{http_code}" "$SPA/login")
check "ada's IdP session is untouched -- SSO-resumes, no password" 200 "$code"
curl -s -c "$JAR_ADA" -b "$JAR_ADA" -L -o /dev/null "$SPA/logout"  # -L: this redirects
# to the IdP's own /logout, which is where the session revoke and back-channel fan-out
# to every SP this session reached actually happens -- skip -L and only SP-A's own
# local session gets revoked, the IdP-wide sign-out never actually runs.
code=$(curl -s -c "$JAR_ADA" -b "$JAR_ADA" -L -o /dev/null -w "%{http_code}" "$SPB/login")
check "after /logout (everywhere), SSO-resume at SP-B now needs a password too" 200 "$code"
# (200 here means it landed back on the *login form*, not /profile -- check by content:)
body=$(curl -s -c "$JAR_ADA" -b "$JAR_ADA" -L "$SPB/login")
if echo "$body" | grep -q 'name="password"'; then
  echo "  OK   confirms a real login form was shown, not a silent resume"
  pass=$((pass + 1))
else
  echo "  FAIL expected a login form after full logout, got something else"
  fail=$((fail + 1))
fi

# ---------------------------------------------------------------------------
section "Isolation proof (from inside SP-A's own admin panel)"
# ---------------------------------------------------------------------------
body=$(curl -s -c "$JAR_GRACE" -b "$JAR_GRACE" "$SPA/admin/isolation-check")
iso_count=$(echo "$body" | grep -c "ISOLATED</span>")
check "both isolation probes report ISOLATED" 2 "$iso_count"

# ---------------------------------------------------------------------------
section "Admin API (idp-internal has no published port -- run via container exec)"
# ---------------------------------------------------------------------------
# curl isn't installed in the images (python:3.13-slim doesn't ship it), so these
# use python3 + httpx instead -- both are already project dependencies, always
# present in every container. Swap $COMPOSE_EXEC for `podman compose exec idp-internal`
# if you're on Podman.

echo "  -- list active IdP sessions --"
$COMPOSE_EXEC python3 -c "
import httpx
r = httpx.get('http://idp-internal:9410/admin/sessions', headers={'X-Admin-Token': '$ADMIN_TOKEN'})
print(' ', r.status_code, r.text[:200])
"

echo "  -- list recent audit events --"
$COMPOSE_EXEC python3 -c "
import httpx
r = httpx.get('http://idp-internal:9410/admin/audit?limit=5', headers={'X-Admin-Token': '$ADMIN_TOKEN'})
print(' ', r.status_code)
for e in r.json():
    print('   ', e['event'], e.get('outcome'))
"

echo "  -- rotate the IdP's signing key, then list keys (old one stays valid in JWKS) --"
$COMPOSE_EXEC python3 -c "
import httpx
r = httpx.post('http://idp-internal:9410/admin/keys/rotate', headers={'X-Admin-Token': '$ADMIN_TOKEN'})
print(' rotate:', r.status_code, r.json())
r = httpx.get('http://idp-internal:9410/admin/keys', headers={'X-Admin-Token': '$ADMIN_TOKEN'})
for k in r.json():
    print('   ', k['kid'], k['status'])
"

echo "  -- SP key compromise + recovery round-trip (sp-b), verified with a real login --"
$COMPOSE_EXEC python3 -c "
import httpx
h = {'X-Admin-Token': '$ADMIN_TOKEN'}
r = httpx.post('http://idp-internal:9410/admin/clients/sp-b/revoke-key', headers=h)
print(' 1. revoke:', r.status_code)
"
code=$(login "$SPB" /tmp/fabric_test_recovery_check.jar "ada@example.com" "correct horse battery!1")
check "login at SP-B fails while its key is revoked" 400 "$code"
ROTATE_OUT=$(docker compose exec sp-b python scripts/rotate_sp_key.py sp-b 2>&1)
echo " 2. $(echo "$ROTATE_OUT" | head -1)"
JWK_JSON=$(echo "$ROTATE_OUT" | grep -o '{"public_jwk":.*}')
docker compose exec -e ADMIN_TOKEN="$ADMIN_TOKEN" -e JWK_JSON="$JWK_JSON" idp-internal python3 -c "
import os, json, httpx
h = {'X-Admin-Token': os.environ['ADMIN_TOKEN']}
payload = json.loads(os.environ['JWK_JSON'])
r = httpx.post('http://idp-internal:9410/admin/clients/sp-b/register-key', headers=h, json=payload)
print(' 3. register-key:', r.status_code)
"
code=$(login "$SPB" /tmp/fabric_test_recovery_check.jar "ada@example.com" "correct horse battery!1")
check "login at SP-B works again after recovery" 200 "$code"

echo "  -- group authorize/revoke round-trip on sp-b (engineering), then put back --"
$COMPOSE_EXEC python3 -c "
import httpx
h = {'X-Admin-Token': '$ADMIN_TOKEN'}
r = httpx.post('http://idp-internal:9410/admin/clients/sp-b/groups/engineering/revoke', headers=h)
print(' revoke:', r.status_code)
r = httpx.post('http://idp-internal:9410/admin/clients/sp-b/groups/engineering/authorize', headers=h)
print(' re-authorize:', r.status_code)
"

# ---------------------------------------------------------------------------
section "Admin: revoke-all sessions at SP-A takes effect on the very next request"
# ---------------------------------------------------------------------------
code=$(curl -s -c "$JAR_GRACE" -b "$JAR_GRACE" -o /dev/null -w "%{http_code}" "$SPA/admin")
check "grace -> GET /admin before revoke-all" 200 "$code"
curl -s -X POST -c "$JAR_GRACE" -b "$JAR_GRACE" -o /dev/null "$SPA/admin/revoke-all"
code=$(curl -s -c "$JAR_GRACE" -b "$JAR_GRACE" -o /dev/null -w "%{http_code}" "$SPA/admin")
check "grace -> GET /admin right after (same cookie) -- revoked" 302 "$code"

# ---------------------------------------------------------------------------
section "Summary"
# ---------------------------------------------------------------------------
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
