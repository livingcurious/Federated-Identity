# Flow 5 — SP Key Compromise & Recovery

Scenario: SP-A's `private_key_jwt` signing key is suspected compromised (RCE, a leaked
secret, whatever the cause). Unlike the IdP's own signing keys, an SP key has no expiry
and — before this feature — no revoke lever at all; a leak was effectively permanent.
This flow is the fix: contain immediately, recover without ever exposing the new private
key to the IdP.

## Step 1 — Contain: revoke SP-A's key at the IdP

**Caller:** an operator, holding the admin token, from wherever can reach the internal
IdP surface (under containers: only from inside the compose network — the host itself
has no route to `idp-internal:9410`; verified by running this from **inside the sp-a
container** via `docker exec`, since `sp-a` is on the same network as `idp-internal`).

`POST http://idp-internal:9410/admin/clients/sp-a/revoke-key`,
header `X-Admin-Token: <the one printed by the provisioner>`.

- `require_admin` dependency (`idp/deps.py`): loads the stored Argon2 hash of the admin
  token from `MetaRow`, verifies the supplied header against it with
  `argon2.PasswordHasher.verify` (constant-time-ish; also constant-work even if the
  header is missing/wrong-length, since `verify_password` always runs the hash check
  unless `stored is None`).
- `ClientService.revoke_key("sp-a")` (`idp/service/clients.py`): loads the `ClientRow`,
  sets `key_revoked = True`. **Nothing about the key material itself changes** — the old
  public key stays in `ClientRow.public_jwk`, this is purely a boolean gate checked
  before any cryptographic verification is even attempted.
- `audit.record(Event.CLIENT_KEY_REVOKED, Severity.ALERT, actor="admin",
  client_id="sp-a")` — `204 No Content`.

**Verified live:** `204`.

## Step 2 — Confirm containment: a real login attempt now fails cleanly

A genuine browser-style login (Flow 2, steps 1–4) is driven through, unmodified. It
proceeds normally all the way to the `/token` exchange, where:

- `ClientService.authenticate()` loads `ClientRow` for `sp-a`, checks
  `if client.key_revoked:` **before** calling `crypto.load_key`/verifying any signature —
  fails fast, no wasted crypto work, and importantly this means a revoked key is rejected
  even if the attacker's copy of the key is perfectly valid and correctly signed.
- Raises `InvalidClientError("client key has been revoked")`.
- `audit.record(Event.CLIENT_AUTH_FAILED, Severity.WARNING, client_id="sp-a",
  detail={"reason": "client key has been revoked"})` and, at the `/token` route level,
  `Event.TOKEN_DENIED` (also WARNING) with the same reason.
- SP-A's `LoginService.complete()` sees the non-200 from `/token`, raises
  `LoginError(f"token endpoint rejected the exchange: client key has been revoked")`.
- Browser sees SP-A's own `error.html`, `400`, message: *"IdP returned an error"* → no,
  specifically: *"token endpoint rejected the exchange: client key has been revoked"*.

**Verified live:**
```
login final status: 400
error shown: token endpoint rejected the exchange: client key has been revoked
```

## Step 3 — Recover: generate a fresh keypair, touching only SP-A's own database

**As documented:** `docker compose exec sp-a python scripts/rotate_sp_key.py sp-a`.

`scripts/rotate_sp_key.py::rotate("sp-a")`:
1. Opens **only** `settings.sp_db_path("sp-a")` — never `idp.db`. Under containers this
   resolves to `/data/spa/sp_a.db` via `FABRIC_SP_A_DB_FILE`, i.e. exactly the volume
   `sp-a`'s own container has mounted, and no other container can reach.
2. `crypto.generate_signing_key(new_kid)` — a brand-new Ed25519 keypair, unrelated to the
   compromised one.
3. `ClientKeyRepository.upsert()` — overwrites the single `SPClientKeyRow` for `sp-a`
   with the new `kid` + both JWK halves.
4. Prints `{"public_jwk": {...}}` to **stdout** — deliberately **only** the public half.
   The private half is committed to the DB and never printed, logged, or transmitted
   anywhere by this script.

> **Note — container-image gap found during the first verification pass (see Flow 1,
> Finding 2), since resolved:** `scripts/` was not copied into the Docker/Podman image,
> so `docker compose exec sp-a python scripts/rotate_sp_key.py sp-a` failed with "no
> such file". First verified via an inline equivalent
> (`docker exec identity-fabric-sp-a-1 python -c "..."`, reproducing the script's logic
> verbatim, still scoped to `/data/spa/sp_a.db` only) — result below. `Containerfile` now
> `COPY scripts ./scripts`; the *actual* documented command was re-verified afterward and
> now works unmodified (second result below).

**Verified live** (first pass, inline equivalent, run inside the `sp-a` container):
```json
{"public_jwk": {"crv": "Ed25519", "x": "YG0ldpo3JfKBXbaNaEGmX3jM0SbBM4CxUElbxAWJVTg", "kid": "k_c972876598643cf6", "use": "sig", "alg": "Ed25519", "kty": "OKP"}}
```

**Verified live** (after the `Containerfile` fix, the actual documented command, unmodified):
```
$ docker compose exec sp-a python scripts/rotate_sp_key.py sp-a
New key generated for 'sp-a' (kid=k_a12365509d10b73b).
Register this PUBLIC key with the IdP (POST .../admin/clients/sp-a/register-key):
{"public_jwk": {"crv": "Ed25519", "x": "DvKeTigaVqGwnzGDwnpEJrrk_VnH1WJRRV4cl7G6cCU", "kid": "k_a12365509d10b73b", "use": "sig", "alg": "Ed25519", "kty": "OKP"}}
```
Followed by `register-key` (`204`) and a fresh login attempt (`200`, "Ada Lovelace"
shown) — full recovery via the exact command sequence in `README.md`, no workaround
needed.

## Step 4 — Re-register: submit only the public key to the IdP

`POST http://idp-internal:9410/admin/clients/sp-a/register-key`,
body `{"public_jwk": {...from step 3...}}`, same admin token.

`ClientService.register_key("sp-a", public_jwk)`:
1. **Refuses** if the submitted JWK contains a `"d"` field (the private-key component of
   an OKP JWK) — `InvalidRequestError("refusing to store a private key component
   ('d')")`. This exists specifically so that even an operator mistake — pasting the
   *private* half by accident — can't leak it into `idp.db`.
2. `crypto.load_key(public_jwk)` — must actually parse as a usable Ed25519 key; a
   malformed/garbage submission is rejected here (`400`) rather than silently stored.
3. Sets `client.public_jwk = public_jwk` and `client.key_revoked = False` — the new key
   is now trusted, and the revocation is lifted **in the same call**, so there's no
   window where the new key is registered but still blocked by the old revoke flag.
4. `audit.record(Event.CLIENT_KEY_REGISTERED, Severity.NOTICE, actor="admin",
   client_id="sp-a")` — `204 No Content`.

**Verified live:** `204`.

## Step 5 — Confirm recovery: login works again

Flow 2 driven through once more, unmodified. `/token` now succeeds — SP-A's fresh key
correctly signs the new client assertion, the IdP verifies it against the newly
registered public key, and the full token exchange + session creation completes
normally.

**Verified live:**
```
login final status: 200
shows Ada Lovelace: True
```

## Full audit trail for this flow (read from `idp.db`'s `audit_events` table)

| event | severity | client_id | detail |
|---|---|---|---|
| `client.key.revoked` | alert | sp-a | — |
| `client.auth.failed` | warning | sp-a | reason: client key has been revoked |
| `token.exchange.denied` | warning | sp-a | error: invalid_client, error_description: client key has been revoked |
| `client.key.registered` | notice | sp-a | — |

Every step of this incident — the containment action, the blocked attempt while
contained, and the recovery — is independently reconstructable from the audit trail
alone, without needing to correlate anything else.
