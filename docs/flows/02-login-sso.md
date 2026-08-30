# Flow 2 — Login + SSO (SP-A first, then SP-B with no second login)

Actors: a browser, SP-A (`sp-a`), SP-B (`sp-b`), the IdP (public app on `idp`, internal
app on `idp-internal`). All requests/responses below are the **actual** ones captured
live on 2026-08-29 against the container deployment (hostnames resolved via curl
`--resolve`, no `/etc/hosts` edit — see Flow 1).

## Step-by-step

1. **Browser → SP-A: `GET /login`** (`sp/api/routes.py::login`).
   SP-A has no session cookie yet. `LoginService.begin()`
   (`sp/service/login.py`):
   - Generates `state` (`crypto.new_opaque("st_")`), `nonce` (`crypto.new_opaque("no_")`),
     and a PKCE `code_verifier` (`crypto.new_code_verifier()`, 64 random bytes,
     base64url).
   - Inserts an `SPPendingAuthRow` in **SP-A's own DB**, keyed by `state`, holding
     `nonce` + `code_verifier`, expiring in `auth_code_ttl_seconds + 60` = 120s.
   - Fetches the IdP's `authorization_endpoint` from
     `GET http://idp:9400/.well-known/openid-configuration` (cached after the first
     call, in `IdPClient`).
   - Returns `302 Found` → `http://idp:9400/authorize?response_type=code&client_id=sp-a&
     redirect_uri=http://sp-a:9401/callback&scope=openid+profile&state=<state>&
     nonce=<nonce>&code_challenge=<S256(verifier)>&code_challenge_method=S256`.

2. **Browser → IdP: `GET /authorize`** (`idp/api/auth_ui.py::authorize`).
   - `_validate_authorize_params`: requires `response_type=code`,
     `code_challenge_method=S256`, a non-empty `code_challenge`, and `"openid"` present
     in `scope`. Any failure → `400`.
   - `ClientService.get("sp-a")` loads `ClientRow` from `idp.db`; compares
     `redirect_uri` **exactly** against the registered value — any mismatch (even a
     trailing slash) → `400 "redirect_uri does not match the registered value"`. No
     open-redirect surface here.
   - No `fabric_idp_sid` cookie present (first-ever login) → renders `login.html`,
     `200`, with the 7 authorize params carried as **hidden form fields** (escaped by
     Jinja2's autoescape — confirmed no XSS via any of these reflected values).

3. **Browser → IdP: `POST /login`** with `email=ada@example.com`,
   `password=correct horse battery`, plus the 7 hidden fields from step 2
   (`idp/api/auth_ui.py::login`).
   - Re-validates the same params (defense in depth against a tampered hidden form).
   - `UserService.authenticate()` (`idp/service/users.py`): looks up `UserRow` by
     lower-cased email; verifies the Argon2id hash with `argon2.PasswordHasher.verify`.
     **If the email doesn't exist**, it still runs `_hasher.verify()` against a
     precomputed dummy hash before returning the same `"invalid email or password"`
     error — constant-time-ish, prevents timing-based user enumeration.
   - On success: `SessionService.create("user-ada")` inserts an `IdPSessionRow` — new
     `sid` (`crypto.new_opaque("sid_")`), `idle_expiry` = now+900s,
     `absolute_expiry` = now+28800s, `revoked=False`.
   - Audits `auth.login.succeeded` (NOTICE) with `subject=user-ada`, `sid`.
   - `_resume_authorization()` — the group-authorization gate runs **first**, here:
     `UserService.get_groups(sess_row.subject)` vs `client.authorized_groups` — if the
     intersection is empty, this stops right here: renders `forbidden.html`, `403`, audits
     `client.access.denied` (WARNING), and **no code is ever minted**. Ada is in
     `engineering`, which SP-A authorizes, so this passes and continues to:
     `OIDCFlowService.issue_authorization_code()` — re-checks `redirect_uri`, mints
     `code` (`crypto.new_opaque("ac_")`), inserts an `AuthCodeRow` binding
     `code ↔ client_id, subject, sid, redirect_uri, code_challenge, nonce`,
     `expires_at` = now+60s, `consumed=False`.
   - Response: `303 See Other` → `http://sp-a:9401/callback?code=<code>&state=<state>`
     (or the `403` above, on a denial) — **either way, with**
     `Set-Cookie: fabric_idp_sid=<sid>; HttpOnly; Path=/; SameSite=lax`
     (`Secure` only if `FABRIC_COOKIE_SECURE=true`): the cookie is set unconditionally by
     the caller (`login()`), since the group gate is an authorization decision about
     *this SP*, not an authentication failure — a denied user still gets their IdP-wide
     SSO cookie to reach apps they're actually authorized for.

4. **Browser → SP-A: `GET /callback?code=...&state=...`**
   (`sp/api/routes.py::callback`).
   - `LoginService.complete(state, code)`:
     - `PendingAuthRepository.take(state)` — fetches **and deletes** the
       `SPPendingAuthRow` in one call (single-use). `None` → `400 "unknown login state
       (possible CSRF or expired transaction)"`. Expired → `400`.
     - Loads SP-A's own signing key (`SPClientKeyRow`), builds a `private_key_jwt`
       client assertion: `{iss: "sp-a", sub: "sp-a", aud: <token_endpoint>, jti, iat,
       exp: iat+120}`, signed EdDSA/Ed25519.
     - `IdPClient.token_endpoint()` — from the **already-cached** discovery doc, this
       resolves to `http://idp-internal:9410/token`, **not** the public `idp:9400` — see
       Flow 1 / DESIGN.md §5.7.
     - `POST http://idp-internal:9410/token` with `grant_type=authorization_code, code,
       redirect_uri, client_id=sp-a, code_verifier=<the one stored server-side in step
       1>, client_assertion_type=..., client_assertion=<jwt from above>`.
   - **At the IdP (`idp/api/token.py::token` → `OIDCFlowService.exchange_code`,
     running on the internal app):**
     - `ClientService.authenticate()`: checks `client_assertion_type`; loads
       `ClientRow`; **checks `key_revoked` first** (fails fast, no signature check, if
       revoked — see Flow 5); verifies the JWT signature against the registered public
       key, `issuer=client_id`, `audience=<the exact token_endpoint URL SP-A used>`;
       checks `sub == client_id`; checks `exp - iat ≤ 120s`; checks the `jti` hasn't been
       seen (`UsedAssertionRow`, primary key on `jti` — replay-safe even under a race,
       unlike the auth-code `consumed` flag).
     - Loads the `AuthCodeRow` by `code`: must exist, `consumed=False`, not expired,
       `client_id` matches, `redirect_uri` matches exactly, and
       `pkce_matches(code_verifier, stored_code_challenge)` (constant-time SHA-256
       compare). Any mismatch → `400 invalid_grant`.
     - Marks `consumed=True`, loads the user's profile, mints **two** JWTs with the
       IdP's active Ed25519 key: `id_token` (`aud=azp="sp-a"`, `sid`, `nonce` echoed,
       `email`, `name`, 300s TTL) and `access_token` (same claims minus `nonce`/profile,
       plus `scope`, also 300s TTL). **No `roles` claim** — roles are not an IdP concept
       at all (see Flow 3/4's precondition note); the only IdP-internal authorization
       input, `groups`, was already checked back in step 3 (before any code existed) and
       never becomes a claim either.
     - Records that this `sid` reached `client_id=sp-a` (`SessionClientRow`) — this is
       what makes back-channel logout able to find SP-A later.
     - Returns `200` `{access_token, id_token, token_type: "Bearer", expires_in: 300}`,
       `Cache-Control: no-store`.
   - **Back at SP-A:** `LoginService._verify()` on **both** tokens: signature (against
     the IdP's JWKS, fetched from `http://idp:9400/.well-known/jwks.json` — the
     **public** endpoint, cached, refetched only on an unknown `kid`), `iss ==
     http://idp:9400`, **`aud == "sp-a"`** (this is the cross-SP-integrity check), and
     for the `id_token` specifically, `claims["nonce"] == <the nonce SP-A generated in
     step 1>` — this is what stops a token meant for a different login attempt from
     being injected here.
   - `SPSessionService.create_from_claims()`: `subject`, `idp_sid`, `email`, `name` come
     straight from the verified claims above. `roles` does **not** — it's looked up from
     this SP's own `SPUserRoleRow` table by `subject` (defaulting to, and writing
     through, `["user"]` on a first-ever login here). Inserts the resulting
     `SPSessionRow` in **SP-A's own DB** — new `sid` (prefix `spsid_`), 900s idle / 28800s
     absolute expiry.
   - Response: `303 See Other` → `/profile`, **with**
     `Set-Cookie: fabric_sp_sp_a=<spsid>; HttpOnly; Path=/; SameSite=lax`.

5. **Browser → SP-A: `GET /profile`.** `SPSessionService.load_valid()` finds the row,
   slides `idle_expiry` forward another 900s, returns `200` rendering `profile.html`
   with the user's name/email/roles/`sp_sid`/`idp_sid`.

**Verified live:** exact trace captured —
```
GET  http://sp-a:9401/login       -> 302 -> http://idp:9400/authorize?...
GET  http://idp:9400/authorize?...-> 200  (login form)
POST http://idp:9400/login        -> 303 -> http://sp-a:9401/callback?code=...&state=...
GET  http://sp-a:9401/callback?...-> 303 -> /profile
GET  http://sp-a:9401/profile     -> 200  (shows "Ada Lovelace")
```

## SSO to SP-B — no second login

6. **Browser → SP-B: `GET /login`.** Same as step 1, but for `sp-b`'s own `state` /
   `nonce` / `code_verifier` (a fresh, independent `SPPendingAuthRow` in **SP-B's** DB).
   Redirects to `http://idp:9400/authorize?...client_id=sp-b...`.

7. **Browser → IdP: `GET /authorize`, again.** This time the browser **already carries**
   the `fabric_idp_sid` cookie from step 3 (cookies are host-scoped to `idp`, sent
   regardless of which SP triggered the request). `SessionService.load_valid(sid)` finds
   the still-live `IdPSessionRow` (idle timeout slides again). Since a valid session
   exists, `authorize()` skips the login form entirely and calls `_resume_authorization()`
   directly — which runs the **exact same group-authorization gate** as step 3, now
   checked against `client_id="sp-b"`'s `authorized_groups` instead of SP-A's (Ada is
   still in `engineering`, still authorized, so it passes again) — then mints a **new**
   `AuthCodeRow` (`client_id="sp-b"`, same `sid`, SP-B's own `code_challenge`/`nonce`) and
   returns `303` straight to `http://sp-b:9402/callback?code=...&state=...`. **The
   password was never asked for a second time.** (Had Ada's group *not* been authorized
   at SP-B, this exact step is where she'd get a `403` instead — see Flow 1's README
   cross-reference on the group gate; this is the same mechanism, just resuming an
   existing session instead of a fresh login.)

8. **Browser → SP-B: `GET /callback`, `GET /profile`.** Identical mechanics to steps 4–5,
   scoped to SP-B: its own `private_key_jwt` assertion (SP-B's own key, never SP-A's),
   its own PKCE verifier, its own audience check (`aud == "sp-b"`), its own session
   cookie `fabric_sp_sp_b` (a **different** cookie name, so it can't collide with SP-A's
   even though both are eventually reachable from the same browser).

**Verified live:**
```
GET http://sp-b:9402/login        -> 302 -> http://idp:9400/authorize?...client_id=sp-b...
GET http://idp:9400/authorize?... -> 303 -> http://sp-b:9402/callback?...   (no login form!)
GET http://sp-b:9402/callback?... -> 303 -> /profile
GET http://sp-b:9402/profile      -> 200  (shows "ada@example.com", no password field anywhere)
```

## Cross-SP integrity (why SP-A's token is useless at SP-B)

Verified by running this inside the sp-a container (needs SP-A's real private key, which
only that container has): mint a real `id_token` for SP-A using SP-A's genuine private
key, then verify it twice —
```
verify(token, issuer="http://idp:9400", audience="sp-a")  -> succeeds
verify(token, issuer="http://idp:9400", audience="sp-b")  -> InvalidClaimError (rejected)
```
This is enforced independently by *both* sides: the IdP only ever stamps `aud` = the
client that authenticated at `/token` (never a caller-supplied value), and each SP's own
`LoginService._verify()` separately asserts `aud == its own client_id` before trusting
anything in the token. Either check alone would be enough; both existing is
defense-in-depth.
