# Identity Fabric

A small, security-serious **Single Sign-On** trust fabric: one **Identity Provider (IdP)**
that two **Service Providers (SP-A, SP-B)** trust to identify a user. OpenID Connect
Authorization Code + PKCE, **private_key_jwt** client authentication, **Ed25519** JWKS
signing. Full architecture in [`DESIGN.md`](./DESIGN.md); the detailed request-by-request
flow write-ups are in [`docs/flows/`](./docs/flows/).

> Not a production identity system: users and SPs are seeded, and the default run is over
> `localhost` HTTP. A faithful, working model of the security mechanics — see the threat
> model below for exactly which guarantees that does and doesn't give you.

---

## How to run

**Requirements:** Python 3.11+ (developed on 3.13, Apple Silicon). Local mode needs no
Docker/Redis/Postgres — just three `uvicorn` processes and three SQLite files.

**Local:**
```bash
cd identity-fabric
./start.sh
```
Creates the venv (first run), installs, seeds the databases (prints seeded users + a
one-time admin token), and launches four processes:

| Service | URL |
|---|---|
| IdP (public) | http://127.0.0.1:9400 |
| IdP (internal — `/token`, `/admin/*`) | http://127.0.0.1:9410 |
| SP-A · Atlas Console | http://127.0.0.1:9401 |
| SP-B · Borealis Portal | http://127.0.0.1:9402 |

Seeded users (email / password / IdP group):

| Email | Password | Group |
|---|---|---|
| `ada@example.com` | `correct horse battery` | engineering |
| `grace@example.com` | `hopper-admin-2024` | engineering |
| `alan@example.com` | `turing-test-pass` | engineering |
| `marie@example.com` | `curie-radium-1903` | finance-dept |
| `linus@example.com` | `torvalds-penguin` | engineering |
| `diana@example.com` | `diana-hr-secure-1` | hr-dept |

Try it: open SP-A → sign in as `ada@example.com` → land back on SP-A, signed in → open
SP-B → signed in immediately, no second login. "Sign out everywhere" from either ends
the session on both. `python scripts/demo.py` (services running, second terminal)
scripts the same proof plus the cross-SP-audience rejection check.

Stop with **Ctrl+C**.

**Containers** (Docker or Podman — enforced, not just logical, isolation):
```bash
./container-start.sh          # Docker if available, else installs and uses Podman
```
Add `127.0.0.1 idp sp-a sp-b` to `/etc/hosts` first if prompted. Same four services, at
`http://idp:9400`, `http://sp-a:9401`, `http://sp-b:9402` — `idp-internal:9410` has **no
host-published port**; reach it with `<engine> compose exec idp-internal ...`. Admin
token is in `<engine> compose logs provisioner`. Stop with `<engine> compose down` (add
`-v` to also wipe seeded data — required after a schema change, see below).

---

## What we built, and what we cut

The original ask was five features: **cross-SP integrity**, **mutual authentication and
onboarding**, **signing-key rotation without downtime**, **compromise containment**, and
**session lifecycle and persistence**. Here's what actually shipped against that list,
what got added beyond it, and what got cut.

### Built and verified, from the original list

- **Cross-SP integrity.** Every token is stamped `aud`/`azp` = the one SP that
  authenticated at `/token` — never a caller-supplied value. Each SP independently
  re-checks `aud == its own client_id` before trusting anything. Verified live: a
  genuine SP-A token is rejected the instant SP-B checks the audience.
- **Mutual authentication.** SP → IdP: `private_key_jwt` — a signed assertion, no shared
  secret to leak, single-use via `jti`. IdP → SP: JWT signature against published JWKS +
  `iss` pinning. That second half is only a *complete* guarantee under TLS, which this
  build doesn't have (see "cut," below) — without it, "the JWKS I fetched is genuinely
  the IdP's" rests on trusting the network path it was fetched over, not on cryptography.
- **Onboarding.** Started as a single trusted-provisioner script that seeds both known
  SPs at bootstrap. We added a second path: an explicit, Okta-style admin flow
  (`POST /admin/clients` → pending client → SP generates its own keypair → submits only
  the public half via `register-key`). Both paths require an explicit trusted actor;
  neither is automatic self-registration (an SP registering itself over HTTP with no
  prior trust was considered and rejected up front, for the trust-on-first-use problem
  it creates).
- **Signing-key rotation without downtime.** IdP-side rotation with a JWKS overlap
  window existed from day one — a new key goes active while the old one stays
  verifiable until explicitly retired. We extended the same lever to SP keys, which had
  none originally: `revoke-key` → `rotate_sp_key.py` → `register-key`.
- **Compromise containment.** IdP key revoke, IdP session revoke + back-channel logout
  to every SP a session reached — day one. Added: SP-key revoke (an SP key had *zero*
  revocation lever before this work — a leak was permanent), and group revoke (pull an
  entire class of users' access to an SP instantly).
- **Session lifecycle & persistence.** Idle + absolute timeouts, SQLite-backed, survives
  a restart, independent per-SP sessions linked only by `idp_sid`. Solid from day one,
  never needed correction.

### Built, but not on the original list — because the review surfaced a real gap

- **Per-SP authorization.** Not one of the five. Its absence was the single biggest
  issue found in this whole project: *any authenticated user could SSO into any
  registered SP.* "Cross-SP integrity" only guarantees a token can't be replayed across
  SPs — it says nothing about whether the IdP should have minted a token for that SP in
  the first place. Fixed with IdP-level `groups` + per-client `authorized_groups`,
  deny-by-default, checked before any code is ever minted.
- **RBAC decoupled from the IdP.** Once groups existed, the next question was whether
  the IdP should also own fine-grained roles (admin/finance/hr). It shouldn't — role
  vocabularies are inherently per-application and don't scale centrally. Roles were
  pulled out of the `id_token` entirely; each SP now owns its own local role table.
- **Demo surfaces for both** (SP admin/finance/hr panels, two more seeded users) — so
  the access-gate and RBAC behavior are actually exercisable, not just theoretical.

### Cut — named plainly, with the reason

- **TLS/HTTPS.** Out of scope from the original design — `localhost` over HTTP. This is
  the real, current gap in "mutual authentication": the IdP-proves-itself-to-the-SP half
  depends on trusting the network path JWKS was fetched over, and there's no certificate
  chain backing that trust here.
- **Rate limiting / lockout on login.** Flagged in the first security pass, never
  built. Argon2id makes each guess expensive; there's no lockout.
- **Atomic single-use enforcement on the authorization code.** Flagged in the first
  pass — a race window lets the same code theoretically be redeemed twice under
  concurrent requests. Never fixed. Real, but narrow: exploiting it still needs the PKCE
  verifier, which never leaves the legitimate SP's server.
- **`jti` replay tracking on back-channel logout tokens.** Flagged as a minor
  observation, never built — harmless in practice since session revocation is
  idempotent.
- **A live third SP process**, to prove dynamic registration end-to-end in one
  continuous run rather than in independently-verified pieces. Deliberately deferred as
  disproportionate scope for what the feature was actually proving.
- **CSRF tokens** on session-cookie-authenticated POST endpoints. Surfaced late, not yet
  built. `SameSite=Lax` is the only defense today — real, but with gaps (state-changing
  `GET /logout`; `SameSite` doesn't even engage in local dev mode, since everything is
  `127.0.0.1` — one "site").
- **mTLS on the SP↔IdP leg** and **HSM/KMS-backed signing** — both real, stronger
  options, both explicitly discussed and declined as disproportionate for this project's
  scope rather than overlooked.

---

## Key architectural decisions

- **Container/database-per-SP isolation, enforced by the runtime, not just
  convention.** Under containers, each service mounts only its own volume; SP-A and
  SP-B sit on disjoint networks with no route between them. A compromised SP's blast
  radius is its own data and its own (now-revocable) key — not the IdP's key material,
  not the sibling SP.
- **Splitting the IdP itself in two.** The public app (login, `/authorize`, JWKS) and
  the internal app (`/token`, `/admin/*`) run as separate processes, the internal one
  with no host-published port under containers. A deliberate correction, not a day-one
  design: network segmentation between SP-A and SP-B never actually protected
  `/token`/`/admin` in the first place, because a stolen key or the admin token is a
  pure credential, checked by nothing about *where* the request came from — the
  segmentation was a boundary that looked real but wasn't, until this split made network
  placement actually mean something for that specific surface.
- **No shared secrets, anywhere.** `private_key_jwt` instead of a client secret for
  SP→IdP auth; asymmetric keypairs throughout. Revocation is a boolean flip, not a race
  to invalidate a secret everyone already has a copy of.
- **Roles pushed entirely out of the IdP.** The single biggest refactor-scale decision
  in this project: `UserRow.roles` and the `id_token`'s `roles` claim were removed
  outright, replaced by IdP-level `groups` (coarse, org-wide, checked once, before any
  token exists) and fully independent per-SP role tables. The same person can be `admin`
  at one SP and a plain `user` at another — proven live, not just asserted.
- **Deny-by-default authorization.** A newly registered client starts with
  `authorized_groups=[]` — locked out of every group until an admin explicitly grants
  one. No grandfather clause, no implicit trust for a new app.
- **Trusted, one-shot provisioner over dynamic self-registration** for the original two
  SPs — a human/pipeline-driven bootstrap that touches all three volumes exactly once,
  then exits and never runs again, rather than an always-live HTTP registration endpoint
  that would have to solve trust-on-first-use. The later admin-driven registration flow
  keeps this same property (an explicit trusted actor approves every new client) while
  adding the operational flexibility the provisioner alone didn't have.
- **A best-effort migration shim instead of a real migration framework.**
  `ALTER TABLE ... ADD COLUMN` (always nullable) covers "a column got added," honestly
  labeled as not a general migration system. A conscious scope call, not a hidden gap —
  the roles→groups schema change was still treated as breaking and required a reseed.
- **Audit logging as a first-class system from day one.** Structured JSON logs, a
  persisted per-service trail, and alert sinks, all firing independently of the
  request's DB transaction. This is what made every fix in this project — from the
  SP-key revoke to the group-authorization gate — independently verifiable after the
  fact, not just trusted on faith.

---

## Threat model

**Assets:** user credentials and sessions; the IdP's and each SP's signing keys; the
bootstrap admin token; the integrity of the audit trail; cross-tenant isolation (which
users can reach which SPs, and what they can do once there).

**Trust boundaries:** browser ↔ IdP/SPs (fully untrusted network); SP backend ↔ IdP
backend (mutually authenticated, semi-trusted); operator ↔ admin surface (bearer-token
authenticated); one SP's runtime ↔ another SP's runtime (should be zero trust — see
below for exactly how much that holds).

| Threat | Scenario | Mitigation | Residual risk |
|---|---|---|---|
| Cross-tenant access | Any authenticated user tries to SSO into an SP they shouldn't reach | IdP-level `groups` × per-client `authorized_groups`, deny-by-default, checked before any code is minted | The gate itself has no known bypass; group *membership* is seed-only — there's no admin/HR-style lever to manage it at the IdP, only to grant/revoke a group's access to a client |
| SP key theft (RCE, leaked secret) | Attacker exfiltrates an SP's private key, impersonates it to the IdP | `revoke-key` (instant, no DB access needed) → `rotate_sp_key.py` (new key, that SP's own DB only) → `register-key` | Purely reactive — nothing auto-revokes on suspicion; the window between compromise and revocation is wide open until a human acts |
| IdP signing-key compromise | Attacker forges tokens for any user, any SP | `/admin/keys/rotate` + `/revoke`, JWKS overlap window so rotation needs no SP downtime | Same detection gap as above |
| Session/cookie theft via XSS | Malicious script reads/exfiltrates the session cookie | `HttpOnly` on every session cookie | Doesn't stop a *live* XSS payload acting via same-origin requests while it's running — only stops offline replay of an exfiltrated value. The real defense is no-XSS-in-the-first-place (Jinja2 autoescaping, verified) |
| CSRF on session-authenticated POSTs | Cross-site form/fetch forces a state change (revoke sessions, approve a budget, assign a role) as a signed-in victim | `SameSite=Lax` on every session cookie (blocks cross-site POST in modern browsers) | `GET /logout` is still forgeable (low severity); `SameSite` doesn't engage at all in local dev mode (everything is `127.0.0.1` — one "site"); no server-validated token, so the protection depends entirely on client compliance |
| Algorithm confusion / signature bypass | Attacker crafts `alg: none`, or repurposes a public key as an HMAC secret | Verifier pinned to `algorithms=["Ed25519"]` explicitly — the token's own header is never trusted to pick the algorithm; Ed25519 has no symmetric-key-confusable structure at all | None identified |
| Authorization-code interception/replay | A leaked or observed code is redeemed by someone other than the SP that requested it | PKCE (S256, verifier held server-side, never touches the browser), single-use `code`, 60s expiry | The single-use check has a TOCTOU race under concurrent requests (flagged, not fixed) — narrow, since exploiting it still needs the verifier |
| Client-assertion replay | A captured `private_key_jwt` assertion is resubmitted | `jti` tracked via a DB primary-key constraint (race-safe, unlike the code's `consumed` flag), short (120s) TTL, audience-bound to the token endpoint | None identified |
| Audit-log spoofing | Attacker forges the `source_ip` recorded against their own actions | `X-Forwarded-For` only honored from a configured trusted-proxy allowlist; every `uvicorn` process also runs `--forwarded-allow-ips ""` to disable the framework's own default trust of `127.0.0.1` | None identified for this vector; the audit trail has no tamper-evidence of its own (no signing/hash-chaining of log entries) |
| Network-location impersonation of the IdP | Attacker sits at the IdP's address (DNS/ARP spoofing, a rogue container) and serves a fake JWKS/token endpoint | None in this build — this is exactly what TLS + certificate validation would close | **Open.** Direct consequence of the TLS cut; SP trust in the IdP today is address-based, not cryptographically anchored |
| Compromised SP's blast radius | RCE in SP-A | Under containers: no filesystem access to `idp.db`/SP-B's DB, no network route to SP-B, key is independently revocable, audience binding stops it minting tokens for SP-B | Under local-process mode: **none** — shared filesystem and OS user, explicitly documented as full-compromise-equivalent, not a containment claim |
| Supply-chain compromise of the provisioner | A tampered seed script/image compromises every DB it touches at bootstrap | The provisioner is the *only* component that ever touches more than one volume, and only once, before any long-running service starts — minimal, time-boxed exposure | No image signing/attestation, no dependency pinning/scanning — a real, general gap shared with essentially all software, not specific to this design |
| Container/kernel escape | A 0-day breaks out of the container runtime itself | Out of scope — this tier needs separate VMs/hosts, not container isolation | Explicit, documented non-goal |

---

## Retrospective: where the build held up, and where it needed correction

**Where it held up without needing to be told:**

- The original session/audit-logging architecture (idle+absolute timeouts, SQLite
  persistence, the three-pronged audit system) was solid from day one and never needed
  a correction — it's also what made every later fix independently verifiable.
- Recognizing that container network segmentation between SP-A and SP-B never actually
  protected `/token`/`/admin` — that a stolen key or the admin token is a pure
  credential nothing about network location gates — came from the review process
  itself, before it was asked for, and led directly to splitting the IdP into
  public/internal apps.
- The SP-key revocation lever (an SP key had *no* revoke mechanism at all before this
  project) was proposed and built as part of the same containment discussion, not
  requested first.
- Catching that uvicorn's own default proxy-header trust (`127.0.0.1`) would silently
  undo the audit-log IP-spoofing fix — found by testing the fix live and watching it
  fail, then fixing the actual root cause, not just the app-level symptom.
- Pinning the JWT verifier's algorithm explicitly (never trusting the token's own `alg`
  header) and choosing Ed25519 over RSA/ECDSA predate this project's engineering
  rounds, but explaining precisely *why* those choices close specific, named historical
  vulnerability classes (ROBOT, algorithm confusion, nonce-reuse key recovery) held up
  under direct questioning.

**Where it needed direct correction, or a question that hadn't been asked yet:**

- **The biggest one.** The original security review — a full manual pass over the whole
  codebase — never flagged that any authenticated user could SSO into any SP. It found
  real issues (the auth-code race, the audit-log spoofing, missing rate limiting) but
  missed the most fundamental access-control question entirely. This surfaced only
  because of a direct question — *"if a user shouldn't be allowed to access SP-B, what
  happens?"* — and the honest answer at the time was "it will succeed." That one
  question is responsible for the largest single piece of work in this project (groups,
  the access gate, RBAC decoupling, the demo panels).
- **The shape of the fix.** The first instinct offered for per-SP authorization was
  per-user grants. The redirect to group-based, Okta-style assignment — the actual
  right shape for how this scales — came from outside, not as the initial proposal.
- **Decoupling roles from the IdP entirely** was made explicit by a direct question —
  does the IdP need to hold roles at all — and the reasoning validated it afterward, but
  the architectural instinct came from that question, not proactively.
- **Okta-parity for dynamic registration** was a direct ask, not something offered
  proactively — comparing against Okta's actual onboarding flow (assignments,
  pending-key registration) was reactive analysis once the target had already been
  named.
- **The CSRF gap** was surfaced by a direct question in this same conversation, not
  flagged in the original review or during any of the later build rounds —
  `SameSite=Lax`-only protection had been sitting there, unaddressed, the whole time.
