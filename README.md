# Identity Fabric

A small, security-serious **Single Sign-On** trust fabric you can run on an M1 in one
command: one **Identity Provider (IdP)** that two **Service Providers (SP-A, SP-B)**
trust to identify a user. Sign in once at the IdP; each SP gets its own authenticated
session without ever seeing your password.

Protocol: **OpenID Connect Authorization Code + PKCE**, with **private_key_jwt** client
authentication and an **Ed25519 JWKS** signing layer. See [`DESIGN.md`](./DESIGN.md) for
the full architecture and threat reasoning.

> Not a production identity system: users and SPs are **seeded**, and it runs on
> `localhost` over HTTP. It is a faithful, working model of the security mechanics.

---

## Security features (all implemented and tested)

| Feature | Where it lives | How to see it |
|---|---|---|
| **SSO** | IdP session + per-SP tokens | Sign in at SP-A, open SP-B — no second login |
| **Signing-key rotation** | `idp/service/keys.py`, JWKS overlap | `POST /admin/keys/rotate`; SPs refetch JWKS on unknown `kid` |
| **IdP ↔ SP mutual auth** | `private_key_jwt` + JWKS/`iss` checks | Token exchange fails without a valid signed client assertion |
| **Cross-SP integrity** | `aud`/`azp` pinning | A token for SP-A is rejected at SP-B (`scripts/demo.py`) |
| **Compromise containment** | key revoke + session revoke + back-channel logout | `POST /admin/keys/{kid}/revoke`, `POST /admin/sessions/{sid}/revoke` |
| **Session lifecycle & persistence** | idle+absolute timeouts, SQLite-backed | Sessions survive restart; logout propagates to all SPs |
| **Audit logging & alerts** | `common/audit.py`, `audit_events` table, `/admin/audit` | Structured JSON logs + persistent trail; high-signal events (replay, mutual-auth failure, revocations) raise alerts |

---

## Requirements

- **Python 3.11+** (developed and tested on 3.13, Apple Silicon).
- No Docker, Redis, or Postgres. Just three `uvicorn` processes and three SQLite files.

---

## Quick start

One command does everything — creates the venv (first run only), installs, seeds, and
launches all three services:

```bash
cd identity-fabric
./start.sh
```

(Use a specific interpreter with `PYTHON=python3.13 ./start.sh`.)

Prefer to manage the environment yourself? Set it up once and use the pure launcher:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
python run.py
```

Either way, the launcher seeds the databases (printing the seeded users and a one-time **admin token**),
then launches all four processes:

| Service | URL | Who talks to it |
|---|---|---|
| IdP (public) | http://127.0.0.1:9400 | Browsers — login UI, `/authorize`, JWKS |
| IdP (internal) | http://127.0.0.1:9410 | SPs (`/token`) and operators (`/admin/*`) only |
| SP-A · Atlas Console | http://127.0.0.1:9401 | Browsers |
| SP-B · Borealis Portal | http://127.0.0.1:9402 | Browsers |

The IdP's `/token` and `/admin/*` are split onto their own listener (see [§5.7 in
DESIGN.md](./DESIGN.md)) so they can be kept off a publicly published port in a real
deployment — locally there's no network boundary either way, but under Podman (below)
the internal listener has no `ports:` entry at all.

**Try SSO in a browser:**
1. Open **SP-A** → *Sign in with Identity Fabric* → you land on the IdP login page.
2. Sign in as `ada@example.com` / `correct horse battery`.
3. You are returned to SP-A, signed in.
4. Open **SP-B** → you are signed in **immediately**, no password prompt.
5. *Sign out everywhere* from either SP ends the session on both.

Stop everything with **Ctrl+C**.

### Seeded users

| Email | Password | IdP group |
|---|---|---|
| `ada@example.com` | `correct horse battery` | engineering |
| `grace@example.com` | `hopper-admin-2024` | engineering |
| `alan@example.com` | `turing-test-pass` | engineering |
| `marie@example.com` | `curie-radium-1903` | finance-dept |
| `linus@example.com` | `torvalds-penguin` | engineering |
| `diana@example.com` | `diana-hr-secure-1` | hr-dept |

A user's **group** is the only thing the IdP checks to decide whether they may SSO into
an SP *at all* (see the next section) — it carries no permissions of its own. What a
signed-in user can actually *do* at a given SP is decided entirely by that SP, locally
(see "SP-local roles" below).

### Group-based SP access (who can even sign into which app)

Each SP declares which IdP groups it trusts, via `ClientRow.authorized_groups`: Atlas
Console (`sp-a`) welcomes `engineering`, `finance-dept`, and `hr-dept`; Borealis Portal
(`sp-b`) is `engineering`-only. The check lives at the IdP, in
`idp/api/auth_ui.py::_resume_authorization` — the single function both a fresh login
and a silent SSO-resume both funnel through — so it's enforced *before* any
authorization code is ever minted, not after the fact. Sign in as `marie@example.com`
(finance-dept) at SP-A — works fine — then try SP-B: `403 Forbidden`, no code, no
token, nothing issued, logged as `client.access.denied`. She still keeps her IdP-wide
SSO cookie (the gate is a per-SP authorization decision, not an authentication
failure) — she just can't use *that* app.

Admin can grant/revoke a group's access to any client:
```bash
curl -s -X POST -H "X-Admin-Token: $ADMIN" $IDP_INTERNAL/admin/clients/sp-b/groups/finance-dept/authorize
curl -s -X POST -H "X-Admin-Token: $ADMIN" $IDP_INTERNAL/admin/clients/sp-b/groups/finance-dept/revoke
```

### SP-local roles (what a signed-in user can do — Admin, Finance, HR)

Roles are **not** an IdP concept at all — the `id_token` carries no `roles` claim. Each
SP keeps its own role table (`SPUserRoleRow`), seeded independently, so the *same*
person can hold different roles at different apps: `grace` is `admin` at SP-A but a
plain `user` at SP-B. A first-ever login at any SP with no seeded row defaults to
`user`.

Three role-gated panels exist at each SP, all following the same pattern (link hidden
from other roles in the UI — cosmetic — with the actual role check re-run independently
on every request, allow and deny both audited):

| Role | Panel | Action |
|---|---|---|
| `admin` | `/admin` | session list, "revoke all sessions at this SP" |
| `finance` | `/finance` | budget status, "approve budget" |
| `hr` | `/hr` | this SP's local role roster, "assign a role to a subject" |

Try it at SP-A: `grace` sees Admin; `marie` sees Finance (and can approve the quarter's
budget); `diana` sees HR — and can reassign roles for anyone else at that SP entirely
locally, with zero IdP involvement (`POST /hr/assign-role`). `ada`/`alan`/`linus` see
none of the three (plain `user`) until HR grants them one.

### Dynamic client registration (Okta-style app onboarding)

Beyond the two seeded SPs, a new client can be registered at runtime, mirroring how a
real IdP onboards a new app — create it, get pending credentials, submit the key:
```bash
curl -s -X POST -H "X-Admin-Token: $ADMIN" -H "Content-Type: application/json" \
  -d '{"client_id":"sp-c","display_name":"New App","redirect_uri":"https://new-app/callback","post_logout_redirect_uri":"https://new-app","backchannel_logout_uri":"https://new-app/backchannel-logout"}' \
  $IDP_INTERNAL/admin/clients
# -> 201 {"client_id": "sp-c", "status": "pending_key_registration"}
```
`/token` rejects it (`"client has not completed key registration"`) until its public key
is registered — same `register-key` endpoint used for the SP-key-recovery flow below —
and it denies every group until explicitly authorized, same as above.

---

## Run under container isolation (Docker or Podman)

The local run is convenient but has **logical** DB separation only — all three processes
share a user and a `data/` directory, so a compromised SP could read the others' files.
The container topology (`compose.yaml`) turns that into **enforced** isolation and is
closer to how you'd actually deploy this. Nothing in `compose.yaml` is Podman-specific,
so it runs unchanged under either engine.

**One command, either engine:**

```bash
./container-start.sh          # build + up (foreground logs)
./container-start.sh -d       # build + up detached
```

It uses Docker if it's installed and its daemon is reachable; otherwise it installs
Podman (via Homebrew on macOS, or `apt`/`dnf`/`pacman`/`zypper` on Linux — asking for
`sudo` where a package manager needs it) and starts a Podman machine if you're on macOS,
then runs `<engine> compose up --build`. The `/etc/hosts` check below still applies either
way — the script does it for you and tells you exactly what to add if it's missing.

**Isolation model (trusted provisioner):**
- A one-shot **provisioner** seeds all three volumes at bootstrap, then exits — it is the
  only component that ever touches more than one volume, and only at deploy time.
- Each server mounts **only its own volume**, so a compromised SP cannot open the IdP's
  (or the sibling SP's) database — it isn't on any path it can reach.
- **Network segmentation:** SP-A and SP-B share no network (no route between them); each
  SP can reach the IdP, and the IdP can reach each SP for back-channel logout.

**Prerequisite** — the browser and the tokens must agree on hostnames, so add one line to
`/etc/hosts` (once):

```bash
echo '127.0.0.1  idp  sp-a  sp-b' | sudo tee -a /etc/hosts
```

**Start it** — `./container-start.sh` (above) handles engine choice + `/etc/hosts` for
you. If you'd rather drive it directly:

```bash
docker compose up --build     # Docker
podman compose up --build     # Podman 5+, with a running `podman machine` on macOS
./podman-start.sh             # equivalent to the line above, Podman-only, no engine detection
```

Endpoints become http://idp:9400, http://sp-a:9401, http://sp-b:9402 — plus
`http://idp-internal:9410` (token + admin), which has **no host-published port at all**;
reach it with `<engine> compose exec idp-internal curl ...`. The one-time admin token is
in the provisioner's logs:

```bash
<engine> compose logs provisioner | grep -A1 'Admin token'
```

**See the isolation for yourself** (replace `podman` with `docker` if that's your engine
— the container name prefix is the same either way):

```bash
# SP-A can only see its own database
podman exec identity-fabric-sp-a-1 ls -R /data          # → just /data/spa/sp_a.db

# SP-A can reach the IdP, but has no route to SP-B
podman exec identity-fabric-sp-a-1 \
  python -c "import httpx; print(httpx.get('http://idp:9400/.well-known/jwks.json').status_code)"   # 200
podman exec identity-fabric-sp-a-1 \
  python -c "import httpx; httpx.get('http://sp-b:9402/', timeout=4)"   # ConnectError

# /token and /admin are unreachable from the host — only from inside the compose network
curl http://127.0.0.1:9410/admin/keys        # ConnectError: nothing is listening on the host
podman compose exec idp-internal \
  curl -s -H "X-Admin-Token: $ADMIN" http://idp-internal:9410/admin/keys   # works
```

**Stop** (volumes persist so the next `up` keeps your data):

```bash
<engine> compose down
```

> Trade-off: containers isolate against ordinary app-level compromise (RCE reading the
> filesystem / lateral network movement), not against a kernel/container-escape 0-day —
> that tier needs separate VMs or hosts. Containers run as root *inside* the namespace,
> which under rootless Podman is an unprivileged host user.

## The scripted proof

With the services running, in a second terminal:

```bash
source .venv/bin/activate
python scripts/demo.py
```

It drives the live services and asserts (1) SSO across both SPs from a single login and
(2) that a token minted for SP-A is **rejected** when its audience is checked as SP-B.

---

## Driving the security levers (admin API)

The admin surface is guarded by the bootstrap **admin token** printed during seeding
(sent as the `X-Admin-Token` header). It lives on the **internal** IdP listener, not the
public one — export both first:

```bash
export ADMIN="adm_...paste from the seed output..."
export IDP=http://127.0.0.1:9400            # public: login, authorize, jwks
export IDP_INTERNAL=http://127.0.0.1:9410   # internal: token + admin
```

Under Podman, `$IDP_INTERNAL` has no host-published port; run these through the
container instead — see the Podman section above.

**Signing-key rotation** — mint a new active key; the old one lingers in JWKS so
in-flight tokens still verify:

```bash
curl -s $IDP/.well-known/jwks.json                                    # one kid
curl -s -X POST -H "X-Admin-Token: $ADMIN" $IDP_INTERNAL/admin/keys/rotate
curl -s $IDP/.well-known/jwks.json                                    # two kids (active + retiring)
curl -s -H "X-Admin-Token: $ADMIN" $IDP_INTERNAL/admin/keys
```

**Compromise containment — revoke a key** (drops it from JWKS immediately; every token
it signed fails everywhere). You must rotate first, then revoke the *retiring* key:

```bash
curl -s -X POST -H "X-Admin-Token: $ADMIN" $IDP_INTERNAL/admin/keys/<retiring-kid>/revoke
```

**Compromise containment — revoke a session** (kills the IdP session and fires
back-channel logout to every SP it reached):

```bash
curl -s -H "X-Admin-Token: $ADMIN" $IDP_INTERNAL/admin/sessions
curl -s -X POST -H "X-Admin-Token: $ADMIN" $IDP_INTERNAL/admin/sessions/<sid>/revoke
```

**Compromise containment — an SP's own key leaked** (RCE in SP-A, a leaked secret, etc.).
Unlike the IdP's own signing keys, an SP's `private_key_jwt` key has no expiry and, on
its own, no revoke lever — until now. Contain first, recover second:

```bash
# 1. Contain — instantly stops the leaked key from authenticating as sp-a, from anywhere
#    on the network, with no access to SP-A's own database required:
curl -s -X POST -H "X-Admin-Token: $ADMIN" $IDP_INTERNAL/admin/clients/sp-a/revoke-key

# 2. Recover — generate a fresh keypair *in SP-A's own database only* (never touches
#    idp.db); prints the new PUBLIC half, nothing private ever leaves the SP:
python scripts/rotate_sp_key.py sp-a > new_key.json
#    Under containers, run it inside SP-A's own container instead (same script, same
#    volume, just reached a different way):
#    docker compose exec sp-a python scripts/rotate_sp_key.py sp-a > new_key.json

# 3. Re-register the new public key with the IdP (also clears the revoked flag):
curl -s -X POST -H "X-Admin-Token: $ADMIN" -H "Content-Type: application/json" \
  -d @new_key.json $IDP_INTERNAL/admin/clients/sp-a/register-key
```

---

## Logging, audit trail & alerts

Every security-relevant event is emitted three ways at once (see `common/audit.py`):

- **Structured JSON logs** on stderr (logger `fabric.audit`), tagged with `service`,
  `event`, `severity`, `request_id`, `source_ip`, `subject`/`client_id`, and `detail`.
- **A persistent trail** in each service's own `audit_events` table — read the IdP's at:
  ```bash
  curl -s -H "X-Admin-Token: $ADMIN" "$IDP_INTERNAL/admin/audit?limit=20"
  ```
- **Alerts** — `ALERT`-severity events print a loud `[ALERT] …` banner on stderr and go
  to any registered sink (`register_alert_sink` accepts a webhook). High-signal events:
  `assertion.replay.detected`, `client.auth.failed` (failed IdP↔SP mutual auth),
  `key.revoked`, `session.revoked`, `client.key.revoked`, `client.group.revoked`,
  `sp.admin.sessions_revoked`.

Routine events (`auth.login.succeeded/failed`, `token.issued/denied`, `sp.login.*`,
`sp.backchannel.*`, `key.rotated/retired`, `client.key.registered`, `client.registered`,
`client.group.authorized`, `sp.finance.budget_approved`, `sp.hr.role_assigned`) log at
info/notice. `client.access.denied` (a user's group doesn't authorize the SP they tried)
and `sp.access.denied` (a signed-in user hit an SP panel — admin/finance/hr — they don't
have the role for) log at warning. Logs and alerts fire immediately, independent of the
request's DB transaction.

The `source_ip` on every event is the direct TCP peer unless the request came from an IP
listed in `FABRIC_TRUSTED_PROXY_IPS`, in which case `X-Forwarded-For` is honored instead —
with no reverse proxy in front (the default here), trusting that header from *any* caller
would let it forge its own logged source IP. This also requires every `uvicorn` process to
be launched with `--forwarded-allow-ips ""` (as `run.py`/`compose.yaml` do): uvicorn has
its *own* proxy-header trust, defaulting to trusting `127.0.0.1`, that rewrites
`request.client` before the app ever sees the "real" peer — without disabling that too,
any local caller could still spoof it regardless of what the app-level check says.

---

## Configuration

All config is environment-driven (prefix `FABRIC_`); copy `.env.example` → `.env` to
override. Key knobs: ports (including the internal IdP listener,
`FABRIC_IDP_INTERNAL_HOST`/`FABRIC_IDP_INTERNAL_PORT`), `FABRIC_TRUSTED_PROXY_IPS`, cookie
`Secure` flag (turn **on** in production), and session/token lifetimes. Signing keys and
the admin token are **generated at bootstrap** and stored in `idp.db` (the admin token
only as an Argon2 hash) — nothing secret is hardcoded or committed.

Re-running the seed is idempotent: it preserves existing users, keys and sessions, so a
restart keeps you logged in. Delete the files in `data/` to start completely fresh.

Schema changes (a new column added to an existing table) are applied automatically on
boot via a small best-effort `ALTER TABLE ... ADD COLUMN` shim
(`common/database.py::_add_missing_columns`) — existing rows get `NULL` for the new
column rather than the DB needing to be wiped. This is not a general migration system: it
only adds columns, and existing rows keep `NULL` rather than a real backfilled value.

---

## Project layout

```
src/fabric/
  common/         config · clock · crypto (Ed25519/JWT/JWKS) · domain DTOs · db engine · oauth constants
                  audit (JSON logs + audit trail + alert sinks)
  seed.py         provisions all DBs: users · SP registry (+public keys) · first signing key · admin token
  idp/
    api/          oidc (discovery/jwks — public) · token (/token — internal) · auth_ui (home/login/logout,
                  group-authorization gate in _resume_authorization)
                  admin (+ /admin/audit, /admin/clients (create/revoke-key/register-key/groups) — internal)
    main.py       two ASGI apps: `app` (public) and `internal_app` (token + admin)
    service/      keys · sessions · clients (incl. dynamic registration + group grants) · users (groups) · flows · logout
    persistence/  ORM models (+ audit_events) + async repositories        →  idp.db
  sp/
    api/          routes (home/login/callback/profile/logout/backchannel-logout,
                  admin/finance/hr — role-gated via the shared `_require_role` helper)
    service/      idp_client (discovery + JWKS cache) · login · sessions (local role lookup)
    persistence/  ORM models (+ audit_events, user_roles, budget) + async repositories  →  sp_a.db · sp_b.db
run.py                    seed + launch IdP (public+internal) and both SPs (local processes)
start.sh                  one command: venv + install + run.py
scripts/demo.py           scripted end-to-end proof
scripts/rotate_sp_key.py  SP-key-compromise recovery: fresh keypair in that SP's own DB only
Containerfile             single image for all roles
compose.yaml              isolated Docker/Podman topology (provisioner + segmented services)
container-start.sh        one script: Docker if available, else install+use Podman, then compose up
podman-start.sh           /etc/hosts check + `podman compose up --build` (Podman-only, no detection)
```

Two run modes: **local processes** (`start.sh` / `run.py`) for development, and
**containers** (`podman compose`) for enforced isolation. Their security difference — and
the trusted-provisioner seeding model — is written up in [`DESIGN.md`](./DESIGN.md) §10.

Layering is strict per service: `api → service → persistence`, everything async and
typed, HTTP status codes via `starlette.status` (no magic numbers).

---

## Tech choices (short version)

FastAPI · Pydantic v2 / pydantic-settings · **joserfc** (JOSE, by the Authlib author —
not the stale `python-jose`) · **Ed25519** signatures · SQLAlchemy 2.0 async + aiosqlite
· **argon2-cffi** password hashing · httpx · Jinja2 · Podman/Docker for isolated runs.
Rationale and trade-offs are in [`DESIGN.md`](./DESIGN.md).
