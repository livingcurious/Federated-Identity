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

| Email | Password | Roles |
|---|---|---|
| `ada@example.com` | `correct horse battery` | user, engineer |
| `grace@example.com` | `hopper-admin-2024` | user, admin |
| `alan@example.com` | `turing-test-pass` | user |
| `marie@example.com` | `curie-radium-1903` | user |
| `linus@example.com` | `torvalds-penguin` | user |

### SP admin panel (role check demo)

Each SP has an `/admin` page (session list + a "revoke all sessions at this SP" action).
The link to it only renders for the `admin` role, but that's cosmetic — `/admin` and
`POST /admin/revoke-all` independently re-check the role on every request, so reaching
either URL directly doesn't bypass anything. Sign in as `grace@example.com` (has `admin`)
to see it; sign in as `marie@example.com` or `linus@example.com` (no `admin`) and the same
URLs return `403 Forbidden` — both outcomes are logged (`sp.admin.access_denied`,
`sp.admin.sessions_revoked`).

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
  `key.revoked`, `session.revoked`, `client.key.revoked`, `sp.admin.sessions_revoked`.

Routine events (`auth.login.succeeded/failed`, `token.issued/denied`, `sp.login.*`,
`sp.backchannel.*`, `key.rotated/retired`, `client.key.registered`,
`sp.admin.access_denied` — a non-admin hitting `/admin`) log at info/notice/warning. Logs
and alerts fire immediately, independent of the request's DB transaction.

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

---

## Project layout

```
src/fabric/
  common/         config · clock · crypto (Ed25519/JWT/JWKS) · domain DTOs · db engine · oauth constants
                  audit (JSON logs + audit trail + alert sinks)
  seed.py         provisions all DBs: users · SP registry (+public keys) · first signing key · admin token
  idp/
    api/          oidc (discovery/jwks — public) · token (/token — internal) · auth_ui (home/login/logout)
                  admin (+ /admin/audit, /admin/clients/*/revoke-key|register-key — internal)
    main.py       two ASGI apps: `app` (public) and `internal_app` (token + admin)
    service/      keys · sessions · clients · users · flows · logout
    persistence/  ORM models (+ audit_events) + async repositories        →  idp.db
  sp/
    api/          routes (home/login/callback/profile/logout/backchannel-logout,
                  admin — role-gated: GET /admin, POST /admin/revoke-all)
    service/      idp_client (discovery + JWKS cache) · login · sessions
    persistence/  ORM models (+ audit_events) + async repositories        →  sp_a.db · sp_b.db
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
