# Flow 1 — Deploy / Startup

Two independent run modes exist (`DESIGN.md` §10). Both are covered below, step by step,
exactly as verified live on 2026-08-29.

## 1A. Local processes (`start.sh` / `run.py`)

**Preconditions:** Python 3.11+, no other process already bound to 9400/9401/9402/9410.

1. `./start.sh` runs:
   1. Creates `.venv` if missing (`python3 -m venv .venv`).
   2. Activates it, `pip install --quiet -e .` (installs the `fabric` package in editable
      mode from `src/`, plus its dependencies: fastapi, uvicorn, sqlalchemy, aiosqlite,
      joserfc, argon2-cffi, httpx, jinja2, pydantic(-settings), python-multipart).
   3. `exec python run.py`.
2. `run.py::main()`:
   1. `get_settings()` loads `Settings` (pydantic-settings) — reads `FABRIC_*` env vars /
      `.env`, otherwise the built-in defaults (`idp_host=127.0.0.1`, `idp_port=9400`,
      `idp_internal_port=9410`, `sp_a_port=9401`, `sp_b_port=9402`, ...).
   2. `asyncio.run(seed_all())` — see step 3 below. This runs **synchronously**, in the
      parent process, before any server starts.
   3. Spawns **four** `subprocess.Popen` uvicorn processes, each with
      `--forwarded-allow-ips ""` (disables uvicorn's own default trust of
      `X-Forwarded-For` from `127.0.0.1` — see Flow 1's "Findings" below and
      `common/audit.py`):
      - `fabric.idp.main:app` on `idp_port` (9400) — the **public** IdP surface.
      - `fabric.idp.main:internal_app` on `idp_internal_port` (9410) — **internal**
        (`/token`, `/admin/*`).
      - `fabric.sp.main:app` on `sp_a_port` (9401), env `FABRIC_SP_ID=sp-a`.
      - `fabric.sp.main:app` on `sp_b_port` (9402), env `FABRIC_SP_ID=sp-b`.
   4. Prints the four endpoint URLs, then polls `proc.poll()` on each process every 1s
      until Ctrl+C, at which point it sends `SIGINT` to all four and waits (5s timeout,
      then `SIGKILL`) for clean shutdown.
3. `fabric.seed.seed_all()` (runs once, in step 2.2 above):
   1. `settings.data_dir.mkdir(parents=True, exist_ok=True)` — creates `./data/`.
   2. Opens (creating if absent) `idp.db`, `sp_a.db`, `sp_b.db` via
      `common.database.make_engine` + `create_all(engine, <Base>)`. **`create_all` only
      creates tables that don't exist yet — it never alters an existing table's
      columns.** (See Finding 1 below — this bit a real test run today.)
   3. `KeyService(idp_session).ensure_active_key()` — if no `SigningKeyRow` has
      `status="active"`, generates one Ed25519 keypair (`crypto.generate_signing_key`),
      stores both halves (public + private JWK) in `idp.db`.
   4. `_seed_admin()` — if `meta["admin_token_hash"]` is unset, generates a random opaque
      token (`crypto.new_opaque("adm_")`, 256 bits), stores **only its Argon2 hash**,
      returns the plaintext once (never persisted in plaintext anywhere).
   5. `_seed_users()` — if the `users` table is empty, inserts the 6 seeded identities
      (`ada`, `grace`, `alan`, `marie`, `linus`, `diana`), each with an Argon2id
      `password_hash` and an IdP-level **group** (`engineering`, `finance-dept`, or
      `hr-dept` — see `DESIGN.md` §5.8). No roles are seeded at the IdP at all anymore —
      `UserRow` has no `roles` column; roles are entirely SP-local (next step).
   6. `_seed_sp_pair()` for each of `sp-a`, `sp-b`: if that SP has no `SPClientKeyRow` in
      its **own** DB yet, generates an Ed25519 keypair there (private half stays in that
      SP's DB, never touches `idp.db`); either way, **upserts** the `ClientRow` in
      `idp.db` with the SP's current public key + config-derived metadata
      (`redirect_uri`, `post_logout_redirect_uri`, `backchannel_logout_uri`,
      `display_name`) — this metadata refresh happens on every run, so a port/URL change
      in config takes effect without wiping data. `key_revoked` and `authorized_groups`
      are **not** touched on upsert (only set once, at first creation) — a previously
      revoked SP key, or a group grant/revoke an admin made, both survive a reseed.
   6b. `_seed_local_roles()`, right after, per SP: if that SP's `user_roles` table is
      still empty, writes its seeded local role assignments (e.g. `grace → admin` at
      SP-A but `grace → user` at SP-B — see `DESIGN.md` §5.8 on role decoupling).
      Idempotent by checking for *any* existing row, so it never clobbers an HR-panel
      edit made after the first boot.
   7. Prints the bootstrap report (issuer, active kid, SP URLs, seeded users, the
      one-time admin token) to stdout.
4. **Ready.** IdP public UI at `http://127.0.0.1:9400`, IdP internal (`/token`,
   `/admin/*`) at `http://127.0.0.1:9410`, SP-A at `:9401`, SP-B at `:9402`.

**Verified live (2026-08-29):** fresh `rm -f data/*.db` → `seed_all()` → 4 uvicorn
processes → `.well-known/openid-configuration` returns `200` and its `token_endpoint`
correctly points at `http://127.0.0.1:9410/token` → `scripts/demo.py` passes both
assertions (SSO, cross-SP audience rejection).

## 1B. Containers (`container-start.sh` → `compose.yaml`)

1. `./container-start.sh`:
   1. `command -v docker && docker info` — if both succeed, `ENGINE=docker`. Else if
      `podman` exists, `ENGINE=podman`. Else, installs Podman (Homebrew on macOS;
      `apt-get`/`dnf`/`pacman`/`zypper` on Linux) and sets `ENGINE=podman`.
   2. If `ENGINE=podman` on macOS: ensures a `podman-machine-default` VM exists
      (`podman machine init` if not) and is running (`podman machine start` if not).
      Skipped entirely on Linux (Podman is native there) and for the Docker path
      (Docker Desktop manages its own VM).
   3. Checks `/etc/hosts` for `idp`, `sp-a`, `sp-b` entries resolving to loopback; exits
      with instructions if missing (this script does **not** edit `/etc/hosts` itself —
      that needs `sudo`, so it's left to the operator).
   4. Resolves the actual compose command (`docker compose`, falling back to
      `docker-compose`, or `podman compose`) and runs `<that> up --build "$@"`.
2. `compose.yaml` (whichever engine ran it):
   1. Builds `identity-fabric:latest` from `Containerfile` — `python:3.13-slim` base,
      `COPY pyproject.toml`, `COPY src ./src`, `pip install .` (**not** editable this
      time — a real install into the image). Default `CMD` is the provisioner
      (`python -m fabric.seed`); each service overrides `command:`.
   2. **`provisioner`** starts first, mounting **all three** named volumes
      (`idp-data:/data/idp`, `spa-data:/data/spa`, `spb-data:/data/spb`) — the only
      component that ever does. Runs `fabric.seed` (identical logic to §1A step 3, just
      pointed at `/data/*` via `FABRIC_IDP_DB_FILE`/`FABRIC_SP_A_DB_FILE`/
      `FABRIC_SP_B_DB_FILE`), prints the admin token to its own log, then **exits**.
      `restart: "no"` — it never runs again on `up` unless the volumes are wiped.
   3. `idp`, `idp-internal`, `sp-a`, `sp-b` each have
      `depends_on: provisioner: condition: service_completed_successfully` — they don't
      start until the provisioner has exited with code 0.
   4. `idp` (public) and `sp-a`/`sp-b` publish their ports to the host
      (`9400:9400`, `9401:9401`, `9402:9402`). **`idp-internal` has no `ports:` entry at
      all** — reachable only from containers on the `spa-idp`/`spb-idp` networks (which
      `sp-a`, `sp-b`, and `idp`/`idp-internal` itself are all attached to), never from the
      host or beyond. Every uvicorn command also carries `--forwarded-allow-ips ""`, same
      reasoning as §1A.
   5. Network topology: `idp` and `idp-internal` are on **both** `spa-idp` and
      `spb-idp`. `sp-a` is only on `spa-idp`; `sp-b` is only on `spb-idp`. So `sp-a` can
      reach `idp`/`idp-internal` but has **no route at all** to `sp-b` (not even DNS
      resolves it) — confirmed live below.
3. **Ready.**

**Verified live (2026-08-29), against a real `docker compose up --build -d`:**
- `docker compose ps` → all 4 long-running services `Up`; provisioner `Exited (0)`.
- Filesystem isolation: `docker exec identity-fabric-sp-a-1 ls -R /data` → only
  `/data/spa/sp_a.db`.
- Network isolation: `sp-a` container → `httpx.get('http://idp:9400/...')` → `200`;
  → `httpx.get('http://sp-b:9402/')` → `httpx.ConnectError: Name or service not known`
  (no DNS entry at all for `sp-b` inside `sp-a`'s network namespace).
- Internal-port isolation: `curl http://127.0.0.1:9410/admin/keys` from the **host**
  fails to connect (nothing published there); the identical call from inside `sp-a`'s
  container to `http://idp-internal:9410/admin/keys` (with the admin token) → `200`.

## Findings from this verification pass

**Finding 1 — no migration path; a stale volume breaks the provisioner.** `create_all`
(`common/database.py`) only issues `CREATE TABLE IF NOT EXISTS` — it never adds a column
to a table that already exists. Today's first `docker compose up --build` attempt (against
a volume left over from before the SP-key-revoke feature was added) failed the provisioner
with:
```
sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) no such column: clients.key_revoked
```
Fixed for this run by `docker compose down -v` (drops the named volumes) before retrying —
acceptable for a demo with disposable data, but this is a real operational gap: any future
schema change requires wiping data (local: delete files in `data/`; containers:
`down -v`) rather than migrating in place. There is no Alembic (or equivalent) in this
project. Worth knowing before relying on this for anything with data worth keeping across
a schema change.

> **Resolved (2026-08-29):** `common/database.py::create_all` now also runs
> `_add_missing_columns`, a small best-effort additive migration: after creating any
> missing tables, it diffs each table's declared ORM columns against
> `PRAGMA table_info` and `ALTER TABLE ... ADD COLUMN`s anything missing (always
> nullable at the DB level, so it always succeeds on a populated table — existing rows
> get `NULL`, which is falsy and correct for a boolean like `key_revoked`). Verified by
> reproducing the exact original failure — a hand-built `clients` table without
> `key_revoked`, one existing row — and confirming `create_all` self-heals it with no
> data loss and no manual intervention. This is explicitly *not* a general migration
> system: it doesn't rename, drop, retype a column, or backfill anything other than
> `NULL`. A future column that needs real backfilling still needs a real migration.

**Finding 2 — `scripts/` isn't in the container image.** `Containerfile` only
`COPY src ./src` (plus `pyproject.toml`). `scripts/demo.py` and
`scripts/rotate_sp_key.py` are not present inside any container. Two concrete
consequences, both confirmed live:
- `python scripts/demo.py`, run from the **host** against the container deployment,
  fails with `httpx.ConnectError` on the cross-SP-integrity check — not because anything
  is broken, but because that check needs to sign a client assertion using SP-A's real
  private key, which the script tries to read from the local `./data/sp_a.db` file. Under
  containers, SP-A's real key lives inside the `spa-data` volume, not on the host
  filesystem, by design — this is the isolation working, not a bug, but it means
  `demo.py` cannot verify a container deployment as written.
- The SP-key-recovery playbook in `README.md`
  (`python scripts/rotate_sp_key.py sp-a > new_key.json`) does not work as documented
  against containers either — the script isn't in the image, and even if invoked via
  `docker compose exec sp-a python scripts/rotate_sp_key.py sp-a` it would fail with "no
  such file". Flow 5's document below shows the equivalent inline workaround that *was*
  used to verify recovery live; making the documented command actually work would need
  `COPY scripts ./scripts` added to `Containerfile`.

> **Resolved (2026-08-29):** `Containerfile` now also `COPY scripts ./scripts` (alongside
> `src`). Verified by rebuilding the image and running the *actual documented* recovery
> command unmodified — `docker compose exec sp-a python scripts/rotate_sp_key.py sp-a` —
> which now works end-to-end (see Flow 5's updated write-up). As a bonus check,
> `docker compose exec sp-a python scripts/demo.py` was also tried: its SSO check (part
> 1) passes, but its cross-SP-integrity check (part 2) still can't complete from inside
> *either* SP's own container — `sp-a` has no network route to `sp-b` at all, by design
> (§10.2), so no single container in this topology can reach both SPs and hold SP-A's
> key at the same time. That's the isolation working correctly, not a remaining gap —
> `demo.py` is a local-mode (§10.1) tool and was never meant to run inside the segmented
> topology.

Neither finding blocked the deploy flow itself — both were routed around live to
complete this verification pass — but both were real, and both are now fixed (see the
resolution notes above and in Flow 5).
