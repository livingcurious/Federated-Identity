# Flow 1 — Deploy / Startup

This is a container-only project (`DESIGN.md` §10) — there is no local-process run mode.
Covered below, step by step, as verified live on 2026-08-29.

## Container startup (`container-start.sh` → `compose.yaml`)

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
      component that ever does. Runs `fabric.seed.seed_all()`, pointed at `/data/*` via
      `FABRIC_IDP_DB_FILE`/`FABRIC_SP_A_DB_FILE`/`FABRIC_SP_B_DB_FILE`:
      1. `settings.data_dir.mkdir(...)` and opens (creating if absent) `idp.db`,
         `sp_a.db`, `sp_b.db` via `create_all(engine, <Base>)`. **`create_all` only
         creates tables that don't exist yet — it never alters an existing table's
         columns** (see Finding 1 below).
      2. `KeyService.ensure_active_key()` — if no `SigningKeyRow` has `status="active"`,
         generates one Ed25519 keypair, stores both halves in `idp.db`.
      3. `_seed_admin()` — if no admin-token hash exists yet, generates a random opaque
         token, stores **only its Argon2 hash**, prints the plaintext once.
      4. `_seed_users()` — if the `users` table is empty, inserts the 6 seeded
         identities (`ada`, `grace`, `alan`, `marie`, `linus`, `diana`), each with an
         Argon2id `password_hash` and an IdP-level **group** (`engineering`,
         `finance-dept`, or `hr-dept` — see `DESIGN.md` §5.8). No roles are seeded at
         the IdP — `UserRow` has no `roles` column; roles are entirely SP-local.
      5. `_seed_sp_pair()` per SP: generates an Ed25519 keypair in that SP's **own** DB
         if it doesn't have one yet (private half never touches `idp.db`); either way,
         **upserts** the `ClientRow` in `idp.db` with the current public key and
         config-derived metadata — refreshed every run, so a port/URL change takes
         effect without wiping data. `key_revoked` and `authorized_groups` are **not**
         touched on upsert (set once, at first creation), so a revoked key or a group
         grant/revoke survives a reseed.
      6. `_seed_local_roles()` per SP, right after: if that SP's `user_roles` table is
         still empty, writes its seeded local role assignments (e.g. `grace → admin` at
         SP-A but `grace → user` at SP-B — role decoupling, `DESIGN.md` §5.8).
         Idempotent by checking for *any* existing row, so it never clobbers an
         HR-panel edit made after the first boot.
      7. Prints the bootstrap report (issuer, active kid, SP URLs, seeded users, the
         one-time admin token) to its own log, then **exits**. `restart: "no"` — it
         never runs again on `up` unless the volumes are wiped.
   3. `idp`, `idp-internal`, `sp-a`, `sp-b` each have
      `depends_on: provisioner: condition: service_completed_successfully` — they don't
      start until the provisioner has exited with code 0.
   4. `idp` (public) and `sp-a`/`sp-b` publish their ports to the host
      (`9400:9400`, `9401:9401`, `9402:9402`). **`idp-internal` has no `ports:` entry at
      all** — reachable only from containers on the `spa-idp`/`spb-idp` networks (which
      `sp-a`, `sp-b`, and `idp`/`idp-internal` itself are all attached to), never from the
      host or beyond. Every uvicorn command also carries `--forwarded-allow-ips ""`
      (disables uvicorn's own default trust of `X-Forwarded-For` from `127.0.0.1` — see
      "Findings" below and `common/audit.py`).
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
> 1) passed, but its cross-SP-integrity check (part 2) couldn't complete from inside
> *either* SP's own container — `sp-a` has no network route to `sp-b` at all, by design
> (§10.1), so no single container in this topology can reach both SPs and hold SP-A's
> key at the same time. That's the isolation working correctly, not a bug in the script.
>
> **Update:** `run.py` and `scripts/demo.py` have since been removed from the project
> entirely — this is now a container-only deployment, with no local-process run mode to
> document or verify against.

Neither finding blocked the deploy flow itself — both were routed around live to
complete this verification pass — but both were real, and both are now fixed (see the
resolution notes above and in Flow 5).
