"""Bootstrap seeding — a one-time provisioning act, not runtime shared state.

Seeds three isolated databases so they start out consistent:
  * ``idp.db``   — seeded users, the first signing key, the admin-token hash, and each
                   SP's registration (including the SP's **public** key).
  * ``sp_a.db`` / ``sp_b.db`` — each SP's own key pair (the **private** half stays here).

Everything is generated (keys, admin token); nothing is hardcoded. Re-running is
idempotent: existing users/keys/sessions are preserved, so a restart keeps you logged in.
"""

from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from fabric.common import crypto
from fabric.common.config import Settings, get_settings
from fabric.common.database import create_all, make_engine, make_sessionmaker
from fabric.idp.deps import ADMIN_TOKEN_META_KEY
from fabric.idp.persistence.models import ClientRow, IdPBase, UserRow
from fabric.idp.persistence.repositories import (
    ClientRepository,
    MetaRepository,
    UserRepository,
)
from fabric.idp.service.keys import KeyService
from fabric.idp.service.users import hash_password
from fabric.sp.persistence.models import SPBase, SPClientKeyRow
from fabric.sp.persistence.repositories import ClientKeyRepository

# (sub, email, password, name, roles) — demo identities only.
_SEED_USERS: tuple[tuple[str, str, str, str, list[str]], ...] = (
    ("user-ada", "ada@example.com", "correct horse battery", "Ada Lovelace", ["user", "engineer"]),
    ("user-grace", "grace@example.com", "hopper-admin-2024", "Grace Hopper", ["user", "admin"]),
    ("user-alan", "alan@example.com", "turing-test-pass", "Alan Turing", ["user"]),
    # Non-admin — used to demonstrate the SP admin panel correctly denying access.
    ("user-marie", "marie@example.com", "curie-radium-1903", "Marie Curie", ["user"]),
    ("user-linus", "linus@example.com", "torvalds-penguin", "Linus Torvalds", ["user"]),
)


async def _seed_admin(session: AsyncSession) -> str | None:
    meta = MetaRepository(session)
    if await meta.get(ADMIN_TOKEN_META_KEY) is not None:
        return None
    token = crypto.new_opaque("adm_")
    await meta.set(ADMIN_TOKEN_META_KEY, hash_password(token))
    return token


async def _seed_users(session: AsyncSession) -> list[str]:
    users = UserRepository(session)
    if await users.count() > 0:
        return []
    created: list[str] = []
    for sub, email, password, name, roles in _SEED_USERS:
        await users.add(
            UserRow(
                sub=sub,
                email=email,
                name=name,
                password_hash=hash_password(password),
                roles=roles,
            )
        )
        created.append(f"{email} / {password}")
    return created


async def _seed_sp_pair(
    idp_session: AsyncSession, sp_session: AsyncSession, settings: Settings, client_id: str
) -> None:
    """Provision a matched key pair: public half to the IdP client, private half to the SP.

    The SP's existing key is preserved across runs; only the IdP-side client *metadata*
    (redirect/back-channel URIs, display name) is always refreshed from config, so a
    port or URL change takes effect without wiping the databases.
    """
    cfg = settings.sp_client(client_id)
    clients = ClientRepository(idp_session)
    sp_keys = ClientKeyRepository(sp_session)

    existing_key = await sp_keys.get(client_id)
    if existing_key is None:
        kid = crypto.new_kid()
        key = crypto.generate_signing_key(kid)
        public = crypto.public_jwk(key)
        await sp_keys.upsert(
            SPClientKeyRow(
                client_id=client_id, kid=kid, public_jwk=public, private_jwk=crypto.private_jwk(key)
            )
        )
    else:
        public = existing_key.public_jwk

    await clients.upsert(
        ClientRow(
            client_id=client_id,
            display_name=cfg.display_name,
            redirect_uri=cfg.redirect_uri,
            post_logout_redirect_uri=cfg.post_logout_redirect_uri,
            backchannel_logout_uri=cfg.backchannel_logout_uri,
            public_jwk=public,
        )
    )


async def seed_all() -> None:
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    idp_engine = make_engine(settings.idp_db_path)
    await create_all(idp_engine, IdPBase)
    idp_maker = make_sessionmaker(idp_engine)

    sp_engines = {cid: make_engine(settings.sp_db_path(cid)) for cid in settings.sp_clients()}
    for engine in sp_engines.values():
        await create_all(engine, SPBase)

    admin_token: str | None = None
    seeded_users: list[str] = []
    try:
        async with idp_maker() as idp_session:
            active_kid = await KeyService(idp_session).ensure_active_key()
            admin_token = await _seed_admin(idp_session)
            seeded_users = await _seed_users(idp_session)
            for client_id in settings.sp_clients():
                sp_maker = make_sessionmaker(sp_engines[client_id])
                async with sp_maker() as sp_session:
                    await _seed_sp_pair(idp_session, sp_session, settings, client_id)
                    await sp_session.commit()
            await idp_session.commit()
    finally:
        await idp_engine.dispose()
        for engine in sp_engines.values():
            await engine.dispose()

    _report(settings, active_kid=active_kid, admin_token=admin_token, users=seeded_users)


def _report(
    settings: Settings, *, active_kid: str, admin_token: str | None, users: list[str]
) -> None:
    line = "=" * 66
    print(line)
    print("Identity Fabric — bootstrap complete")
    print(line)
    print(f"IdP issuer         : {settings.idp_issuer}")
    print(f"Active signing kid : {active_kid}")
    for cid, cfg in settings.sp_clients().items():
        print(f"SP {cid:<6}        : {cfg.base_url}  ({cfg.display_name})")
    if users:
        print("Seeded users (email / password):")
        for entry in users:
            print(f"  - {entry}")
    else:
        print("Users             : already present (not reseeded)")
    if admin_token is not None:
        print("Admin token (SHOWN ONCE — use header 'X-Admin-Token'):")
        print(f"  {admin_token}")
    else:
        print("Admin token       : already provisioned (hash on file; not reshown)")
    print(line, flush=True)


def main() -> None:
    asyncio.run(seed_all())


if __name__ == "__main__":
    main()
