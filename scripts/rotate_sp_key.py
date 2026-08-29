#!/usr/bin/env python3
"""Generate a fresh keypair for one SP, in place, in that SP's own database only.

Use this as the recovery half of the SP-key-compromise playbook:

    1. Contain immediately (from the IdP host/network, using the admin token):
         curl -s -X POST -H "X-Admin-Token: $ADMIN" \\
           $IDP_INTERNAL/admin/clients/<client_id>/revoke-key
    2. Recover — run this script against the compromised SP's own volume/database:
         python scripts/rotate_sp_key.py sp-a
       It prints the new *public* JWK; nothing private is ever printed or leaves the SP.
    3. Register the new public key with the IdP:
         curl -s -X POST -H "X-Admin-Token: $ADMIN" -H "Content-Type: application/json" \\
           -d '{"public_jwk": <paste the printed JWK>}' \\
           $IDP_INTERNAL/admin/clients/<client_id>/register-key

This only ever touches the target SP's own database — never the IdP's — matching the
per-service volume isolation the containers enforce.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fabric.common import crypto
from fabric.common.config import get_settings
from fabric.common.database import create_all, make_engine, make_sessionmaker
from fabric.sp.persistence.models import SPBase, SPClientKeyRow
from fabric.sp.persistence.repositories import ClientKeyRepository


async def rotate(client_id: str) -> None:
    settings = get_settings()
    if client_id not in settings.sp_clients():
        raise SystemExit(f"unknown SP client_id: {client_id!r}")

    engine = make_engine(settings.sp_db_path(client_id))
    try:
        await create_all(engine, SPBase)
        async with make_sessionmaker(engine)() as session:
            kid = crypto.new_kid()
            key = crypto.generate_signing_key(kid)
            public = crypto.public_jwk(key)
            await ClientKeyRepository(session).upsert(
                SPClientKeyRow(
                    client_id=client_id,
                    kid=kid,
                    public_jwk=public,
                    private_jwk=crypto.private_jwk(key),
                )
            )
            await session.commit()
    finally:
        await engine.dispose()

    print(f"New key generated for {client_id!r} (kid={kid}).", file=sys.stderr)
    print("Register this PUBLIC key with the IdP (POST .../admin/clients/"
          f"{client_id}/register-key):", file=sys.stderr)
    print(json.dumps({"public_jwk": public}))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <client_id>")
    asyncio.run(rotate(sys.argv[1]))


if __name__ == "__main__":
    main()
