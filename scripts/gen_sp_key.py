#!/usr/bin/env python3
"""Generate a standalone Ed25519 keypair for a new SP — no database, no settings needed.

Prints a JSON object with two fields to stdout:
  {"public_jwk": {...}, "private_jwk": {...}}

The operator hands ONLY the public_jwk to the IdP (POST /admin/clients/<id>/register-key).
The private_jwk must be stored securely inside the new SP — it never leaves the SP.

Usage:
    python scripts/gen_sp_key.py <client_id>
    python scripts/gen_sp_key.py sp-c > sp_c_keypair.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fabric.common import crypto


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <client_id>")

    client_id = sys.argv[1]
    kid = crypto.new_kid()
    key = crypto.generate_signing_key(kid)
    public = crypto.public_jwk(key)
    private = crypto.private_jwk(key)

    print(f"Generated Ed25519 keypair for {client_id!r} (kid={kid})", file=sys.stderr)
    print("KEEP private_jwk secret — store it inside the SP only.", file=sys.stderr)
    print("Submit ONLY public_jwk to: POST /admin/clients/<id>/register-key", file=sys.stderr)
    print(json.dumps({"public_jwk": public, "private_jwk": private}, indent=2))


if __name__ == "__main__":
    main()
