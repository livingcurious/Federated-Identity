#!/usr/bin/env python3
"""Launch the whole fabric: seed the databases, then run the IdP and both SPs.

    python run.py

Each service is an independent uvicorn process. Ctrl+C stops them all. Works whether or
not the package is pip-installed — ``src`` is added to PYTHONPATH for the children.
"""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from fabric.common.config import get_settings  # noqa: E402
from fabric.seed import seed_all  # noqa: E402


def _child_env(extra: dict[str, str]) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(SRC), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    env.update(extra)
    return env


def _uvicorn(app: str, port: int, host: str, extra_env: dict[str, str]) -> subprocess.Popen[bytes]:
    # uvicorn trusts 127.0.0.1 to set X-Forwarded-For by default (`proxy_headers=True`,
    # `forwarded_allow_ips="127.0.0.1"`), which would let *any* local caller spoof
    # `request.client.host` before our own trusted-proxy check in `deps.py::client_ip`
    # ever sees it. Trust nobody at this layer; `FABRIC_TRUSTED_PROXY_IPS` is the only
    # place that header is ever honored.
    cmd = [
        sys.executable, "-m", "uvicorn", app,
        "--host", host, "--port", str(port), "--forwarded-allow-ips", "",
    ]
    return subprocess.Popen(cmd, cwd=str(ROOT), env=_child_env(extra_env))


def main() -> None:
    settings = get_settings()
    asyncio.run(seed_all())

    host = settings.idp_host
    internal_host = settings.idp_internal_host or settings.idp_host
    procs: list[subprocess.Popen[bytes]] = [
        _uvicorn("fabric.idp.main:app", settings.idp_port, host, {}),
        _uvicorn("fabric.idp.main:internal_app", settings.idp_internal_port, internal_host, {}),
        _uvicorn("fabric.sp.main:app", settings.sp_a_port, host, {"FABRIC_SP_ID": "sp-a"}),
        _uvicorn("fabric.sp.main:app", settings.sp_b_port, host, {"FABRIC_SP_ID": "sp-b"}),
    ]

    print("\nServices starting:")
    print(f"  IdP           → {settings.idp_issuer}  (public: login, authorize, jwks)")
    print(
        f"  IdP internal  → {settings.idp_internal_base_url}  "
        "(token + admin — not for browsers; keep this off any public port in real deploys)"
    )
    for cid, cfg in settings.sp_clients().items():
        print(f"  {cfg.display_name:<14}→ {cfg.base_url}  ({cid})")
    print("\nOpen an SP in your browser and sign in once. Ctrl+C to stop.\n", flush=True)

    try:
        while True:
            for proc in procs:
                code = proc.poll()
                if code is not None:
                    raise SystemExit(f"a service exited unexpectedly (code {code})")
            try:
                procs[0].wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                continue
    except (KeyboardInterrupt, SystemExit) as exc:
        print(f"\nShutting down… ({exc})", flush=True)
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
        for proc in procs:
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()
