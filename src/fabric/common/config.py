"""Typed, environment-driven configuration (pydantic-settings).

A single :class:`Settings` object is the source of truth for hosts, ports, lifetimes
and derived URLs. Nothing secret lives here — signing keys and the admin token are
generated at bootstrap, never read from config.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SPClientConfig(BaseModel):
    """Static metadata for one Service Provider. Keys are provisioned at seed time."""

    client_id: str
    display_name: str
    base_url: str

    @computed_field  # type: ignore[prop-decorator]
    @property
    def redirect_uri(self) -> str:
        return f"{self.base_url}/callback"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def post_logout_redirect_uri(self) -> str:
        return self.base_url

    @computed_field  # type: ignore[prop-decorator]
    @property
    def backchannel_logout_uri(self) -> str:
        return f"{self.base_url}/backchannel-logout"


class Settings(BaseSettings):
    """Process-wide configuration, overridable via ``FABRIC_*`` env vars or ``.env``."""

    model_config = SettingsConfigDict(
        env_prefix="FABRIC_", env_file=".env", extra="ignore", case_sensitive=False
    )

    # Advertised hostnames used to build issuer / base / redirect URLs. In the single-host
    # local run these all resolve to 127.0.0.1; under containers each service is reached by
    # its own name (idp / sp-a / sp-b), so the SP hosts are overridable independently.
    idp_host: str = "127.0.0.1"
    sp_a_host: str | None = None
    sp_b_host: str | None = None
    idp_port: int = 9400
    sp_a_port: int = 9401
    sp_b_port: int = 9402

    # The IdP's *internal* surface (/token, /admin/*) is split onto its own host:port so it
    # can be kept off any publicly published port — a stolen SP `private_key_jwt` key or a
    # leaked admin token is only useful to whoever can reach this listener. Defaults to the
    # same host as the public IdP (no isolation benefit locally); containers override
    # ``idp_internal_host`` to a compose-internal service name that is never port-published.
    idp_internal_host: str | None = None
    idp_internal_port: int = 9410

    cookie_secure: bool = False

    # Comma-separated IPs allowed to set X-Forwarded-For for audit `source_ip` purposes.
    # Empty (default) means: never trust the header — there is no reverse proxy in front of
    # these services by default, so any client could otherwise spoof its logged source IP.
    trusted_proxy_ips: str = ""

    idp_session_idle_seconds: int = 900
    idp_session_absolute_seconds: int = 28800
    sp_session_idle_seconds: int = 900
    sp_session_absolute_seconds: int = 28800

    access_token_ttl_seconds: int = 300
    id_token_ttl_seconds: int = 300
    auth_code_ttl_seconds: int = 60
    client_assertion_max_ttl_seconds: int = 120

    data_dir: Path = Path("./data")

    # Per-database file overrides. Under container isolation each service mounts only its
    # own volume, so its DB lives on a distinct path rather than a shared data_dir.
    idp_db_file: Path | None = None
    sp_a_db_file: Path | None = None
    sp_b_db_file: Path | None = None

    # Which SP this process is, when running an SP app (set by the launcher).
    sp_id: str | None = None

    @property
    def idp_issuer(self) -> str:
        return f"http://{self.idp_host}:{self.idp_port}"

    @property
    def idp_internal_base_url(self) -> str:
        """Base URL for the internal-only IdP surface (/token, /admin/*)."""
        return f"http://{self.idp_internal_host or self.idp_host}:{self.idp_internal_port}"

    @property
    def trusted_proxy_ip_set(self) -> frozenset[str]:
        return frozenset(ip.strip() for ip in self.trusted_proxy_ips.split(",") if ip.strip())

    @property
    def idp_db_path(self) -> Path:
        return self.idp_db_file or (self.data_dir / "idp.db")

    def _sp_host(self, client_id: str) -> str:
        override = {"sp-a": self.sp_a_host, "sp-b": self.sp_b_host}.get(client_id)
        return override or self.idp_host

    def _sp_port(self, client_id: str) -> int:
        return {"sp-a": self.sp_a_port, "sp-b": self.sp_b_port}[client_id]

    def sp_db_path(self, client_id: str) -> Path:
        override = {"sp-a": self.sp_a_db_file, "sp-b": self.sp_b_db_file}.get(client_id)
        return override or (self.data_dir / f"{client_id.replace('-', '_')}.db")

    def sp_clients(self) -> dict[str, SPClientConfig]:
        """The registered Service Providers, keyed by ``client_id``."""
        return {
            "sp-a": SPClientConfig(
                client_id="sp-a",
                display_name="Atlas Console",
                base_url=f"http://{self._sp_host('sp-a')}:{self._sp_port('sp-a')}",
            ),
            "sp-b": SPClientConfig(
                client_id="sp-b",
                display_name="Borealis Portal",
                base_url=f"http://{self._sp_host('sp-b')}:{self._sp_port('sp-b')}",
            ),
        }

    def sp_client(self, client_id: str) -> SPClientConfig:
        clients = self.sp_clients()
        if client_id not in clients:
            raise KeyError(f"unknown SP client_id: {client_id!r}")
        return clients[client_id]


@lru_cache
def get_settings() -> Settings:
    return Settings()
