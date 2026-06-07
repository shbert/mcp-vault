# -*- coding: utf-8 -*-
"""Configuration du service MCP Vault via pydantic-settings."""

from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Configuration chargée depuis les variables d'env / .env."""

    # --- Serveur MCP ---
    mcp_server_name: str = "mcp-vault"
    mcp_server_host: str = "0.0.0.0"
    mcp_server_port: int = 8030
    mcp_server_debug: bool = False

    # --- WAF ---
    # Port externe du WAF Caddy (variable partagée avec docker-compose). Déclaré ici
    # pour que le .env mutualisé ne soit pas rejeté tout en gardant extra="forbid"
    # (toute autre variable inconnue = typo → erreur explicite au démarrage).
    waf_port: int = 8085

    # --- Transport security (protection anti-DNS-rebinding du SDK MCP) ---
    # FQDN publics autorisés pour le header Host sur /mcp, séparés par des virgules.
    # Le loopback (localhost/127.0.0.1) est TOUJOURS autorisé en plus (health checks
    # internes, tests e2e via WAF localhost). Surchargeable via MCP_ALLOWED_HOSTS.
    mcp_allowed_hosts: str = "vault.mcp.cloud-temple.app,my.vault.mcp.cloud-temple.app"
    # Origins HTTP supplémentaires, séparés par des virgules. "https://<fqdn>" est de
    # toute façon dérivé pour chaque FQDN ci-dessus ; cette variable AJOUTE d'autres
    # origins (ne les remplace pas). Surchargeable via MCP_ALLOWED_ORIGINS.
    mcp_allowed_origins: str = ""

    # --- Auth ---
    admin_bootstrap_key: str = "change_me_in_production"

    # --- S3 Token Store (optionnel — si vide, tokens en mémoire uniquement) ---
    s3_endpoint_url: str = ""
    s3_access_key_id: str = ""
    s3_secret_access_key: str = ""
    s3_bucket_name: str = ""
    s3_region_name: str = "fr1"

    # --- OpenBao ---
    openbao_addr: str = "http://127.0.0.1:8200"
    openbao_shares: int = 1
    openbao_threshold: int = 1
    openbao_data_dir: str = "/openbao/file"
    openbao_config_dir: str = "/openbao/config"

    # --- S3 Vault Storage Sync ---
    vault_s3_prefix: str = "_storage"
    vault_s3_sync_interval: int = 60

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @property
    def allowed_hosts_list(self) -> list[str]:
        """FQDN publics autorisés (CSV), normalisés en minuscules (DNS insensible à la casse)."""
        return [h.strip().lower() for h in self.mcp_allowed_hosts.split(",") if h.strip()]

    @property
    def allowed_origins_list(self) -> list[str]:
        """Origins HTTP supplémentaires (CSV), normalisées en minuscules."""
        return [o.strip().lower() for o in self.mcp_allowed_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    """Singleton pour la config (cachée en mémoire)."""
    return Settings()
