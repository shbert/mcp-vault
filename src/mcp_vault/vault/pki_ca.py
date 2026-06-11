# -*- coding: utf-8 -*-
"""
PKI Certificate Authority — CA interne pour l'écosystème mcp-vault.

CA globale (deux mounts système réservés) :
  _sys_pki_root/  — CA racine (lab: self-signed ; prod: CSR importé)
  _sys_pki_int/   — CA intermédiaire d'émission + serveur ACME

Les mounts _sys_pki_* sont protégés contre vault_delete
(guard dans spaces.py:delete_space et server.py:vault_delete).

Sync S3 forcée après toute mutation critique (setup, rotate, revoke)
pour éviter la perte d'inventaire/révocation lors d'un crash.
"""

import asyncio
import logging
import re
from typing import Optional

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from ..config import get_settings
from ._hvac_utils import safe_list_keys

logger = logging.getLogger("mcp-vault.pki-ca")

_ROOT_MOUNT = "_sys_pki_root"
_INT_MOUNT = "_sys_pki_int"
_ACME_ROLE_NAME = "acme-servers"

# Politiques EAB valides côté OpenBao (config/acme). "required" N'EXISTE PAS —
# valeurs acceptées : not-required, new-account-required, always-required.
# Lab : pas d'EAB (enrôlement libre). Prod : EAB exigé à la création de compte
# (bloque l'enrôlement public non authentifié sans casser les comptes existants).
_EAB_POLICY_LAB = "not-required"
_EAB_POLICY_PROD = "new-account-required"
# Headers de réponse ACME (RFC 8555) qu'OpenBao doit être autorisé à renvoyer ;
# sinon ils sont strippés et l'enrôlement ACME réel échoue.
_ACME_RESPONSE_HEADERS = ["Replay-Nonce", "Link", "Location"]


def _eab_required(eab_policy: str) -> bool:
    """True si la politique EAB impose un External Account Binding."""
    return eab_policy in ("new-account-required", "always-required")

# Préfixe protégé — utilisé dans spaces.py et server.py pour refuser vault_delete
RESERVED_MOUNT_PREFIX = "_sys_pki_"

# SÉCURITÉ : regex de validation du serial_number (hex séparé par colons)
_SERIAL_NUMBER_PATTERN = re.compile(r'^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})+$')

# SÉCURITÉ : regex de validation des domaines ACME (FQDN ou wildcard *.domain.tld)
_DOMAIN_PATTERN = re.compile(
    r'^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
)

# Lock global pour serialiser les appels à setup_pki_ca (idempotence + race condition)
_PKI_SETUP_LOCK: Optional[asyncio.Lock] = None


def _get_setup_lock() -> asyncio.Lock:
    # ⚠️ Lock per-process (asyncio) : NE FONCTIONNE QU'EN SINGLE-WORKER.
    # Pour multi-worker (uvicorn workers > 1), utiliser un verrou distribué.
    global _PKI_SETUP_LOCK
    if _PKI_SETUP_LOCK is None:
        _PKI_SETUP_LOCK = asyncio.Lock()
    return _PKI_SETUP_LOCK


def _get_hvac_client():
    """Lazy import de get_hvac_client (évite l'import hvac au niveau module)."""
    from ..openbao.manager import get_hvac_client
    return get_hvac_client()  # noqa: F821 — hvac importé dans get_hvac_client


def is_reserved_mount(vault_id: str) -> bool:
    """Retourne True si vault_id est un mount système PKI protégé."""
    return vault_id.startswith(RESERVED_MOUNT_PREFIX)


def _sha256_fingerprint(pem_text: str) -> str:
    """Empreinte SHA-256 d'un certificat PEM (format XX:XX:...)."""
    cert = x509.load_pem_x509_certificate(pem_text.encode())
    fp_bytes = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in fp_bytes)


def _cert_expiry_iso(pem_text: str) -> str:
    """Date d'expiration ISO 8601 d'un certificat PEM."""
    cert = x509.load_pem_x509_certificate(pem_text.encode())
    return cert.not_valid_after_utc.isoformat()


async def _read_pem_url(path: str) -> str:
    """
    Lit un endpoint PKI OpenBao retournant du texte PEM brut (non-JSON).

    Les endpoints /ca/pem, /ca_chain, /crl sont unauthenticated dans PKI engine.
    Valide que la réponse est du PEM avant de la retourner (sauf CRL — format DER/PEM distinct).
    """
    settings = get_settings()
    url = f"{settings.openbao_addr}/v1/{path}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url, follow_redirects=False)
        resp.raise_for_status()

    # Validation minimale : le contenu doit commencer par un header PEM
    text = resp.text
    if not text.strip().startswith("-----BEGIN "):
        raise ValueError(f"Réponse OpenBao non-PEM pour {path} : {text[:80]!r}")
    return text


def is_pki_initialized() -> bool:
    """Retourne True si les deux mounts PKI système sont montés."""
    client = _get_hvac_client()
    if not client:
        return False
    try:
        mounts = client.sys.list_mounted_secrets_engines()
        data = mounts.get("data", mounts)
        return f"{_ROOT_MOUNT}/" in data and f"{_INT_MOUNT}/" in data
    except Exception:
        return False


def _base_url() -> str:
    """URL publique de la façade mcp-vault (issuing_certificates, ACME directory).

    Priorité : PKI_BASE_URL (override explicite, ex: http://mcp-vault:8030 en test Docker)
    > premier FQDN non-loopback de MCP_ALLOWED_HOSTS (https://{fqdn})
    > fallback localhost (invalide en prod — warning émis).
    """
    settings = get_settings()
    if settings.pki_base_url:
        return settings.pki_base_url_validated
    hosts = settings.allowed_hosts_list
    loopback = {"127.0.0.1", "localhost", "::1"}
    fqdn = next((h for h in hosts if h not in loopback), None)
    if not fqdn:
        logger.warning(
            "⚠️ PKI : aucun FQDN public dans MCP_ALLOWED_HOSTS — "
            "les CDPs et URLs ACME utiliseront localhost (invalides en prod). "
            "Configurer MCP_ALLOWED_HOSTS ou PKI_BASE_URL."
        )
        return "http://localhost:8080"
    return f"https://{fqdn}"


def _mount_pki_engine(client, mount: str, max_ttl: str) -> None:
    """Monte un engine PKI (idempotent — ignore si déjà monté)."""
    try:
        client.sys.enable_secrets_engine(
            backend_type="pki",
            path=mount,
            config={"max_lease_ttl": max_ttl},
        )
        logger.info(f"✅ PKI engine monté : {mount}")
    except Exception as e:
        msg = str(e).lower()
        if "existing mount" not in msg and "path is already in use" not in msg:
            raise


async def setup_pki_ca(lab_mode: bool = True,
                       allowed_domains: Optional[list] = None,
                       leaf_ttl: str = "720h") -> dict:
    """
    Configure la hiérarchie PKI complète (racine + intermédiaire + ACME).

    Idempotent : reconfigure sans détruire les mounts existants.
    Lab : CA racine self-signed. Prod : générer un CSR, signer extern, importer.

    Sync S3 forcée après setup (durabilité CA critique).
    """
    if allowed_domains is None:
        allowed_domains = ["*.lesur.lan", "lesur.lan"] if lab_mode else []

    if not allowed_domains:
        return {"status": "error", "message": "allowed_domains requis"}

    # MOYEN : validation du format des domaines autorisés (FQDN ou wildcard *.domain.tld)
    for domain in allowed_domains:
        if not _DOMAIN_PATTERN.match(domain.strip()):
            return {"status": "error", "message": f"Domaine invalide : '{domain}' (format FQDN requis)"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    base = _base_url()

    # ÉLEVÉ : lock global pour éviter les race conditions si setup_pki_ca est appelé en parallèle
    async with _get_setup_lock():
        try:
            # ── 1. CA Racine ────────────────────────────────────────────────
            _mount_pki_engine(client, _ROOT_MOUNT, "87600h")

            root_cert_pem = ""
            try:
                root_resp = client.write(
                    f"{_ROOT_MOUNT}/root/generate/internal",
                    common_name="MCP Vault Root CA",
                    ttl="87600h",
                    key_type="rsa",
                    key_bits=4096,
                    issuer_name="mcp-vault-root",
                )
                root_cert_pem = root_resp.get("data", {}).get("certificate", "") if root_resp else ""
            except Exception as e:
                if "issuer name already in use" in str(e).lower():
                    logger.info("ℹ️  CA racine déjà générée — skip génération (idempotent)")
                else:
                    raise

            client.write(
                f"{_ROOT_MOUNT}/config/urls",
                issuing_certificates=[f"{base}/pki/ca/root.pem"],
                crl_distribution_points=[f"{base}/pki/ca/crl.pem"],
            )
            logger.info("✅ CA racine PKI configurée")

            # ── 2. CA Intermédiaire ─────────────────────────────────────────
            _mount_pki_engine(client, _INT_MOUNT, "43800h")

            # Autoriser OpenBao à renvoyer les headers de réponse ACME (RFC 8555).
            # Sans ce tuning, OpenBao strippe Replay-Nonce/Link/Location et
            # l'enrôlement ACME (newNonce, newOrder) échoue côté client — y compris
            # en lab. C'est un prérequis dur : on fait échouer le setup si le tuning
            # échoue, plutôt que d'annoncer une PKI opérationnelle qui ne l'est pas.
            try:
                client.sys.tune_mount_configuration(
                    path=_INT_MOUNT,
                    allowed_response_headers=_ACME_RESPONSE_HEADERS,
                )
                logger.info("✅ Tuning ACME headers : %s", ", ".join(_ACME_RESPONSE_HEADERS))
            except Exception as e:
                logger.error("❌ Tuning allowed_response_headers échoué : %s", type(e).__name__)
                raise RuntimeError(
                    "Tuning ACME headers (Replay-Nonce/Link/Location) échoué — "
                    "l'enrôlement ACME serait cassé ; setup PKI interrompu"
                ) from e

            try:
                csr_resp = client.write(
                    f"{_INT_MOUNT}/intermediate/generate/internal",
                    common_name="MCP Vault Intermediate CA",
                    ttl="43800h",
                    key_type="rsa",
                    key_bits=4096,
                    issuer_name="mcp-vault-int",
                    add_basic_constraints=True,
                )
                csr = csr_resp["data"]["csr"]

                # issuer_ref est un paramètre de PATH (pas de body) dans l'API OpenBao :
                # /issuer/:issuer_ref/sign-intermediate.
                sign_resp = client.write(
                    f"{_ROOT_MOUNT}/issuer/mcp-vault-root/sign-intermediate",
                    csr=csr,
                    format="pem_bundle",
                    ttl="43800h",
                )
                signed_cert = sign_resp["data"]["certificate"]

                import_resp = client.write(
                    f"{_INT_MOUNT}/intermediate/set-signed",
                    certificate=signed_cert,
                )
                imported_issuers = import_resp.get("data", {}).get("imported_issuers", []) if import_resp else []
                new_issuer_id = imported_issuers[0] if imported_issuers else ""

                if new_issuer_id:
                    client.write(f"{_INT_MOUNT}/config/issuers", default=new_issuer_id)
            except Exception as e:
                if "issuer name already in use" in str(e).lower():
                    logger.info("ℹ️  CA intermédiaire déjà générée — skip génération (idempotent)")
                else:
                    raise

            client.write(
                f"{_INT_MOUNT}/config/urls",
                issuing_certificates=[f"{base}/pki/ca/chain.pem"],
                crl_distribution_points=[f"{base}/pki/ca/crl.pem"],
            )
            logger.info("✅ CA intermédiaire PKI configurée")

            # ── 3. Rôle d'émission ACME ─────────────────────────────────────
            client.write(
                f"{_INT_MOUNT}/roles/{_ACME_ROLE_NAME}",
                server_flag=True,
                client_flag=False,
                allow_any_name=False,
                allow_localhost=False,
                allow_ip_sans=False,
                allowed_domains=allowed_domains,
                allow_subdomains=True,
                allow_wildcard_certificates=True,
                enforce_hostnames=True,
                max_ttl=leaf_ttl,
                no_store=False,
                key_type="rsa",
                key_bits=2048,
                require_cn=False,
            )
            logger.info(f"✅ Rôle ACME '{_ACME_ROLE_NAME}' configuré pour {allowed_domains}")

            # ── 3b. Cluster path (requis par OpenBao pour ACME) ─────────────
            # OpenBao génère des URLs absolues dans le directory ACME basées
            # sur ce chemin. PkiMiddleware gère les deux patterns :
            #   /acme/*               (URL courte, user-facing)
            #   /v1/_sys_pki_int/acme/* (URL longue, générée par OpenBao)
            # Note : hvac.write(path, **kwargs) a path en 1er arg → collision
            # avec le champ body OpenBao "path". On passe par l'adaptateur.
            _cluster_path = f"{base}/v1/{_INT_MOUNT}"
            client._adapter.post(
                f"/v1/{_INT_MOUNT}/config/cluster",
                json={"path": _cluster_path},
            )
            logger.info(f"✅ Cluster path PKI configuré : {_cluster_path}")

            # ── 4. Serveur ACME ─────────────────────────────────────────────
            eab_policy = _EAB_POLICY_LAB if lab_mode else _EAB_POLICY_PROD
            client.write(
                f"{_INT_MOUNT}/config/acme",
                enabled=True,
                default_directory_policy=f"role:{_ACME_ROLE_NAME}",
                allowed_roles=[_ACME_ROLE_NAME],
                allowed_issuers=["*"],
                eab_policy=eab_policy,
            )
            logger.info("✅ Serveur ACME activé (eab_policy=%s)", eab_policy)

            # ── 5. Sync S3 forcée ───────────────────────────────────────────
            from ..s3_sync import upload_to_s3
            sync_ok = await upload_to_s3()
            if not sync_ok:
                logger.error("❌ Sync S3 échouée après setup PKI — durabilité CA compromise")
            else:
                logger.info("✅ Sync S3 OK après setup PKI")

            root_expiry = _cert_expiry_iso(root_cert_pem) if root_cert_pem else "inconnu"
            root_fp = _sha256_fingerprint(root_cert_pem) if root_cert_pem else ""

            return {
                "status": "ok",
                "lab_mode": lab_mode,
                "root_mount": _ROOT_MOUNT,
                "int_mount": _INT_MOUNT,
                "acme_directory": f"{base}/acme/directory",
                "root_pem_url": f"{base}/pki/ca/root.pem",
                "chain_pem_url": f"{base}/pki/ca/chain.pem",
                "crl_url": f"{base}/pki/ca/crl.pem",
                "root_expires": root_expiry,
                "root_fingerprint_sha256": root_fp,
                "allowed_domains": allowed_domains,
                "leaf_ttl": leaf_ttl,
                "eab_policy": eab_policy,
                "eab_required": _eab_required(eab_policy),
                "s3_sync_ok": sync_ok,
            }
        except Exception as e:
            logger.error(f"❌ Erreur setup PKI CA : {e}")
            return {"status": "error", "message": str(e)}


async def get_ca_root_pem() -> dict:
    """Retourne la CA racine PEM avec empreinte SHA-256 et URL stable."""
    if not is_pki_initialized():
        return {"status": "error", "message": "PKI non initialisée — appelez pki_ca_setup"}
    try:
        pem = await _read_pem_url(f"{_ROOT_MOUNT}/ca/pem")
        return {
            "status": "ok",
            "pem": pem,
            "sha256_fingerprint": _sha256_fingerprint(pem),
            "expires": _cert_expiry_iso(pem),
            "url": f"{_base_url()}/pki/ca/root.pem",
            "usage": "Ajouter dans le trust store des clients httpx et Caddyfile (trusted_ca_file / acme_ca_root)",
        }
    except Exception as e:
        logger.error(f"❌ Erreur lecture CA racine : {e}")
        return {"status": "error", "message": str(e)}


async def get_pki_status() -> dict:
    """État complet de la PKI (issuers, expiration, ACME, compteur certs)."""
    if not is_pki_initialized():
        return {"status": "not_initialized", "message": "PKI non initialisée"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        try:
            certs_resp = client.list(f"{_INT_MOUNT}/certs")
            cert_count = len(certs_resp.get("data", {}).get("keys", []))
        except Exception:
            cert_count = 0

        try:
            root_pem = await _read_pem_url(f"{_ROOT_MOUNT}/ca/pem")
            root_expires = _cert_expiry_iso(root_pem)
            root_fp = _sha256_fingerprint(root_pem)
        except Exception:
            root_expires, root_fp = "inconnu", ""

        try:
            int_pem = await _read_pem_url(f"{_INT_MOUNT}/ca/pem")
            int_expires = _cert_expiry_iso(int_pem)
        except Exception:
            int_expires = "inconnu"

        try:
            acme_cfg = client.read(f"{_INT_MOUNT}/config/acme")
            acme_data = acme_cfg.get("data", {}) if acme_cfg else {}
            acme_enabled = acme_data.get("enabled", False)
            eab_policy = acme_data.get("eab_policy", "unknown")
        except Exception:
            acme_enabled, eab_policy = False, "unknown"

        base = _base_url()
        return {
            "status": "ok",
            "initialized": True,
            "root_expires": root_expires,
            "root_fingerprint_sha256": root_fp,
            "int_expires": int_expires,
            "cert_count": cert_count,
            "acme_enabled": acme_enabled,
            "eab_policy": eab_policy,
            "eab_required": _eab_required(eab_policy),
            "acme_directory": f"{base}/acme/directory",
            "root_pem_url": f"{base}/pki/ca/root.pem",
            "chain_pem_url": f"{base}/pki/ca/chain.pem",
            "crl_url": f"{base}/pki/ca/crl.pem",
        }
    except Exception as e:
        logger.error(f"❌ Erreur status PKI : {e}")
        return {"status": "error", "message": str(e)}


async def list_pki_roles() -> dict:
    """Liste les rôles d'émission PKI configurés sur la CA intermédiaire."""
    if not is_pki_initialized():
        return {"status": "error", "message": "PKI non initialisée"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        response = client.list(f"{_INT_MOUNT}/roles")
        roles = safe_list_keys(response)  # None si aucun rôle (issue #38)
        return {"status": "ok", "roles": roles, "count": len(roles)}
    except Exception as e:
        msg = str(e).lower()
        if "404" in msg or "no entries" in msg:
            return {"status": "ok", "roles": [], "count": 0}
        logger.error(f"❌ Erreur liste rôles PKI : {e}")
        return {"status": "error", "message": str(e)}


async def get_pki_role_info(role_name: str) -> dict:
    """Détails d'un rôle d'émission PKI (domaines, TTL, flags TLS)."""
    if not role_name:
        return {"status": "error", "message": "role_name requis"}
    if not is_pki_initialized():
        return {"status": "error", "message": "PKI non initialisée"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        response = client.read(f"{_INT_MOUNT}/roles/{role_name}")
        if not response or not response.get("data"):
            return {"status": "error", "message": f"Rôle PKI '{role_name}' non trouvé"}
        data = response["data"]
        return {
            "status": "ok",
            "role_name": role_name,
            "allowed_domains": data.get("allowed_domains", []),
            "allow_any_name": data.get("allow_any_name", False),
            "allow_subdomains": data.get("allow_subdomains", False),
            "allow_wildcard_certificates": data.get("allow_wildcard_certificates", False),
            "server_flag": data.get("server_flag", False),
            "client_flag": data.get("client_flag", False),
            "allow_ip_sans": data.get("allow_ip_sans", False),
            "allow_localhost": data.get("allow_localhost", False),
            "max_ttl": data.get("max_ttl", ""),
            "key_type": data.get("key_type", ""),
            "key_bits": data.get("key_bits", 0),
        }
    except Exception as e:
        logger.error(f"❌ Erreur info rôle PKI '{role_name}' : {e}")
        return {"status": "error", "message": str(e)}


async def list_issued_certs(limit: int = 100, offset: int = 0) -> dict:
    """Inventaire paginé des certificats émis (serials, SANs, expiration, révocation)."""
    if not is_pki_initialized():
        return {"status": "error", "message": "PKI non initialisée"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        certs_resp = client.list(f"{_INT_MOUNT}/certs")
        all_serials = safe_list_keys(certs_resp)  # None si aucun cert émis (issue #38)
        total = len(all_serials)
        page_serials = all_serials[offset:offset + limit]

        certs = []
        for serial in page_serials:
            try:
                cert_resp = client.read(f"{_INT_MOUNT}/cert/{serial}")
                cert_data = cert_resp.get("data", {}) if cert_resp else {}
                cert_pem = cert_data.get("certificate", "")
                revocation_time = cert_data.get("revocation_time", 0)

                entry: dict = {"serial": serial, "revoked": revocation_time > 0}

                if cert_pem:
                    try:
                        cert = x509.load_pem_x509_certificate(cert_pem.encode())
                        entry["not_after"] = cert.not_valid_after_utc.isoformat()
                        try:
                            san_ext = cert.extensions.get_extension_for_oid(
                                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                            )
                            entry["sans"] = [str(n.value) for n in san_ext.value]
                        except x509.ExtensionNotFound:
                            entry["sans"] = []
                    except Exception:
                        pass

                certs.append(entry)
            except Exception:
                certs.append({"serial": serial, "error": "unreadable"})

        return {
            "status": "ok",
            "total": total,
            "offset": offset,
            "limit": limit,
            "certs": certs,
        }
    except Exception as e:
        msg = str(e).lower()
        if "404" in msg or "no entries" in msg:
            return {"status": "ok", "total": 0, "offset": offset, "limit": limit, "certs": []}
        logger.error(f"❌ Erreur inventaire certs PKI : {e}")
        return {"status": "error", "message": str(e)}


async def revoke_cert(serial_number: str) -> dict:
    """
    Révoque un certificat et force la rotation de la CRL.

    Sync S3 forcée : la révocation est une mutation critique (ne pas perdre).
    """
    if not serial_number:
        return {"status": "error", "message": "serial_number requis"}
    # CRITIQUE : validation stricte du serial_number (format hex:xx:xx)
    if not _SERIAL_NUMBER_PATTERN.match(serial_number.strip()):
        return {"status": "error", "message": "serial_number invalide (format attendu : aa:bb:cc:...)"}
    if not is_pki_initialized():
        return {"status": "error", "message": "PKI non initialisée"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        revoke_resp = client.write(
            f"{_INT_MOUNT}/revoke",
            serial_number=serial_number.strip(),
        )
        rev_time = revoke_resp.get("data", {}).get("revocation_time", 0) if revoke_resp else 0

        client.write(f"{_INT_MOUNT}/crl/rotate")

        from ..s3_sync import upload_to_s3
        sync_ok = await upload_to_s3()
        if not sync_ok:
            logger.error(f"❌ Sync S3 échouée après révocation {serial_number} — CRL peut être obsolète en S3")

        logger.info(f"✅ Cert révoqué et CRL mise à jour : {serial_number}")
        return {
            "status": "ok",
            "serial_number": serial_number,
            "revocation_time": rev_time,
            "crl_updated": True,
            "s3_sync_ok": sync_ok,
        }
    except Exception as e:
        logger.error(f"❌ Erreur révocation cert {serial_number} : {e}")
        return {"status": "error", "message": str(e)}


async def rotate_intermediate(keep_old_issuer: bool = True,
                               overlap_ttl: str = "48h") -> dict:
    """
    Rotation sans coupure de la CA intermédiaire.

    Nouveau CSR → signature racine → import → set default issuer.
    L'ancien issuer reste actif si keep_old_issuer=True (certs existants valides).
    Sync S3 forcée après rotation.
    """
    if not is_pki_initialized():
        return {"status": "error", "message": "PKI non initialisée"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        old_config = client.read(f"{_INT_MOUNT}/config/issuers")
        old_default_id = old_config.get("data", {}).get("default", "") if old_config else ""

        csr_resp = client.write(
            f"{_INT_MOUNT}/intermediate/generate/internal",
            common_name="MCP Vault Intermediate CA (rotated)",
            key_type="rsa",
            key_bits=4096,
            issuer_name="mcp-vault-int-new",
            add_basic_constraints=True,
        )
        csr = csr_resp["data"]["csr"]

        # issuer_ref est un paramètre de PATH (cf. setup_pki_ca) — pas de body.
        sign_resp = client.write(
            f"{_ROOT_MOUNT}/issuer/mcp-vault-root/sign-intermediate",
            csr=csr,
            format="pem_bundle",
            ttl="43800h",
        )
        signed_cert = sign_resp["data"]["certificate"]

        import_resp = client.write(
            f"{_INT_MOUNT}/intermediate/set-signed",
            certificate=signed_cert,
        )
        imported_issuers = import_resp.get("data", {}).get("imported_issuers", []) if import_resp else []
        new_issuer_id = imported_issuers[0] if imported_issuers else ""

        if new_issuer_id:
            client.write(f"{_INT_MOUNT}/config/issuers", default=new_issuer_id)
            logger.info(f"✅ Nouvel issuer intermédiaire défini comme default : {new_issuer_id}")

        if not keep_old_issuer and old_default_id:
            try:
                client.delete(f"{_INT_MOUNT}/issuer/{old_default_id}")
                logger.info(f"🗑️ Ancien issuer supprimé : {old_default_id}")
            except Exception as e:
                logger.warning(f"⚠️ Impossible de supprimer l'ancien issuer {old_default_id} : {e}")

        from ..s3_sync import upload_to_s3
        sync_ok = await upload_to_s3()
        if not sync_ok:
            logger.error("❌ Sync S3 échouée après rotation intermédiaire — durabilité compromise")

        try:
            new_pem = await _read_pem_url(f"{_INT_MOUNT}/ca/pem")
            new_expires = _cert_expiry_iso(new_pem)
        except Exception:
            new_expires = "inconnu"

        return {
            "status": "ok",
            "old_issuer_id": old_default_id,
            "new_issuer_id": new_issuer_id,
            "new_expires": new_expires,
            "keep_old_issuer": keep_old_issuer,
            "overlap_ttl": overlap_ttl,
            "s3_sync_ok": sync_ok,
        }
    except Exception as e:
        logger.error(f"❌ Erreur rotation intermédiaire PKI : {e}")
        return {"status": "error", "message": str(e)}
