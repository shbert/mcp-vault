# -*- coding: utf-8 -*-
"""
Helpers d'authentification basés sur contextvars.

Le middleware ASGI injecte les infos du token dans les contextvars.
Les outils MCP appellent check_access() et check_write_permission()
pour vérifier les permissions sans dépendre du framework HTTP.
"""

from contextvars import ContextVar
from typing import Optional

# --- Context variables injectées par le middleware ---
current_token_info: ContextVar[Optional[dict]] = ContextVar("current_token_info", default=None)


def check_access(resource_id: str) -> Optional[dict]:
    """
    Vérifie que le token courant a accès à la ressource (vault).

    Logique d'autorisation :
    1. Pas de token → refusé
    2. Admin → accès total
    3. allowed_resources non vide → la ressource doit être dans la liste
    4. allowed_resources vide → owner-based isolation :
       seul le créateur du vault y a accès (via _vault_meta.created_by)

    Args:
        resource_id: ID du vault à vérifier

    Returns:
        None si OK, dict {"status": "error", ...} si refusé
    """
    token_info = current_token_info.get()

    # Pas de token → accès refusé
    if token_info is None:
        return {"status": "error", "message": "Authentification requise"}

    # Admin → accès total
    if "admin" in token_info.get("permissions", []):
        return None

    # Liste explicite de vaults autorisés → vérifier l'appartenance
    allowed = token_info.get("allowed_resources", [])
    if allowed:
        if resource_id not in allowed:
            return {
                "status": "error",
                "message": f"Accès refusé à '{resource_id}'",
                "allowed_vaults": allowed,
            }
        return None

    # Liste vide → owner-based isolation
    # Le token n'a accès qu'aux vaults qu'il a créés
    client_name = token_info.get("client_name", "")
    if client_name:
        from ..vault.spaces import check_vault_owner
        if not check_vault_owner(resource_id, client_name):
            return {
                "status": "error",
                "message": f"Accès refusé à '{resource_id}' (vous n'en êtes pas le propriétaire)",
            }

    return None


def check_write_permission() -> Optional[dict]:
    """
    Vérifie que le token courant a la permission d'écriture.

    Returns:
        None si OK, dict {"status": "error", ...} si refusé
    """
    token_info = current_token_info.get()

    if token_info is None:
        return {"status": "error", "message": "Authentification requise"}

    permissions = token_info.get("permissions", [])
    if "write" not in permissions and "admin" not in permissions:
        return {"status": "error", "message": "Permission d'écriture requise"}

    return None


def check_admin_permission() -> Optional[dict]:
    """
    Vérifie que le token courant a la permission admin.

    Returns:
        None si OK, dict {"status": "error", ...} si refusé
    """
    token_info = current_token_info.get()

    if token_info is None:
        return {"status": "error", "message": "Authentification requise"}

    if "admin" not in token_info.get("permissions", []):
        return {"status": "error", "message": "Permission admin requise"}

    return None


def check_policy(tool_name: str) -> Optional[dict]:
    """
    Vérifie que le token courant a le droit d'utiliser cet outil MCP.

    Logique :
    1. Pas de token → pas de restriction (géré par check_access)
    2. Admin → toujours autorisé
    3. Pas de policy_id → tout autorisé
    4. PolicyStore absent + policy_id présent → fail-close (la policy ne peut être vérifiée)
    5. Policy existe → vérifier via is_tool_allowed()
    6. Policy introuvable dans le store → fail-close (cohérent avec policies.py)

    Args:
        tool_name: Nom de l'outil MCP (ex: "vault_delete", "ssh_sign_key")

    Returns:
        None si OK, dict {"status": "error", ...} si refusé par la policy
    """
    token_info = current_token_info.get()

    # Pas de token → pas de policy à vérifier
    if token_info is None:
        return None

    # Admin → toujours autorisé
    if "admin" in token_info.get("permissions", []):
        return None

    # Pas de policy_id assignée → tout autorisé
    policy_id = token_info.get("policy_id", "")
    if not policy_id:
        return None

    # Vérifier via PolicyStore
    from .policies import get_policy_store

    store = get_policy_store()
    if not store:
        # PolicyStore absent mais token porte un policy_id : on ne peut pas vérifier
        # → fail-close pour éviter qu'une policy soit contournée par indisponibilité S3.
        # Si S3 n'est pas configuré du tout, les tokens n'ont jamais de policy_id.
        client = token_info.get("client_name", "?")
        try:
            from ..audit import log_audit
            log_audit(tool_name, "denied",
                      detail=f"PolicyStore indisponible — policy '{policy_id}' non vérifiable",
                      client_name=client)
        except Exception:
            pass
        return {"status": "error",
                "message": f"PolicyStore indisponible — policy '{policy_id}' ne peut être vérifiée",
                "policy_id": policy_id}

    if store.is_tool_allowed(policy_id, tool_name):
        return None

    # Audit : enregistrer le refus de policy (événement de sécurité)
    client = token_info.get("client_name", "?")
    try:
        from ..audit import log_audit
        log_audit(
            tool_name, "denied",
            detail=f"Bloque par policy '{policy_id}'",
            client_name=client,
        )
    except Exception:
        pass

    return {
        "status": "error",
        "message": f"Outil '{tool_name}' refusé par la policy '{policy_id}'",
        "policy_id": policy_id,
    }


def check_path_policy(vault_id: str, path: str,
                       required_permission: str = "read") -> Optional[dict]:
    """
    Vérifie que le token courant a le droit d'accéder à ce chemin de secret.

    Utilise les path_rules de la policy assignée au token. Vérifie à la fois :
    - que l'opération est permise par la règle (required_permission)
    - que le chemin est dans les allowed_paths de la règle

    Args:
        vault_id: ID du vault
        path: Chemin du secret (ex: "web/github")
        required_permission: "read", "write" (couvre delete), "admin"

    Returns:
        None si OK, dict {"status": "error", ...} si refusé
    """
    token_info = current_token_info.get()

    if token_info is None:
        return None  # Pas de token → pas de restriction path

    if "admin" in token_info.get("permissions", []):
        return None  # Admin → tout autorisé

    policy_id = token_info.get("policy_id", "")
    if not policy_id:
        return None  # Pas de policy → pas de restriction

    from .policies import get_policy_store

    store = get_policy_store()
    if not store:
        # Fail-close cohérent avec check_policy() : policy_id présent sans PolicyStore → refus
        client = token_info.get("client_name", "?")
        try:
            from ..audit import log_audit
            log_audit(f"secret_{required_permission}", "denied",
                      detail=f"PolicyStore indisponible — path policy '{policy_id}' non vérifiable",
                      client_name=client, vault_id=vault_id)
        except Exception:
            pass
        return {"status": "error",
                "message": f"PolicyStore indisponible — path policy '{policy_id}' ne peut être vérifiée",
                "policy_id": policy_id}

    if store.is_path_allowed(policy_id, vault_id, path, required_permission):
        return None

    # Refusé — log audit
    client = token_info.get("client_name", "?")
    try:
        from ..audit import log_audit
        log_audit(
            f"secret_{required_permission}", "denied",
            detail=f"Chemin '{path}' dans '{vault_id}' bloque par policy '{policy_id}'",
            client_name=client,
            vault_id=vault_id,
        )
    except Exception:
        pass

    return {
        "status": "error",
        "message": (
            f"Accès refusé au chemin '{path}' dans '{vault_id}' (policy '{policy_id}')"
            if path else
            f"Accès refusé au vault '{vault_id}' (policy '{policy_id}')"
        ),
        "policy_id": policy_id,
    }


def get_current_client_name() -> str:
    """Retourne le nom du client courant (depuis le token)."""
    token_info = current_token_info.get()
    if token_info is None:
        return "anonymous"
    return token_info.get("client_name", "unknown")
