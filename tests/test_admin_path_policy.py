#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests comportementaux pour check_path_policy() sur l'API REST admin secrets.

Réécriture de la version initiale (pure recherche de chaînes dans le source)
vers des tests qui exercent réellement le code de production : si check_path_policy
était retiré de api.py, ces tests échoueraient.

Architecture : ASGI invocation directe de handle_admin_api() avec mocks ciblés.
"""
import json
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _loop():
    """Boucle d'événements valide même si une suite antérieure l'a fermée (issue #36)."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop


def _make_scope(method: str, path: str, token: str = "admin-bootstrap-token") -> dict:
    """Construit un scope ASGI minimal."""
    return {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
    }


def _make_receive(body: bytes = b"{}"):
    """Construit une coroutine receive ASGI qui retourne le body."""
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    return receive


def _collected_responses():
    """Retourne un collecteur de réponses ASGI et sa liste."""
    responses = []

    async def send(message):
        responses.append(message)

    return responses, send


def _make_token_info(permissions=None, policy_id="", allowed_resources=None):
    return {
        "client_name": "test-agent",
        "permissions": permissions or ["read"],
        "policy_id": policy_id,
        "allowed_resources": allowed_resources or ["test-vault"],
        "hash": "a" * 64,
    }


async def _call_admin_api(scope, body=b"{}"):
    """Appelle handle_admin_api et retourne le status code + body JSON."""
    from mcp_vault.admin.api import handle_admin_api
    responses, send = _collected_responses()
    receive = _make_receive(body)
    await handle_admin_api(scope, receive, send, mcp=None)
    status = next((r["status"] for r in responses if r.get("type") == "http.response.start"), None)
    body_bytes = b"".join(
        r.get("body", b"") for r in responses if r.get("type") == "http.response.body"
    )
    return status, json.loads(body_bytes) if body_bytes else {}


def test_admin_api_list_secrets_blocked_by_path_policy():
    """
    GET /admin/api/vaults/{vault}/secrets est bloqué par check_path_policy("read").
    Si check_path_policy était retiré, le test échouerait (on obtiendrait 200, pas 403).
    """
    import asyncio

    scope = _make_scope("GET", "/admin/api/vaults/test-vault/secrets")
    token_info = _make_token_info(permissions=["read", "write"], policy_id="test-policy")

    # check_path_policy retourne une erreur pour vault=test-vault → doit bloquer
    path_policy_err = {"status": "error", "message": "Chemin refusé par policy"}

    with patch("mcp_vault.admin.api._get_token_info", return_value=token_info), \
         patch("mcp_vault.admin.api.check_policy", return_value=None), \
         patch("mcp_vault.admin.api.check_path_policy", return_value=path_policy_err) as mock_cpp, \
         patch("mcp_vault.admin.api._check_vault_access", return_value=None):
        status, body = _loop().run_until_complete(
            _call_admin_api(scope)
        )

    assert status == 403, f"Attendu 403 (bloqué par path policy), obtenu {status}: {body}"
    mock_cpp.assert_called_once_with("test-vault", "", "read")
    print("  ✅ list_secrets bloqué par check_path_policy(vault_id, '', 'read')")


def test_admin_api_read_secret_blocked_by_path_policy():
    """
    GET /admin/api/vaults/{vault}/secrets/{path} est bloqué par check_path_policy("read").
    """
    import asyncio

    scope = _make_scope("GET", "/admin/api/vaults/test-vault/secrets/secret/key")
    token_info = _make_token_info(permissions=["read"], policy_id="test-policy")
    path_policy_err = {"status": "error", "message": "Path interdit"}

    with patch("mcp_vault.admin.api._get_token_info", return_value=token_info), \
         patch("mcp_vault.admin.api.check_policy", return_value=None), \
         patch("mcp_vault.admin.api.check_path_policy", return_value=path_policy_err) as mock_cpp, \
         patch("mcp_vault.admin.api._check_vault_access", return_value=None):
        status, body = _loop().run_until_complete(
            _call_admin_api(scope)
        )

    assert status == 403, f"Attendu 403, obtenu {status}: {body}"
    mock_cpp.assert_called_once_with("test-vault", "secret/key", "read")
    print("  ✅ read_secret bloqué par check_path_policy(vault_id, path, 'read')")


def test_admin_api_write_secret_blocked_by_path_policy():
    """
    POST /admin/api/vaults/{vault}/secrets est bloqué par check_path_policy("write").
    """
    import asyncio

    scope = _make_scope("POST", "/admin/api/vaults/test-vault/secrets")
    token_info = _make_token_info(permissions=["read", "write"], policy_id="test-policy")
    path_policy_err = {"status": "error", "message": "Écriture refusée par policy"}
    body = json.dumps({"path": "db/prod", "data": {"key": "val"}}).encode()

    with patch("mcp_vault.admin.api._get_token_info", return_value=token_info), \
         patch("mcp_vault.admin.api.check_policy", return_value=None), \
         patch("mcp_vault.admin.api.check_path_policy", return_value=path_policy_err) as mock_cpp, \
         patch("mcp_vault.admin.api._check_vault_access", return_value=None):
        status, resp = _loop().run_until_complete(
            _call_admin_api(scope, body=body)
        )

    assert status == 403, f"Attendu 403, obtenu {status}: {resp}"
    mock_cpp.assert_called_once_with("test-vault", "db/prod", "write")
    print("  ✅ write_secret bloqué par check_path_policy(vault_id, path, 'write')")


def test_admin_api_delete_secret_blocked_by_path_policy():
    """
    DELETE /admin/api/vaults/{vault}/secrets/{path} est bloqué par check_path_policy("write").
    """
    import asyncio

    scope = _make_scope("DELETE", "/admin/api/vaults/test-vault/secrets/db/prod")
    token_info = _make_token_info(permissions=["read", "write"], policy_id="test-policy")
    path_policy_err = {"status": "error", "message": "Suppression refusée par policy"}

    with patch("mcp_vault.admin.api._get_token_info", return_value=token_info), \
         patch("mcp_vault.admin.api.check_policy", return_value=None), \
         patch("mcp_vault.admin.api.check_path_policy", return_value=path_policy_err) as mock_cpp, \
         patch("mcp_vault.admin.api._check_vault_access", return_value=None):
        status, resp = _loop().run_until_complete(
            _call_admin_api(scope)
        )

    assert status == 403, f"Attendu 403, obtenu {status}: {resp}"
    mock_cpp.assert_called_once_with("test-vault", "db/prod", "write")
    print("  ✅ delete_secret bloqué par check_path_policy(vault_id, path, 'write')")


if __name__ == "__main__":
    import asyncio

    tests = [
        test_admin_api_list_secrets_blocked_by_path_policy,
        test_admin_api_read_secret_blocked_by_path_policy,
        test_admin_api_write_secret_blocked_by_path_policy,
        test_admin_api_delete_secret_blocked_by_path_policy,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t(); passed += 1
        except Exception as e:
            print(f"  ❌ {t.__name__}: {e}"); failed += 1
    print(f"\n{'=' * 50}")
    print(f"  {'✅' if not failed else '❌'} {passed}/{passed+failed} tests passent")
    print(f"{'=' * 50}")
    sys.exit(0 if not failed else 1)
