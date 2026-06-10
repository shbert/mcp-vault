#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests CLI vault — comportementaux (non-complaisant).

Vérifie que chaque commande vault appelle le bon outil MCP avec les bons
arguments. Utilise run_cli_mocked() qui intercepte MCPClient.call_tool.

Usage :
    python -m pytest tests/cli/test_vault.py -v
"""

import pytest

from . import (
    banner, section, check, check_value, check_contains,
    run_cli, run_cli_mocked,
)

# ─── Réponses de référence ────────────────────────────────────────────────────

_VAULT_CREATED = {"status": "created", "vault_id": "test-vault", "description": "Test"}
_VAULT_LIST    = {"status": "ok", "vaults": [{"vault_id": "test-vault", "description": "Test", "created_by": "admin", "secrets_count": 3}]}
_VAULT_INFO    = {"status": "ok", "vault_id": "test-vault", "description": "Test", "secrets_count": 3}
_VAULT_UPDATED = {"status": "ok", "vault_id": "test-vault"}
_VAULT_DELETED = {"status": "deleted", "vault_id": "test-vault"}


def test_vault():
    """Tests comportementaux vault — vérifie les appels MCPClient réels."""

    banner("CLI — Vault : tests comportementaux (non-complaisant)")

    # ── Aide ─────────────────────────────────────────────────────────────────
    section("Aide vault")
    r = run_cli(["vault", "--help"])
    check_value("vault --help exit code", r.exit_code, 0)
    for subcmd in ["create", "list", "info", "update", "delete"]:
        check_contains(f"Sous-commande '{subcmd}' visible", r.output, subcmd)

    # ── vault create ─────────────────────────────────────────────────────────
    section("vault create — appelle vault_create avec vault_id et description")
    r, mock = run_cli_mocked(
        ["vault", "create", "test-vault", "-d", "Test"],
        _VAULT_CREATED,
    )
    check_value("Exit code", r.exit_code, 0)
    check(
        "vault_create appelé avec les bons args",
        mock.call_args is not None and
        mock.call_args[0][0] == "vault_create" and
        mock.call_args[0][1].get("vault_id") == "test-vault" and
        mock.call_args[0][1].get("description") == "Test",
        f"call_args={mock.call_args}",
    )

    section("vault create sans description — description vide par défaut")
    r, mock = run_cli_mocked(["vault", "create", "test-vault"], _VAULT_CREATED)
    check_value("Exit code", r.exit_code, 0)
    check(
        "vault_create appelé — description vide par défaut",
        mock.call_args is not None and mock.call_args[0][1].get("description", "") == "",
        f"call_args={mock.call_args}",
    )

    # ── vault list ───────────────────────────────────────────────────────────
    section("vault list — appelle vault_list")
    r, mock = run_cli_mocked(["vault", "list"], _VAULT_LIST)
    check_value("Exit code", r.exit_code, 0)
    check("vault_list appelé", mock.call_args is not None and mock.call_args[0][0] == "vault_list")

    # ── vault info ───────────────────────────────────────────────────────────
    section("vault info — appelle vault_info avec vault_id")
    r, mock = run_cli_mocked(["vault", "info", "test-vault"], _VAULT_INFO)
    check_value("Exit code", r.exit_code, 0)
    check(
        "vault_info appelé avec vault_id correct",
        mock.call_args is not None and
        mock.call_args[0][0] == "vault_info" and
        mock.call_args[0][1].get("vault_id") == "test-vault",
        f"call_args={mock.call_args}",
    )

    # ── vault update ─────────────────────────────────────────────────────────
    section("vault update — appelle vault_update avec description")
    r, mock = run_cli_mocked(
        ["vault", "update", "test-vault", "-d", "Nouvelle desc"],
        _VAULT_UPDATED,
    )
    check_value("Exit code", r.exit_code, 0)
    check(
        "vault_update appelé avec vault_id et description",
        mock.call_args is not None and
        mock.call_args[0][0] == "vault_update" and
        mock.call_args[0][1].get("vault_id") == "test-vault" and
        "Nouvelle desc" in mock.call_args[0][1].get("description", ""),
        f"call_args={mock.call_args}",
    )

    # ── vault delete ─────────────────────────────────────────────────────────
    section("vault delete sans --yes — click.confirm abort (exit 1), call_tool NON appelé")
    r, mock = run_cli_mocked(["vault", "delete", "test-vault"], _VAULT_DELETED)
    check_value("Exit code 1 (abort)", r.exit_code, 1)
    check(
        "vault_delete NON appelé sans confirmation",
        not mock.called,
        f"call_tool a été appelé alors qu'il ne devrait pas : {mock.call_args}",
    )

    section("vault delete --yes — appelle vault_delete avec confirm=True")
    r, mock = run_cli_mocked(["vault", "delete", "test-vault", "--yes"], _VAULT_DELETED)
    check_value("Exit code", r.exit_code, 0)
    check(
        "vault_delete appelé avec confirm=True",
        mock.call_args is not None and
        mock.call_args[0][0] == "vault_delete" and
        mock.call_args[0][1].get("vault_id") == "test-vault" and
        mock.call_args[0][1].get("confirm") is True,
        f"call_args={mock.call_args}",
    )

    # ── Erreur propagée ───────────────────────────────────────────────────────
    section("vault info — erreur serveur propagée sans crash CLI")
    r, mock = run_cli_mocked(
        ["vault", "info", "inexistant"],
        {"status": "error", "message": "Vault non trouvé"},
    )
    check_value("Exit code reste 0 même en erreur", r.exit_code, 0)
    check("vault_info bien appelé même en cas d'erreur", mock.called)
