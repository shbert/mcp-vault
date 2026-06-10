#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests CLI secret — comportementaux (non-complaisant).

Vérifie que chaque commande secret appelle le bon outil MCP avec les bons
arguments. Utilise run_cli_mocked() qui intercepte MCPClient.call_tool.
"""

import pytest

from . import (
    banner, section, check, check_value, check_contains,
    run_cli, run_cli_mocked,
)

_SECRET_WRITTEN  = {"status": "ok", "vault_id": "mon-vault", "path": "db/postgres", "version": 1}
_SECRET_READ     = {"status": "ok", "vault_id": "mon-vault", "path": "db/postgres", "data": {"host": "db.ct.com", "username": "admin"}, "version": 1}
_SECRET_LIST     = {"status": "ok", "vault_id": "mon-vault", "keys": ["db/postgres", "db/mysql"]}
_SECRET_DELETED  = {"status": "ok", "vault_id": "mon-vault", "path": "db/postgres"}
_SECRET_TYPES    = {"status": "ok", "types": [{"name": "login"}, {"name": "database"}]}
_SECRET_PASSWORD = {"status": "ok", "password": "Xk9#mP2!", "length": 32}


def test_secret():
    """Tests comportementaux secret — vérifie les appels MCPClient réels."""

    banner("CLI — Secrets : tests comportementaux (non-complaisant)")

    # ── Aide ─────────────────────────────────────────────────────────────────
    section("Aide secret")
    r = run_cli(["secret", "--help"])
    check_value("secret --help exit code", r.exit_code, 0)
    for subcmd in ["write", "read", "list", "delete", "types", "password"]:
        check_contains(f"Sous-commande '{subcmd}'", r.output, subcmd)

    # ── secret write ─────────────────────────────────────────────────────────
    section("secret write — appelle secret_write avec vault_id, path, data, type")
    r, mock = run_cli_mocked(
        ["secret", "write", "mon-vault", "db/postgres",
         "-d", '{"host":"db.ct.com","username":"admin"}', "-t", "database"],
        _SECRET_WRITTEN,
    )
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_write appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_write")
    check_value("vault_id correct", args.get("vault_id"), "mon-vault")
    check_value("path correct", args.get("path"), "db/postgres")
    check_value("secret_type correct", args.get("secret_type"), "database")  # param = secret_type, pas type
    check("data transmis", isinstance(args.get("data"), dict) and "host" in args.get("data", {}))

    section("secret write avec JSON invalide — rejeté avant appel MCP")
    r, mock = run_cli_mocked(
        ["secret", "write", "mon-vault", "db/test", "-d", "pas_du_json"],
        _SECRET_WRITTEN,
    )
    check_value("Exit code 0 (erreur affichée proprement)", r.exit_code, 0)
    check("secret_write NON appelé pour JSON invalide", not mock.called)

    # ── secret read ──────────────────────────────────────────────────────────
    section("secret read — appelle secret_read avec vault_id et path")
    r, mock = run_cli_mocked(["secret", "read", "mon-vault", "db/postgres"], _SECRET_READ)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_read appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_read")
    check_value("vault_id correct", args.get("vault_id"), "mon-vault")
    check_value("path correct", args.get("path"), "db/postgres")

    section("secret read -v 2 — version transmise")
    r, mock = run_cli_mocked(["secret", "read", "mon-vault", "db/postgres", "-v", "2"], _SECRET_READ)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check_value("version=2 transmise", args.get("version"), 2)

    # ── secret list ───────────────────────────────────────────────────────────
    section("secret list — appelle secret_list avec vault_id")
    r, mock = run_cli_mocked(["secret", "list", "mon-vault"], _SECRET_LIST)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_list appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_list")
    check_value("vault_id correct", args.get("vault_id"), "mon-vault")

    # ── secret delete ─────────────────────────────────────────────────────────
    section("secret delete sans --yes — click.confirm abort (exit 1), call_tool NON appelé")
    r, mock = run_cli_mocked(["secret", "delete", "mon-vault", "db/postgres"], _SECRET_DELETED)
    check_value("Exit code 1 (abort)", r.exit_code, 1)
    check("secret_delete NON appelé sans confirmation", not mock.called)

    section("secret delete --yes — appelle secret_delete")
    r, mock = run_cli_mocked(["secret", "delete", "mon-vault", "db/postgres", "--yes"], _SECRET_DELETED)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_delete appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_delete")
    check_value("vault_id correct", args.get("vault_id"), "mon-vault")
    check_value("path correct", args.get("path"), "db/postgres")

    # ── secret types ──────────────────────────────────────────────────────────
    section("secret types — appelle secret_types sans args")
    r, mock = run_cli_mocked(["secret", "types"], _SECRET_TYPES)
    check_value("Exit code", r.exit_code, 0)
    check("secret_types appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_types")
    check_value("Aucun argument passé", mock.call_args[0][1], {})

    # ── secret password ───────────────────────────────────────────────────────
    section("secret password -l 32 — appelle secret_generate_password avec length=32")
    r, mock = run_cli_mocked(["secret", "password", "-l", "32"], _SECRET_PASSWORD)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_generate_password appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_generate_password")
    check_value("length=32 transmis", args.get("length"), 32)

    section("secret password — longueur défaut (sans -l)")
    r, mock = run_cli_mocked(["secret", "password"], _SECRET_PASSWORD)
    check_value("Exit code", r.exit_code, 0)
    check("secret_generate_password appelé", mock.called)

    # ── Erreur propagée ───────────────────────────────────────────────────────
    section("secret read — erreur propagée sans crash")
    r, mock = run_cli_mocked(
        ["secret", "read", "vault-inexistant", "path/inexistante"],
        {"status": "error", "message": "Vault non trouvé"},
    )
    check_value("Exit code 0 même en erreur", r.exit_code, 0)
    check("secret_read bien appelé", mock.called)
