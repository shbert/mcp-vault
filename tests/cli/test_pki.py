#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests CLI PKI — comportementaux (non-complaisant).

Vérifie que chaque commande pki appelle le bon outil MCP avec les bons
arguments. Utilise run_cli_mocked() qui intercepte MCPClient.call_tool.
"""

import pytest

from . import (
    banner, section, check, check_value, check_contains,
    run_cli, run_cli_mocked,
)

_PKI_SETUP_OK = {
    "status": "ok", "lab_mode": True,
    "root_mount": "_sys_pki_root", "int_mount": "_sys_pki_int",
    "acme_directory": "https://vault.example.com/acme/directory",
    "root_pem_url": "https://vault.example.com/pki/ca/root.pem",
    "chain_pem_url": "https://vault.example.com/pki/ca/chain.pem",
    "crl_url": "https://vault.example.com/pki/ca/crl.pem",
    "root_expires": "2036-06-10T00:00:00+00:00",
    "root_fingerprint_sha256": "AA:BB:CC:DD",
    "allowed_domains": ["*.lesur.lan", "lesur.lan"],
    "leaf_ttl": "720h", "eab_required": False, "s3_sync_ok": True,
}
_PKI_CA_KEY_OK = {
    "status": "ok", "pem": "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----",
    "sha256_fingerprint": "AA:BB:CC", "expires": "2036-06-10T00:00:00+00:00",
    "url": "https://vault.example.com/pki/ca/root.pem", "usage": "Ajouter dans trust store",
}
_PKI_ROLES_OK   = {"status": "ok", "roles": ["acme-servers"], "count": 1}
_PKI_ROLE_INFO  = {"status": "ok", "role_name": "acme-servers", "allowed_domains": ["*.lesur.lan"], "max_ttl": "720h", "server_flag": True, "client_flag": False, "allow_ip_sans": False, "allow_localhost": False, "allow_subdomains": True, "allow_wildcard_certificates": True, "key_type": "rsa", "key_bits": 2048}
_PKI_CERTS_OK   = {"status": "ok", "total": 2, "offset": 0, "limit": 100, "certs": [{"serial": "12:34:ab:cd", "sans": ["test.lesur.lan"], "not_after": "2026-12-01T00:00:00+00:00", "revoked": False}]}
_PKI_REVOKE_OK  = {"status": "ok", "serial_number": "12:34:ab:cd", "revocation_time": 1234567890, "crl_updated": True, "s3_sync_ok": True}
_PKI_ROTATE_OK  = {"status": "ok", "old_issuer_id": "old-uuid", "new_issuer_id": "new-uuid", "new_expires": "2028-06-10T00:00:00+00:00", "keep_old_issuer": True, "overlap_ttl": "48h", "s3_sync_ok": True}


def test_pki():
    """Tests comportementaux PKI CA — vérifie les appels MCPClient réels."""

    banner("CLI — PKI CA : tests comportementaux (non-complaisant)")

    # ── Aide ─────────────────────────────────────────────────────────────────
    section("Aide pki")
    r = run_cli(["pki", "--help"])
    check_value("pki --help exit code", r.exit_code, 0)
    for subcmd in ["setup", "ca-key", "roles", "role-info", "certs", "revoke", "rotate"]:
        check_contains(f"Sous-commande '{subcmd}'", r.output, subcmd)

    # ── pki setup ────────────────────────────────────────────────────────────
    section("pki setup --lab — appelle pki_ca_setup avec lab_mode=True")
    r, mock = run_cli_mocked(
        ["pki", "setup", "--lab", "--domains", "*.lesur.lan,lesur.lan", "--ttl", "720h"],
        _PKI_SETUP_OK,
    )
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("pki_ca_setup appelé", mock.call_args is not None and mock.call_args[0][0] == "pki_ca_setup")
    check_value("lab_mode=True", args.get("lab_mode"), True)
    check_value("allowed_domains correct", args.get("allowed_domains"), "*.lesur.lan,lesur.lan")
    check_value("leaf_ttl correct", args.get("leaf_ttl"), "720h")

    section("pki setup --prod — lab_mode=False")
    r, mock = run_cli_mocked(
        ["pki", "setup", "--prod", "--domains", "mcp.cloud-temple.app"],
        _PKI_SETUP_OK,
    )
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check_value("lab_mode=False pour --prod", args.get("lab_mode"), False)

    # ── pki ca-key ───────────────────────────────────────────────────────────
    section("pki ca-key — appelle pki_ca_public_key sans args")
    r, mock = run_cli_mocked(["pki", "ca-key"], _PKI_CA_KEY_OK)
    check_value("Exit code", r.exit_code, 0)
    check("pki_ca_public_key appelé", mock.call_args is not None and mock.call_args[0][0] == "pki_ca_public_key")
    check_value("Aucun argument passé", mock.call_args[0][1], {})

    # ── pki roles ────────────────────────────────────────────────────────────
    section("pki roles — appelle pki_ca_list_roles sans args")
    r, mock = run_cli_mocked(["pki", "roles"], _PKI_ROLES_OK)
    check_value("Exit code", r.exit_code, 0)
    check("pki_ca_list_roles appelé", mock.call_args is not None and mock.call_args[0][0] == "pki_ca_list_roles")

    # ── pki role-info ─────────────────────────────────────────────────────────
    section("pki role-info acme-servers — appelle pki_ca_role_info")
    r, mock = run_cli_mocked(["pki", "role-info", "acme-servers"], _PKI_ROLE_INFO)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("pki_ca_role_info appelé", mock.call_args is not None and mock.call_args[0][0] == "pki_ca_role_info")
    check_value("role_name correct", args.get("role_name"), "acme-servers")

    # ── pki certs ────────────────────────────────────────────────────────────
    section("pki certs — appelle pki_list_certs avec limit/offset par défaut")
    r, mock = run_cli_mocked(["pki", "certs"], _PKI_CERTS_OK)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("pki_list_certs appelé", mock.call_args is not None and mock.call_args[0][0] == "pki_list_certs")
    check_value("limit défaut = 100", args.get("limit"), 100)
    check_value("offset défaut = 0", args.get("offset"), 0)

    section("pki certs --limit 20 --offset 40 — pagination transmise")
    r, mock = run_cli_mocked(["pki", "certs", "--limit", "20", "--offset", "40"], _PKI_CERTS_OK)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check_value("limit=20 transmis", args.get("limit"), 20)
    check_value("offset=40 transmis", args.get("offset"), 40)

    section("pki certs --limit abc — rejeté par Click (type=int)")
    r = run_cli(["pki", "certs", "--limit", "abc"])
    check_value("Exit code 2 pour type invalide", r.exit_code, 2)

    # ── pki revoke ───────────────────────────────────────────────────────────
    section("pki revoke <serial> — appelle pki_revoke_cert")
    r, mock = run_cli_mocked(["pki", "revoke", "12:34:ab:cd:ef:12:34:56"], _PKI_REVOKE_OK)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("pki_revoke_cert appelé", mock.call_args is not None and mock.call_args[0][0] == "pki_revoke_cert")
    check_value("serial_number transmis", args.get("serial_number"), "12:34:ab:cd:ef:12:34:56")

    # ── pki rotate ───────────────────────────────────────────────────────────
    section("pki rotate — appelle pki_ca_rotate_intermediate avec keep_old=True par défaut")
    r, mock = run_cli_mocked(["pki", "rotate"], _PKI_ROTATE_OK)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("pki_ca_rotate_intermediate appelé", mock.call_args is not None and mock.call_args[0][0] == "pki_ca_rotate_intermediate")
    check_value("keep_old_issuer=True par défaut", args.get("keep_old_issuer"), True)
    check_value("overlap_ttl défaut = '48h'", args.get("overlap_ttl"), "48h")

    section("pki rotate --no-keep-old — keep_old_issuer=False transmis")
    r, mock = run_cli_mocked(["pki", "rotate", "--no-keep-old"], _PKI_ROTATE_OK)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check_value("keep_old_issuer=False transmis", args.get("keep_old_issuer"), False)

    # ── Erreur propagée ───────────────────────────────────────────────────────
    section("pki ca-key — erreur 'PKI non initialisée' propagée sans crash")
    r, mock = run_cli_mocked(
        ["pki", "ca-key"],
        {"status": "error", "message": "PKI non initialisée — appelez pki_ca_setup"},
    )
    check_value("Exit code 0 même en erreur", r.exit_code, 0)
    check("pki_ca_public_key bien appelé", mock.called)
