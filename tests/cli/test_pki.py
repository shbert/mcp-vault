#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════
  TEST CLI — PKI CA : setup, ca-key, roles, role-info, certs, revoke, rotate
═══════════════════════════════════════════════════════════════
"""

from . import (
    banner, section, check, check_value, check_contains,
    run_cli,
)


def test_pki():
    """Teste toutes les commandes PKI CA du CLI (aide seulement — pas de vrai serveur)."""

    banner("CLI — PKI CA (setup, ca-key, roles, role-info, certs, revoke, rotate)")

    # ── pki --help ──
    section("Aide pki — groupe principal")
    r = run_cli(["pki", "--help"])
    check_value("pki --help exit code", r.exit_code, 0)
    check_contains("Mentionne 'PKI'", r.output, "PKI")
    for subcmd in ["setup", "ca-key", "roles", "role-info", "certs", "revoke", "rotate"]:
        check_contains(f"Sous-commande '{subcmd}' visible", r.output, subcmd)

    # ── pki setup --help ──
    section("Aide pki setup")
    r = run_cli(["pki", "setup", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Option --lab/--prod", r.output, "--lab")
    check_contains("Option --domains", r.output, "--domains")
    check_contains("Option --ttl", r.output, "--ttl")

    # ── pki ca-key --help ──
    section("Aide pki ca-key")
    r = run_cli(["pki", "ca-key", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Mentionne SHA-256 ou PEM", r.output, "SHA-256")

    # ── pki roles --help ──
    section("Aide pki roles")
    r = run_cli(["pki", "roles", "--help"])
    check_value("Exit code", r.exit_code, 0)

    # ── pki role-info --help ──
    section("Aide pki role-info")
    r = run_cli(["pki", "role-info", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Argument ROLE_NAME", r.output, "ROLE_NAME")

    # ── pki certs --help ──
    section("Aide pki certs")
    r = run_cli(["pki", "certs", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Option --limit", r.output, "--limit")
    check_contains("Option --offset", r.output, "--offset")

    # ── pki revoke --help ──
    section("Aide pki revoke")
    r = run_cli(["pki", "revoke", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Argument SERIAL_NUMBER", r.output, "SERIAL_NUMBER")

    # ── pki rotate --help ──
    section("Aide pki rotate")
    r = run_cli(["pki", "rotate", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Option --keep-old/--no-keep-old", r.output, "--keep-old")
    check_contains("Option --overlap", r.output, "--overlap")

    # ── Rendu simulé pki setup ──
    section("Rendu simulé — pki setup (ok)")
    from scripts.cli.display import show_pki_result
    from io import StringIO
    import sys
    # Ne doit pas lever d'exception
    show_pki_result({
        "status": "ok",
        "lab_mode": True,
        "root_mount": "_sys_pki_root",
        "int_mount": "_sys_pki_int",
        "acme_directory": "https://vault.example.com/acme/directory",
        "root_pem_url": "https://vault.example.com/pki/ca/root.pem",
        "chain_pem_url": "https://vault.example.com/pki/ca/chain.pem",
        "crl_url": "https://vault.example.com/pki/ca/crl.pem",
        "root_expires": "2036-06-10T00:00:00+00:00",
        "root_fingerprint_sha256": "AA:BB:CC:DD",
        "allowed_domains": ["*.lesur.lan", "lesur.lan"],
        "leaf_ttl": "720h",
        "eab_required": False,
        "s3_sync_ok": True,
    })
    check("Rendu setup sans exception", True)

    # ── Rendu simulé inventaire certs ──
    section("Rendu simulé — pki certs")
    show_pki_result({
        "status": "ok",
        "total": 2,
        "offset": 0,
        "limit": 100,
        "certs": [
            {"serial": "12:34:ab:cd", "sans": ["test.lesur.lan"], "not_after": "2026-12-01T00:00:00+00:00", "revoked": False},
            {"serial": "56:78:ef:01", "sans": ["*.lesur.lan"], "not_after": "2026-09-15T00:00:00+00:00", "revoked": True},
        ],
    })
    check("Rendu certs sans exception", True)

    # ── Rendu simulé révocation ──
    section("Rendu simulé — pki revoke")
    show_pki_result({
        "status": "ok",
        "serial_number": "12:34:ab:cd",
        "revocation_time": 1234567890,
        "crl_updated": True,
        "s3_sync_ok": True,
    })
    check("Rendu revoke sans exception", True)

    # ── Rendu erreur ──
    section("Rendu erreur PKI")
    show_pki_result({"status": "error", "message": "PKI non initialisée"})
    check("Rendu error sans exception", True)
