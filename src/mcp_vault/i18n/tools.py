# -*- coding: utf-8 -*-
"""
Descriptions multilingues des outils MCP (en|de|fr).

La description servie à l'agent IA pour choisir l'outil est sélectionnée par
le réglage `vault_lang` (défaut: en). Le français reste la source historique
(docstrings dans server.py) ; en/de en sont des traductions fidèles.

Glossaire : les noms produits restent en anglais dans toutes les langues —
Vault, Token, Policy, Secret, SSH CA, PKI, TLS, ACME, CA, MCP, JWT, S3.
"""

TOOL_DESCRIPTIONS = {
    # ─────────────────────────────────────────────────────────────────
    "en": {
        "system_health": "Check the health of the MCP Vault service. Tests OpenBao and S3 connectivity and returns the status of each backend.",
        "system_about": "Return information about the MCP Vault service: version, available tools, and system info.",
        "vault_create": "Create a new Vault (secret store, KV v2 mount in OpenBao) identified by a unique vault_id.",
        "vault_list": "List all Vaults (secret stores) accessible to the current Token, with owner-based isolation.",
        "vault_info": "Return detailed information about a single Vault.",
        "vault_update": "Update a Vault's metadata (its description).",
        "vault_delete": "Delete a Vault and ALL of its secrets. Irreversible; requires confirm=True and admin permission.",
        "secret_write": "Write a typed secret into a Vault. Supported types: login, password, secure_note, api_key, ssh_key, database, server, certificate, env_file, credit_card, identity, wifi, crypto_wallet, custom. Supports tags and a favorite flag.",
        "secret_read": "Read a secret from a Vault, optionally a specific version (0 = latest).",
        "secret_list": "List the secrets in a Vault, optionally filtered by a path prefix.",
        "secret_delete": "Delete a secret and all of its versions.",
        "secret_wrap": "Create a single-use wrap Token for a (vault_id, secret_path) scoped to a JIT mission. The plaintext secret never transits; OpenBao cubbyhole guarantees single-use. The returned wrap_token is sensitive and must never be logged.",
        "secret_revoke_wrap": "Revoke a wrap Token idempotently. An unknown or already-revoked lease_id is treated as success; only network or 5xx errors are hard failures.",
        "secret_wrap_lookup": "Find and revoke wrap Tokens created with a given operation_id, used to compensate orphaned provisions after a broker crash. Idempotent.",
        "secret_consume": "Release a secret by validating the mission identity (anti-confused-deputy C18). Validates the mission_token JWT (ES256/JWKS), checks registry bindings (mission_id, tenant_id, aud), then unwraps the OpenBao cubbyhole. wrap_token and mission_token are never logged or returned.",
        "secret_types": "List all available secret types (1Password-style) with their required and optional fields (14 types).",
        "secret_generate_password": "Generate a cryptographically secure password (CSPRNG) with configurable length and character classes (uppercase, lowercase, digits, symbols, exclusions).",
        "policy_create": "Create a new MCP Policy for granular access control. A Policy defines which MCP tools are allowed/denied (wildcards supported, denied takes priority) and per-Vault path permissions. Assignable to a Token. Admin only.",
        "policy_list": "List all MCP Policies with a summary of each (ID, description, counters). Admin only.",
        "policy_get": "Return the full details of an MCP Policy (allowed_tools, denied_tools, path_rules). Admin only.",
        "policy_delete": "Delete an MCP Policy. Irreversible; Tokens referencing it lose their restriction. Requires confirm=True. Admin only.",
        "ssh_ca_setup": "Configure an SSH CA role in a Vault, defining allowed users, default user, and certificate TTL.",
        "ssh_sign_key": "Sign an SSH public key with the Vault's SSH CA, producing a short-lived certificate.",
        "ssh_ca_public_key": "Retrieve the SSH CA public key, used to configure the target servers (TrustedUserCAKeys).",
        "ssh_ca_list_roles": "List the SSH CA roles configured in a Vault (allowed users, TTL, extensions).",
        "ssh_ca_role_info": "Return the details of a single SSH CA role (TTL, allowed_users, extensions).",
        "pki_ca_setup": "Set up the full internal PKI (root CA + intermediate CA + ACME server). Idempotent. In lab mode the root is self-signed; in prod generate a CSR (lab_mode=False) and import the signed cert.",
        "pki_ca_public_key": "Return the PKI root CA in PEM with its SHA-256 fingerprint and a stable URL, for httpx CA bundles and the Caddyfile.",
        "pki_ca_list_roles": "List the PKI issuance roles configured on the intermediate CA.",
        "pki_ca_role_info": "Return the details of a PKI issuance role (allowed domains, TTL, TLS flags).",
        "pki_list_certs": "Return a paginated inventory of issued certificates (serials, SANs, expiry, revocation status).",
        "pki_revoke_cert": "Revoke a certificate by serial number and force a CRL update. Admin only.",
        "pki_issue_cert": "Issue a server certificate signed by the intermediate CA (manual issuance, outside ACME). Admin only. The private key is returned ONCE and never stored or logged.",
        "pki_ca_rotate_intermediate": "Rotate the intermediate CA without downtime: generate a new CSR, sign with the root CA, import as new issuer. The old issuer stays valid if keep_old_issuer=True. Admin only.",
        "token_update": "Update an existing Token (policy, permissions, allowed Vaults). Only the provided non-empty fields change. Admin only.",
        "audit_log": "Query the audit log of all MCP operations, most recent first, with combinable filters (client, vault_id, tool with wildcards, category, status, since ISO date). Admin only.",
    },
    # ─────────────────────────────────────────────────────────────────
    "de": {
        "system_health": "Prüft den Zustand des MCP-Vault-Dienstes. Testet die OpenBao- und S3-Konnektivität und gibt den Status jedes Backends zurück.",
        "system_about": "Gibt Informationen zum MCP-Vault-Dienst zurück: Version, verfügbare Tools und Systeminfos.",
        "vault_create": "Erstellt einen neuen Vault (Secret-Speicher, KV-v2-Mount in OpenBao), identifiziert durch eine eindeutige vault_id.",
        "vault_list": "Listet alle für das aktuelle Token zugänglichen Vaults (Secret-Speicher) auf, mit besitzerbasierter Isolation.",
        "vault_info": "Gibt detaillierte Informationen zu einem einzelnen Vault zurück.",
        "vault_update": "Aktualisiert die Metadaten eines Vault (dessen Beschreibung).",
        "vault_delete": "Löscht einen Vault und ALLE seine Secrets. Unwiderruflich; erfordert confirm=True und Admin-Berechtigung.",
        "secret_write": "Schreibt ein typisiertes Secret in einen Vault. Unterstützte Typen: login, password, secure_note, api_key, ssh_key, database, server, certificate, env_file, credit_card, identity, wifi, crypto_wallet, custom. Unterstützt Tags und ein Favoriten-Flag.",
        "secret_read": "Liest ein Secret aus einem Vault, optional eine bestimmte Version (0 = neueste).",
        "secret_list": "Listet die Secrets in einem Vault auf, optional gefiltert nach einem Pfad-Präfix.",
        "secret_delete": "Löscht ein Secret und alle seine Versionen.",
        "secret_wrap": "Erstellt ein Single-Use-Wrap-Token für ein (vault_id, secret_path), an eine JIT-Mission gebunden. Das Klartext-Secret wird nie übertragen; OpenBao Cubbyhole garantiert die einmalige Nutzung. Das zurückgegebene wrap_token ist sensibel und darf niemals geloggt werden.",
        "secret_revoke_wrap": "Widerruft ein Wrap-Token idempotent. Eine unbekannte oder bereits widerrufene lease_id gilt als Erfolg; nur Netzwerk- oder 5xx-Fehler sind echte Fehler.",
        "secret_wrap_lookup": "Findet und widerruft mit einer bestimmten operation_id erstellte Wrap-Tokens, um verwaiste Provisionierungen nach einem Broker-Absturz zu kompensieren. Idempotent.",
        "secret_consume": "Gibt ein Secret frei und validiert dabei die Missions-Identität (Anti-Confused-Deputy C18). Validiert das mission_token-JWT (ES256/JWKS), prüft die Registry-Bindings (mission_id, tenant_id, aud) und entpackt dann das OpenBao Cubbyhole. wrap_token und mission_token werden nie geloggt oder zurückgegeben.",
        "secret_types": "Listet alle verfügbaren Secret-Typen (im 1Password-Stil) mit ihren erforderlichen und optionalen Feldern auf (14 Typen).",
        "secret_generate_password": "Generiert ein kryptografisch sicheres Passwort (CSPRNG) mit konfigurierbarer Länge und Zeichenklassen (Großbuchstaben, Kleinbuchstaben, Ziffern, Symbole, Ausschlüsse).",
        "policy_create": "Erstellt eine neue MCP-Policy für granulare Zugriffssteuerung. Eine Policy legt fest, welche MCP-Tools erlaubt/verboten sind (Wildcards unterstützt, Verbote haben Vorrang) sowie Pfad-Berechtigungen je Vault. Einem Token zuweisbar. Nur Admin.",
        "policy_list": "Listet alle MCP-Policies mit einer Zusammenfassung je Policy auf (ID, Beschreibung, Zähler). Nur Admin.",
        "policy_get": "Gibt die vollständigen Details einer MCP-Policy zurück (allowed_tools, denied_tools, path_rules). Nur Admin.",
        "policy_delete": "Löscht eine MCP-Policy. Unwiderruflich; Tokens, die sie referenzieren, verlieren ihre Einschränkung. Erfordert confirm=True. Nur Admin.",
        "ssh_ca_setup": "Konfiguriert eine SSH-CA-Rolle in einem Vault und definiert erlaubte Benutzer, Standardbenutzer und Zertifikats-TTL.",
        "ssh_sign_key": "Signiert einen öffentlichen SSH-Schlüssel mit der SSH CA des Vault und erzeugt ein kurzlebiges Zertifikat.",
        "ssh_ca_public_key": "Ruft den öffentlichen Schlüssel der SSH CA ab, zur Konfiguration der Zielserver (TrustedUserCAKeys).",
        "ssh_ca_list_roles": "Listet die in einem Vault konfigurierten SSH-CA-Rollen auf (erlaubte Benutzer, TTL, Erweiterungen).",
        "ssh_ca_role_info": "Gibt die Details einer einzelnen SSH-CA-Rolle zurück (TTL, allowed_users, Erweiterungen).",
        "pki_ca_setup": "Richtet die vollständige interne PKI ein (Root CA + Intermediate CA + ACME-Server). Idempotent. Im Lab-Modus ist die Root selbstsigniert; in Produktion einen CSR erzeugen (lab_mode=False) und das signierte Zertifikat importieren.",
        "pki_ca_public_key": "Gibt die PKI-Root-CA als PEM mit ihrem SHA-256-Fingerprint und einer stabilen URL zurück, für httpx-CA-Bundles und das Caddyfile.",
        "pki_ca_list_roles": "Listet die auf der Intermediate CA konfigurierten PKI-Ausstellungsrollen auf.",
        "pki_ca_role_info": "Gibt die Details einer PKI-Ausstellungsrolle zurück (erlaubte Domains, TTL, TLS-Flags).",
        "pki_list_certs": "Gibt ein paginiertes Inventar der ausgestellten Zertifikate zurück (Seriennummern, SANs, Ablauf, Widerrufsstatus).",
        "pki_revoke_cert": "Widerruft ein Zertifikat anhand der Seriennummer und erzwingt eine CRL-Aktualisierung. Nur Admin.",
        "pki_issue_cert": "Stellt ein Serverzertifikat aus, signiert von der Intermediate CA (manuelle Ausstellung, außerhalb von ACME). Nur Admin. Der private Schlüssel wird EINMAL zurückgegeben und nie gespeichert oder geloggt.",
        "pki_ca_rotate_intermediate": "Rotiert die Intermediate CA ohne Ausfallzeit: erzeugt einen neuen CSR, signiert mit der Root CA, importiert als neuen Issuer. Der alte Issuer bleibt gültig, wenn keep_old_issuer=True. Nur Admin.",
        "token_update": "Aktualisiert ein bestehendes Token (Policy, Berechtigungen, erlaubte Vaults). Nur die angegebenen, nicht-leeren Felder werden geändert. Nur Admin.",
        "audit_log": "Fragt das Audit-Log aller MCP-Operationen ab, neueste zuerst, mit kombinierbaren Filtern (client, vault_id, tool mit Wildcards, Kategorie, Status, since als ISO-Datum). Nur Admin.",
    },
    # ─────────────────────────────────────────────────────────────────
    "fr": {
        "system_health": "Vérifie l'état de santé du service MCP Vault. Teste la connectivité OpenBao et S3 et retourne le statut de chaque backend.",
        "system_about": "Retourne les informations du service MCP Vault : version, outils disponibles et infos système.",
        "vault_create": "Crée un nouveau Vault (coffre de secrets, mount KV v2 dans OpenBao) identifié par un vault_id unique.",
        "vault_list": "Liste tous les Vaults (coffres de secrets) accessibles par le Token courant, avec isolation owner-based.",
        "vault_info": "Retourne les informations détaillées d'un Vault.",
        "vault_update": "Met à jour les métadonnées d'un Vault (sa description).",
        "vault_delete": "Supprime un Vault et TOUS ses secrets. Irréversible ; nécessite confirm=True et la permission admin.",
        "secret_write": "Écrit un secret typé dans un Vault. Types disponibles : login, password, secure_note, api_key, ssh_key, database, server, certificate, env_file, credit_card, identity, wifi, crypto_wallet, custom. Supporte tags et favori.",
        "secret_read": "Lit un secret depuis un Vault, éventuellement une version spécifique (0 = dernière).",
        "secret_list": "Liste les secrets d'un Vault, éventuellement filtrés par un préfixe de chemin.",
        "secret_delete": "Supprime un secret et toutes ses versions.",
        "secret_wrap": "Crée un wrap Token single-use pour un couple (vault_id, secret_path) scopé à une mission JIT. Le secret en clair ne transite jamais ; le cubbyhole OpenBao garantit le single-use. Le wrap_token retourné est sensible et ne doit jamais être loggué.",
        "secret_revoke_wrap": "Révoque un wrap Token de façon idempotente. Un lease_id introuvable ou déjà révoqué est un succès ; seules les erreurs réseau ou 5xx sont des échecs durs.",
        "secret_wrap_lookup": "Retrouve et révoque les wrap Tokens créés avec un operation_id donné, pour compenser les provisions orphelines après un crash du broker. Idempotent.",
        "secret_consume": "Libère un secret en validant l'identité de mission (anti-confused-deputy C18). Valide le JWT mission_token (ES256/JWKS), vérifie les bindings registry (mission_id, tenant_id, aud), puis unwrap le cubbyhole OpenBao. wrap_token et mission_token ne sont jamais loggués ni retournés.",
        "secret_types": "Liste tous les types de secrets disponibles (style 1Password) avec leurs champs requis et optionnels (14 types).",
        "secret_generate_password": "Génère un mot de passe cryptographiquement sûr (CSPRNG) avec longueur et classes de caractères configurables (majuscules, minuscules, chiffres, symboles, exclusions).",
        "policy_create": "Crée une nouvelle Policy MCP pour un contrôle d'accès granulaire. Une Policy définit quels outils MCP sont autorisés/refusés (wildcards supportés, le refus prime) et les permissions de chemin par Vault. Assignable à un Token. Admin requis.",
        "policy_list": "Liste toutes les Policies MCP avec un résumé de chacune (ID, description, compteurs). Admin requis.",
        "policy_get": "Retourne les détails complets d'une Policy MCP (allowed_tools, denied_tools, path_rules). Admin requis.",
        "policy_delete": "Supprime une Policy MCP. Irréversible ; les Tokens qui la référencent perdent leur restriction. Nécessite confirm=True. Admin requis.",
        "ssh_ca_setup": "Configure un rôle SSH CA dans un Vault, définissant les utilisateurs autorisés, l'utilisateur par défaut et le TTL des certificats.",
        "ssh_sign_key": "Signe une clé publique SSH avec la SSH CA du Vault, produisant un certificat à durée de vie courte.",
        "ssh_ca_public_key": "Récupère la clé publique de la SSH CA, pour configurer les serveurs cibles (TrustedUserCAKeys).",
        "ssh_ca_list_roles": "Liste les rôles SSH CA configurés dans un Vault (utilisateurs autorisés, TTL, extensions).",
        "ssh_ca_role_info": "Retourne les détails d'un rôle SSH CA (TTL, allowed_users, extensions).",
        "pki_ca_setup": "Configure la PKI interne complète (CA racine + intermédiaire + serveur ACME). Idempotent. En lab la racine est self-signed ; en prod générer un CSR (lab_mode=False) et importer le certificat signé.",
        "pki_ca_public_key": "Retourne la CA racine PKI en PEM avec son empreinte SHA-256 et une URL stable, pour les bundles CA httpx et le Caddyfile.",
        "pki_ca_list_roles": "Liste les rôles d'émission PKI configurés sur la CA intermédiaire.",
        "pki_ca_role_info": "Retourne les détails d'un rôle d'émission PKI (domaines autorisés, TTL, flags TLS).",
        "pki_list_certs": "Retourne un inventaire paginé des certificats émis (serials, SANs, expiration, statut de révocation).",
        "pki_revoke_cert": "Révoque un certificat par son numéro de série et force la mise à jour de la CRL. Admin requis.",
        "pki_issue_cert": "Émet un certificat serveur signé par la CA intermédiaire (émission manuelle, hors ACME). Admin requis. La clé privée est retournée UNE FOIS et n'est jamais stockée ni journalisée.",
        "pki_ca_rotate_intermediate": "Effectue la rotation sans coupure de la CA intermédiaire : génère un nouveau CSR, signe avec la CA racine, importe comme nouvel issuer. L'ancien issuer reste valide si keep_old_issuer=True. Admin requis.",
        "token_update": "Met à jour un Token existant (policy, permissions, Vaults autorisés). Seuls les champs fournis (non vides) sont modifiés. Admin requis.",
        "audit_log": "Consulte le journal d'audit de toutes les opérations MCP, plus récentes en premier, avec filtres combinables (client, vault_id, tool avec wildcards, catégorie, statut, since en date ISO). Admin requis.",
    },
}


def tool_description(name: str, lang: str) -> str:
    """
    Retourne la description de l'outil `name` dans la langue `lang`.

    Fallback : langue demandée → en → fr → nom de l'outil.
    """
    by_lang = TOOL_DESCRIPTIONS.get(lang) or {}
    return (
        by_lang.get(name)
        or TOOL_DESCRIPTIONS["en"].get(name)
        or TOOL_DESCRIPTIONS["fr"].get(name)
        or name
    )
