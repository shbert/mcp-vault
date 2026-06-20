# 🔐 MCP Vault

> **Sichere Secret-Verwaltung für KI-Agenten — eingebettetes OpenBao**

> 🇫🇷 [Français](README.md) · 🇬🇧 [English](README.en.md)

MCP Vault ist ein [MCP](https://modelcontextprotocol.io/)-Server, der einen Secret-Tresor für KI-Agenten und Missionen bereitstellt. Er bettet [OpenBao](https://openbao.org/) (Open-Source-Fork von HashiCorp Vault, Linux Foundation) als Verschlüsselungs-Engine ein.

**Denken Sie an 1Password, aber für Ihre KI-Agenten.**

### 📸 Administrationskonsole

|               Dashboard                |          Vaults & Secrets           |          Audit & Alerts            |
| :------------------------------------: | :---------------------------------: | :--------------------------------: |
| ![Dashboard](screenshoots/screen1.png) | ![Vaults](screenshoots/screen2.png) | ![Audit](screenshoots/screen3.png) |

---

## 📖 Dokumentation

| Dokument                                                | Beschreibung                                                                                                                                                                  |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**ARCHITECTURE.md**](DESIGN/mcp-vault/ARCHITECTURE.md) | Vollständige Spezifikation — Vision, 6-schichtige ASGI-Architektur, Vaults, SSH CA, MCP-Policies (6 einsatzbereite Beispiele), Sicherheit der Unseal-Keys (3 Faktoren), HSM-Roadmap |
| [**TECHNICAL.md**](DESIGN/mcp-vault/TECHNICAL.md)       | Technische Dokumentation — Quellmodule (inkl. PKI v0.5.1), 6-schichtiger ASGI-Stack, Docker, Tests, Abhängigkeiten, Roadmap                                                   |
| [**SECURITY_AUDIT.md**](DESIGN/mcp-vault/SECURITY_AUDIT.md) | Konsolidierter Sicherheitsaudit-Bericht — 60 Findings V2.1, 28 behoben, 13 dokumentierte Restrisiken                                                                       |
| [**scripts/README.md**](scripts/README.md)              | Vollständiger CLI-Leitfaden — 7 Befehlsgruppen, interaktive Shell, Beispiele                                                                                                   |
| [**tests/README.md**](tests/README.md)                  | Leitfaden zur Testausführung — 4 Stufen, ~600 Tests, Befehle für Auditoren                                                                                                    |
| [**TEST_CATALOG.md**](tests/TEST_CATALOG.md)            | e2e-Testkatalog — 15 Kategorien, 312 Assertions, Zweck jedes Abschnitts (für Auditoren)                                                                                       |

---

## ⚡ Schnellstart

```bash
# 1. Klonen und konfigurieren
cp .env.example .env
# S3-Credentials in .env anpassen

# 2. Build und Start
docker compose build
docker compose up -d

# 3. Prüfen (aus dem Container)
docker compose exec mcp-vault python scripts/mcp_cli.py health

# 4. Testen (312 e2e-Tests)
docker compose exec mcp-vault python tests/test_e2e.py
```

### Automatischer Lifecycle

Beim Start führt MCP Vault Folgendes aus:
1. Lädt Tokens aus S3
2. Stellt OpenBao-Daten wieder her (Docker-Volume oder S3)
3. Startet OpenBao, initialisiert es (beim ersten Mal) und entsperrt es
4. **Unseal-Keys**: verschlüsselt (AES-256-GCM) auf S3, niemals im Klartext auf der Festplatte — nur im Arbeitsspeicher
5. Aktiviert die periodische S3-Synchronisierung (60s)

Beim Herunterfahren (`docker compose stop`):
1. Versiegelt OpenBao 🔒
2. Abschließender Upload nach S3 📤
3. Beendet den Prozess — Keys werden aus dem Arbeitsspeicher gelöscht

---

## 🛠️ MCP-Tools (36)

### System (2)

| Tool            | Beschreibung                                      |
| --------------- | ------------------------------------------------- |
| `system_health` | Gesundheitsstatus (OpenBao + S3)                  |
| `system_about`  | Service-Informationen (Version, Tools, Plattform) |

> 💡 **Introspektion**: Der Endpunkt `/admin/api/whoami` und der CLI-Befehl `whoami` ermöglichen die Überprüfung von Identität und Berechtigungen des aktuellen Tokens.

### Vaults — Secret-Speicher (5)

| Tool                                   | Perm  | Beschreibung                                              |
| -------------------------------------- | ----- | -------------------------------------------------------- |
| `vault_create(vault_id, description?)` | write | Erstellt einen Vault (KV-v2-Mount) + Metadaten (Owner, Datum) |
| `vault_list()`                         | read  | Listet zugängliche Vaults auf (nach Token gefiltert)     |
| `vault_info(vault_id)`                 | read  | Vault-Details (Metadaten, secrets_count, Owner)          |
| `vault_update(vault_id, description)`  | write | Aktualisiert die Beschreibung eines Vaults               |
| `vault_delete(vault_id, confirm)`      | admin | Löscht einen Vault und alle seine Secrets ⚠️            |

### Secrets (6)

| Tool                                        | Perm  | Beschreibung                                       |
| ------------------------------------------- | ----- | -------------------------------------------------- |
| `secret_write(vault_id, path, data, type?)` | write | Schreibt ein typisiertes Secret                    |
| `secret_read(vault_id, path, version?)`     | read  | Liest ein Secret (neueste oder bestimmte Version)  |
| `secret_list(vault_id, path?)`              | read  | Listet die Keys eines Vaults auf                   |
| `secret_delete(vault_id, path)`             | write | Löscht ein Secret und alle seine Versionen         |
| `secret_types()`                            | read  | Listet die 14 Secret-Typen auf                     |
| `secret_generate_password(length?, ...)`    | read  | Generiert ein CSPRNG-Passwort                      |

### SSH Certificate Authority (5)

Jeder Vault verfügt über seine **eigene isolierte SSH CA** — die CAs sind zwischen Vaults kryptografisch verschieden. Ein von der CA eines Vaults signiertes Zertifikat funktioniert NICHT auf Servern, die für einen anderen Vault konfiguriert sind.

| Tool                                                 | Perm  | Beschreibung                                                |
| ---------------------------------------------------- | ----- | ----------------------------------------------------------- |
| `ssh_ca_setup(vault_id, role, allowed_users?, ttl?)` | write | Konfiguriert eine SSH CA + Rolle in einem Vault             |
| `ssh_sign_key(vault_id, role, public_key, ttl?)`     | read  | Signiert einen öffentlichen Schlüssel → kurzlebiges Zertifikat |
| `ssh_ca_public_key(vault_id)`                        | read  | Öffentlicher CA-Schlüssel (für `TrustedUserCAKeys` auf Servern) |
| `ssh_ca_list_roles(vault_id)`                        | read  | Listet die in einem Vault konfigurierten SSH-CA-Rollen auf  |
| `ssh_ca_role_info(vault_id, role)`                   | read  | Rollendetails (TTL, allowed_users, Extensions)              |

### MCP-Policies — granulare Zugriffskontrolle (4)

Policies schränken die pro Token zugänglichen Tools ein, mit Unterstützung für **Wildcards** (`system_*`, `ssh_*`...) und **Regeln pro Vault** (`prod-*` → nur Lesen).

| Tool                                                                                 | Perm  | Beschreibung                                         |
| ------------------------------------------------------------------------------------ | ----- | --------------------------------------------------- |
| `policy_create(policy_id, description?, allowed_tools?, denied_tools?, path_rules?)` | admin | Erstellt eine Policy mit Zugriffsregeln             |
| `policy_list()`                                                                      | admin | Listet Policies mit Zählern auf                     |
| `policy_get(policy_id)`                                                              | admin | Vollständige Details (allowed/denied tools, path_rules) |
| `policy_delete(policy_id, confirm)`                                                  | admin | Löscht eine Policy ⚠️                              |

> 📋 6 einsatzbereite Policies dokumentiert in [ARCHITECTURE.md §6.4.1](DESIGN/mcp-vault/ARCHITECTURE.md): `readonly`, `ssh-operator`, `developer`, `prod-reader-dev-writer`, `ci-cd-agent`, `security-auditor`

### Token Management (1)

| Tool                                                           | Perm  | Beschreibung                                            |
| -------------------------------------------------------------- | ----- | ------------------------------------------------------- |
| `token_update(hash_prefix, policy_id?, permissions?, vaults?)` | admin | Ändert ein bestehendes Token (Policy, Permissions, Vaults) |

### Interne PKI — CA + ACME (8) *(v0.5.0)*

Souveräne CA für das Ökosystem: Caddy-WAFs registrieren sich über ACME genau wie bei Let's Encrypt, jedoch auf einer internen, vom öffentlichen Netz isolierten CA. Einsetzbar im Labor (`*.lesur.lan`) und in air-gapped Produktionsumgebungen.

| Tool | Perm | Beschreibung |
| --- | --- | --- |
| `pki_ca_setup(lab_mode, allowed_domains, leaf_ttl)` | admin | Initialisiert Root- + Intermediate-CA + ACME-Rolle |
| `pki_ca_public_key()` | read | Root-CA-PEM, SHA-256-Fingerprint, stabile URL |
| `pki_ca_list_roles()` | read | Listet die Ausstellungsrollen auf |
| `pki_ca_role_info(role_name)` | read | Rollendetails (Domains, TTL, TLS-Flags) |
| `pki_list_certs(limit?, offset?)` | admin | Paginiertes Inventar der ausgestellten Zertifikate |
| `pki_issue_cert(common_name, ttl?, alt_names?, ip_sans?)` | admin | Manuelle Zertifikatsausstellung (außerhalb von ACME) — einmaliger privater Schlüssel |
| `pki_revoke_cert(serial_number)` | admin | Widerruf + CRL-Aktualisierung |
| `pki_ca_rotate_intermediate(keep_old_issuer?, overlap_ttl?)` | admin | Rotation der Intermediate-CA ohne Ausfallzeit |

> Öffentliche Endpunkte (ohne Auth, Standard ACME/PKI): `/acme/directory`, `/pki/ca/root.pem`, `/pki/ca/chain.pem`, `/pki/ca/crl.pem`
>
> **`PKI_BASE_URL`** (optional): Basis-URL für die CDPs und den OpenBao-ACME-Cluster-Pfad. Leer = abgeleitet aus `MCP_ALLOWED_HOSTS`. Docker-Test-Override: `http://mcp-vault:8030`. Muss `http(s)://` sein.

### JIT Wrap Broker + vermittelter Verbrauch — C18 (4) *(v0.4.13 / v0.6.x)*

Vertrag für den `CredentialBrokerService` von mcp-mission: Lieferung von Single-Use-Credentials über OpenBao Response Wrapping (Cubbyhole), mit einem Write-Ahead-Registry auf S3 für die Kompensation von Waisen, und Anti-Confused-Deputy-Validierung (C18).

| Tool | Perm | Beschreibung |
| --- | --- | --- |
| `secret_wrap(vault_id, secret_path, mission_id, operation_id, ttl_seconds?, tenant_id?, expected_aud?)` | admin | Erstellt ein Single-Use-Wrap-Token (Write-Ahead-Registry) |
| `secret_revoke_wrap(lease_id)` | admin | Idempotenter Widerruf eines Wrap-Tokens (nicht gefunden = Erfolg) |
| `secret_wrap_lookup(operation_id)` | admin | Findet & widerruft Wraps nach operation_id (Waisen-Kompensation #74) |
| `secret_consume(wrap_token, operation_id, mission_token)` | admin | Validiert ES256/JWKS-JWT, prüft vollständiges Binding (mission_id, tenant_id, aud), unwrappt OpenBao (C18) |

> C18-Validierung mit `ENFORCE_MISSION_TOKEN_VALIDATION=true` aktivieren. Standard (false): Warnung loggen, fortfahren — keinerlei Auswirkung im Standalone-Modus ohne mcp-mission.
> `tenant_id` und `expected_aud` in `secret_wrap` speisen das vollständige C18-Binding auf der `secret_consume`-Seite *(v0.6.8)*.

### Audit (1)

| Tool                                                                       | Perm  | Beschreibung                                                            |
| -------------------------------------------------------------------------- | ----- | ----------------------------------------------------------------------- |
| `audit_log(limit?, client?, vault_id?, tool?, category?, status?, since?)` | admin | Filterbares Audit-Log (Ring-Buffer mit 5000 Einträgen + persistentes JSONL) |

<details>
<summary>💡 Typischer SSH-CA-Workflow (z. B. LLMaaS-Infrastruktur)</summary>

```python
# 1. Initiales Setup (EINMALIG) — Vault + SSH-Rollen erstellen
vault_create("llmaas-infra", description="SSH CA LLMaaS")
ssh_ca_setup("llmaas-infra", "adminct", allowed_users="adminct", ttl="1h")
ssh_ca_setup("llmaas-infra", "agentic", allowed_users="agentic,iaagentic", ttl="30m")

# 2. CA auf den Servern bereitstellen (EINMALIG)
result = ssh_ca_public_key("llmaas-infra")
# → result["public_key"] in /etc/ssh/trusted-user-ca-keys.pem eintragen

# 3. Tägliche Nutzung — einen öffentlichen Schlüssel signieren
cert = ssh_sign_key("llmaas-infra", "adminct", public_key="ssh-ed25519 AAAA...", ttl="1h")
# → cert["signed_key"] = signiertes Zertifikat, 1h gültig
# → OpenSSH verwendet es automatisch, wenn es neben dem privaten Schlüssel liegt
```

</details>

---

## 🔑 Secret-Typen (im 1Password-Stil)

| Typ             | Icon  | Erforderliche Felder     | Verwendung           |
| --------------- | ----- | ------------------------ | -------------------- |
| `login`         | 🔑   | username, password       | Web-/App-Zugangsdaten |
| `password`      | 🔒   | password                 | Einfaches Passwort   |
| `secure_note`   | 📝   | content                  | Sichere Notizen      |
| `api_key`       | 🔌   | key                      | API-Schlüssel        |
| `ssh_key`       | 🗝️ | private_key              | SSH-Schlüsselpaare   |
| `database`      | 🗄️ | host, username, password | DB-Verbindungen      |
| `server`        | 🖥️ | host, username           | Serverzugriff        |
| `certificate`   | 📜   | certificate, private_key | TLS/SSL-Zertifikate  |
| `env_file`      | 📄   | content                  | .env-Dateien         |
| `credit_card`   | 💳   | number, expiry, cvv      | Bankkarten           |
| `identity`      | 👤   | name                     | Identitäten          |
| `wifi`          | 📶   | ssid, password           | Wi-Fi-Netzwerke      |
| `crypto_wallet` | ₿     | *(alles optional)*       | Krypto-Wallets       |
| `custom`        | ⚙️  | *(freie Felder)*         | Alles Übrige         |

Jedes Secret unterstützt: `tags`, `favorite`, automatische KV-v2-Versionierung.

---

## 🔒 Authentifizierung

> ⚠️ **Es wird ausschließlich der Header `Authorization: Bearer <token>` akzeptiert.** Die Authentifizierung per Query-String (`?token=`) wurde aus Sicherheitsgründen entfernt (v0.3.1).

```
Authorization: Bearer <token>
```

| Permission | Lesen | Schreiben | Admin |
| ---------- | ----- | --------- | ----- |
| `read`     | ✅    | ❌        | ❌    |
| `write`    | ✅    | ✅        | ❌    |
| `admin`    | ✅    | ✅        | ✅    |

**3 Isolationsschichten**:
1. **Vault-Ebene**: `allowed_resources=[]` → owner-basiert (nur vom Token erstellte Vaults) oder explizite Liste
2. **Tool-Ebene**: Policies mit `allowed_tools`/`denied_tools` (fnmatch-Wildcards)
3. **Path-Ebene**: `allowed_paths` in den `path_rules` → Kontrolle pro einzelnem Secret

---

## 🖥️ CLI

MCP Vault enthält ein vollständiges CLI mit Click + Rich + interaktiver Shell:

```bash
# Skriptfähige Befehle
python scripts/mcp_cli.py health
python scripts/mcp_cli.py about
python scripts/mcp_cli.py whoami                       # Identität des aktuellen Tokens
python scripts/mcp_cli.py vault list
python scripts/mcp_cli.py vault create prod-servers -d "Prod SSH keys"
python scripts/mcp_cli.py secret write prod-servers web/github -d '{"username":"me","password":"s3cr3t"}' -t login
python scripts/mcp_cli.py secret read prod-servers web/github
python scripts/mcp_cli.py secret password -l 32
python scripts/mcp_cli.py token create agent-sre --vaults prod --policy readonly
python scripts/mcp_cli.py token list
python scripts/mcp_cli.py policy create no-ssh -d "No SSH" --denied "ssh_*"
python scripts/mcp_cli.py policy create team-x --allowed "secret_*" --path-rules '[{"vault_pattern":"shared-*","allowed_paths":["shared/*"]}]'
python scripts/mcp_cli.py audit --status denied --limit 10

# Interne PKI (v0.5.0)
python scripts/mcp_cli.py pki setup --lab --domains '*.lesur.lan,lesur.lan'
python scripts/mcp_cli.py pki ca-key
python scripts/mcp_cli.py pki certs
python scripts/mcp_cli.py pki revoke 12:34:ab:cd:ef:12:34:56

# Interaktive Shell
python scripts/mcp_cli.py shell
```

> Die `--help`-Ausgabe jedes Befehls erläutert das 3-schichtige Sicherheitsmodell und leitet den Benutzer an.

Siehe [scripts/README.md](scripts/README.md) für die vollständige CLI-Dokumentation.

---

## ⚙️ Umgebungsvariablen

`.env.example` → `.env` kopieren und anpassen. Die Variablen sind nach Domäne gruppiert:

| Gruppe | Variablen | Erforderlich |
|--------|-----------|--------------|
| **Server** | `MCP_SERVER_NAME`, `MCP_SERVER_PORT`, `MCP_ALLOWED_HOSTS` | Ja |
| **Auth** | `ADMIN_BOOTSTRAP_KEY` | Ja |
| **S3** | `S3_ENDPOINT_URL`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_BUCKET_NAME`, `S3_REGION_NAME` | Ja |
| **S3-Signierung** | `S3_FORCE_SIGV4` | Nein — erzwingt SigV4 für MinIO/VersityGW/AWS |
| **OpenBao** | `OPENBAO_ADDR`, `OPENBAO_SHARES`, `OPENBAO_THRESHOLD` | Ja |
| **Storage-Sync** | `VAULT_S3_PREFIX`, `VAULT_S3_SYNC_INTERVAL` | Nein |
| **PKI** *(v0.5.x)* | `PKI_BASE_URL` | Nein — überschreibt ACME-URL in Docker-Tests |
| **Mission JWT** *(v0.6.x)* | `ENFORCE_MISSION_TOKEN_VALIDATION`, `MISSION_JWKS_URL`, `MISSION_TOKEN_AUD`, `MISSION_JWKS_CACHE_TTL`, `MISSION_STATUS_URL` | Nein — Standalone ohne mcp-mission |
| **Lokalisierung** | `VAULT_LANG` | Nein — Sprache der Tool-Beschreibungen (Standard `en`) |
| **CLI-Tokens** | `VAULT_WRAP_TOKEN`, `VAULT_MISSION_TOKEN` | Nein — vor dem Befehl exportieren, niemals in `.env` |

> **Sensible CLI-Tokens**: `VAULT_WRAP_TOKEN` und `VAULT_MISSION_TOKEN` dürfen NICHT in `.env` gespeichert werden — sie ändern sich bei jeder Operation. Per `export` oder inline übergeben:
> ```bash
> VAULT_WRAP_TOKEN=hvs.CAES... mcp-vault secret consume op-123
> ```

Siehe `.env.example` für die vollständige Dokumentation jeder Variable.

---

## 🏗️ Architektur

> 📐 **Vollständige Dokumentation**: Der Ordner [`DESIGN/mcp-vault/`](DESIGN/mcp-vault/) enthält die detaillierte Spezifikation ([ARCHITECTURE.md](DESIGN/mcp-vault/ARCHITECTURE.md) — Vision, Sicherheit, SSH CA, Policies, HSM-Roadmap) und die technische Dokumentation ([TECHNICAL.md](DESIGN/mcp-vault/TECHNICAL.md) — Module, Docker, Tests, Abhängigkeiten).

```
Internet → WAF (Caddy + Coraza :8085) → MCP Vault (Python :8030) → OpenBao (:8200 localhost)
                  ↕ OWASP CRS v4                  ↕
              L7-Schutz                    S3 Dell ECS (Persistenz)
```

### WAF — Caddy + Coraza (OWASP CRS v4)

Der WAF schützt die API vor L7-Angriffen (SQL-Injection, XSS, LFI, RCE, SSRF):
- **Caddy v2.11.2** kompiliert mit **coraza-caddy v2.2.0** via `xcaddy`
- **24 OWASP-CoreRuleSet-v4.7.0-Regeln** geladen
- **Blocking-Modus auf ALLEN Endpunkten** (health, `/mcp`, `/admin/api`)
- **Gezielte Ausnahmen** (JSON-RPC-Falschpositive: französischer Unicode 920540, PowerShell-Namen 932120; CA/CRL-`.pem`-Verteilung 920440) deklariert **vor dem CRS-Include** (Muster „exclusions before CRS") — erforderlich, um CRS-Regeln der Phase:1 zu neutralisieren
- **Security-Header**: CSP, X-Frame-Options DENY, X-XSS-Protection, nosniff
- Erlaubte Methoden gemäß MCP-Protokoll: GET, POST, DELETE, PUT, PATCH

### ASGI-Stack (6 Schichten)
```
PkiMiddleware → AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP
```

`PkiMiddleware` (v0.5.0) ist die äußerste Schicht — sie fängt `/acme/*` und `/pki/ca/*.pem` vor der Auth ab (öffentliche Endpunkte per PKI/ACME-Design).

### OpenBao-Lifecycle
```
STARTUP:  S3-Download → bao server → init/unseal → periodische Synchronisierung
RUNTIME:  Secrets via hvac → S3-Sync alle 60s
SHUTDOWN: seal → abschließender S3-Upload → Prozess beenden
CRASH:    lokales Docker-Volume → sofortiger Neustart
```

### Sicherheit der Unseal-Keys

Die Unseal-Keys von OpenBao werden durch **physische Trennung mit 3 Faktoren** geschützt:

| Faktor                                   | Speicherung              | Kompromittierung allein = unzureichend |
| ---------------------------------------- | ------------------------ | -------------------------------------- |
| **Verschlüsselte Daten** (OpenBao-Barrier) | Docker-Volume + S3     | Unlesbar ohne Unseal-Key               |
| **Unseal-Keys** (AES-256-GCM-verschlüsselt) | nur S3                | Nicht entschlüsselbar ohne Bootstrap-Key |
| **ADMIN_BOOTSTRAP_KEY**                  | nur Umgebungsvariable    | Nutzlos ohne die verschlüsselten Keys  |

**Invarianten**: Unseal-Keys liegen **niemals** im Klartext auf der Festplatte — nur im Arbeitsspeicher während der Laufzeit. Ein Crash löscht die Keys automatisch.

**Sicherheits-Roadmap**:

| Version              | Ansatz                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **v0.6.8** (aktuell) | Keys auf S3 mit AES-256-GCM+AAD verschlüsselt, nur im Arbeitsspeicher zur Laufzeit — C18-Hardening: Singleton-JWT + vollständiges tenant_id/aud-Binding |
| **v1.0**             | Transit Auto-Unseal über dediziertes OpenBao (Cloud Temple KMS)                                                     |
| **v2.0**             | **HSM-Anbindung** (Hardware Security Module) Cloud Temple — Keys verlassen niemals das zertifizierte Hardwaremodul |

> 📖 Siehe [DESIGN/mcp-vault/ARCHITECTURE.md](DESIGN/mcp-vault/ARCHITECTURE.md) §8 und §11 für die vollständigen Details.

---

## 📋 Tests (~600 Tests, kein Mocking)

> 📖 Siehe [tests/README.md](tests/README.md) für den vollständigen Ausführungsleitfaden.

```bash
# 1. CLI-Tests — Parsing + Anzeige (197 Tests, OHNE Server)
python tests/test_cli_all.py

# 2. CLI-LIVE-Tests — vollständiger Zyklus (79 Tests, echter Server)
MCP_URL=http://localhost:8085 MCP_TOKEN=<key> python tests/test_cli_live.py

# 3. MCP-e2e-Tests (312 Tests, in Docker)
docker compose exec mcp-vault python tests/test_e2e.py

# 4. Krypto-Tests (18 Tests, OHNE Server — AES-256-GCM + AAD + Entropie-Validierung)
python tests/test_crypto.py

# Eine einzelne CLI-Gruppe
python tests/test_cli_all.py --only policy

# Eine einzelne e2e-Gruppe
docker compose exec mcp-vault python tests/test_e2e.py --test enforcement
```

### e2e-Abdeckung (312 Tests, 15 Kategorien)

| Kategorie              | Tests  | Beschreibung                                                                      |
| ---------------------- | ------ | --------------------------------------------------------------------------------- |
| System                 | 7      | health, about, services, tools_count (36)                                          |
| Vault CRUD             | 28     | create + Metadaten, list, info + Owner, update, delete, confirm, Fehler            |
| Secrets CRUD           | 24     | 10 Typen geschrieben, read/list/delete, Validierung                                |
| Versionierung          | 8      | v1→v2→v3, read latest, read spezifisch                                            |
| Passwords              | 14     | Längen, Optionen, Ausschlüsse, CSPRNG                                             |
| Isolation              | 7      | Secrets zwischen Vaults abgeschottet                                              |
| Fehler                 | 10     | Edge Cases, fehlender Vault, ungültiger Typ, `_vault_meta`-Schutz                 |
| S3 Sync                | 3      | tar.gz-Archiv auf S3                                                              |
| SSH CA                 | 33     | setup, mehrere Rollen, ed25519-Signierung, list/info roles, CA-Isolation, Cleanup |
| Typen                  | 14     | 14 Typen einzeln verifiziert                                                       |
| Admin API              | 15     | health, whoami, generate-password, logs, CSPRNG-Eindeutigkeit                      |
| MCP-Policies           | 43     | CRUD, Validierung, Wildcards, path_rules, Duplikate, Fehler, Admin-API-REST        |
| **Policy Enforcement** | **37** | check_policy, token_update, denied/allowed, Policy-Wechsel, Admin API             |
| **Audit Log**          | **31** | audit_log MCP, Filter (category/tool/status/since/limit), Statistiken, Admin API /audit |
| **WAF Security**       | **17** | LFI, SQLi, XSS, RCE, Scanner Detection → 403 + Nicht-Regression legitimer Anfragen |

---

## 📁 Projektstruktur

```
mcp-vault/
├── .env.example              # Konfiguration (nach .env kopieren)
├── docker-compose.yml        # WAF + MCP Vault + Volumes
├── Dockerfile                # Multi-Stage (OpenBao 2.5.1 + Python 3.12)
├── requirements.txt          # Python-Abhängigkeiten
├── requirements.lock         # Gepinnte Abhängigkeiten (exakte Versionen)
├── VERSION                   # 0.6.8
├── DESIGN/mcp-vault/
│   ├── ARCHITECTURE.md       # Detaillierte Spezifikation (v0.6.8)
│   ├── TECHNICAL.md          # Technische Dokumentation (v0.6.8)
│   └── SECURITY_AUDIT.md     # Konsolidierter Audit-Bericht (60 Findings V2.1)
├── scripts/
│   ├── mcp_cli.py            # CLI-Einstiegspunkt
│   ├── README.md             # CLI-Dokumentation
│   └── cli/                  # CLI-Modul (Click + Rich + prompt-toolkit)
│       ├── __init__.py       # Config (.env, BASE_URL, TOKEN)
│       ├── client.py         # MCPClient (Streamable HTTP)
│       ├── commands.py       # 7 Click-Gruppen
│       ├── display.py        # Rich-Anzeige
│       └── shell.py          # Interaktive Shell
├── src/mcp_vault/
│   ├── config.py             # pydantic-settings-Konfiguration
│   ├── server.py             # FastMCP + 36 MCP-Tools + Lifecycle + Audit
│   ├── lifecycle.py          # Startup/Shutdown-Orchestrator
│   ├── s3_client.py          # Hybrider SigV2/SigV4-S3-Client
│   ├── s3_sync.py            # File-Backend ↔ S3-Sync
│   ├── auth/                 # Bearer-Tokens, check_access, ContextVar, jwt_validator
│   ├── admin/                # Web-Konsole /admin + REST-API
│   ├── openbao/              # Process Manager, HCL-Config, Lifecycle
│   ├── vault/                # Spaces, Secrets, SSH CA, PKI CA, Wrapping, Typen
│   └── static/               # Admin-SPA-Konsole (100% CLI-Parität)
│       ├── admin.html        # HTML-Struktur + 7 Modals
│       ├── css/admin.css     # Cloud-Temple-Design (Dark Theme)
│       ├── js/               # 9 JS-Module (config, api, app, dashboard, vaults, tokens, policies, activity, pki)
│       └── img/              # logo-cloudtemple.svg
├── tests/
│   ├── README.md             # Leitfaden zur Testausführung (Auditoren)
│   ├── TEST_CATALOG.md       # Testkatalog für Auditoren
│   ├── test_cli_all.py       # 197 CLI-Parsing-Tests (ohne Server)
│   ├── test_cli_live.py      # 79 CLI-Live-Tests (echter Server)
│   ├── test_e2e.py           # 312 MCP-e2e-Tests (15 Kategorien)
│   ├── test_crypto.py        # 18 AES-256-GCM + AAD-Tests
│   ├── test_jwt_validator.py # C18-JWT-Validator-Tests (mission_token)
│   ├── test_wrap.py          # JIT-Wrap-Broker + C18-Binding-Tests
│   ├── test_service.py       # Low-Level-Tests
│   ├── test_integration.py   # pytest-Tests
│   └── cli/                  # CLI-Tests nach Gruppe aufgeteilt (7 Dateien)
└── waf/                      # WAF Caddy + Coraza (OWASP CRS v4)
    ├── Dockerfile            # Multi-Stage (xcaddy + CRS v4.7.0)
    ├── Caddyfile             # Reverse Proxy + coraza_waf
    └── coraza.conf           # Coraza-Config + MCP-Ausnahmen
```

---

## 🌐 Cloud Temple MCP-Ökosystem

| Server           | Rolle                             | Port  |
| ---------------- | --------------------------------- | ----- |
| **MCP Tools**    | Werkzeugkasten (SSH, HTTP, Shell) | :8010 |
| **Live Memory**  | Gemeinsamer Arbeitsspeicher       | :8002 |
| **Graph Memory** | Langzeitgedächtnis (Graph)        | :8080 |
| **MCP Vault**    | 🔐 Secret-Tresor                 | :8030 |
| **MCP Agent**    | Laufzeit für autonome Agenten     | :8040 |
| **MCP Mission**  | Missions-Orchestrator             | :8020 |

---

**Lizenz**: Apache 2.0 | **Autor**: Cloud Temple | **Version**: 0.6.8
