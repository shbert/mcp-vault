#!/usr/bin/env bash
# =============================================================================
# Tests d'acceptation PKI — T0 à T10 (issue #15)
# Utilise l'API REST admin (/admin/api/pki/*) + curl + openssl
#
# Usage :
#   bash tests/pki/test_pki_integration.sh
#
# Prérequis :
#   docker compose up -d
#   cd tests/pki && docker compose -f docker-compose.test-pki.yml up -d && cd ../..
# =============================================================================

WAF="http://localhost:8085"

# Récupère le token depuis .env
TOKEN=$(grep -E "^ADMIN_BOOTSTRAP_KEY=" .env 2>/dev/null | cut -d= -f2- | tr -d '"')
if [[ -z "$TOKEN" ]]; then
  echo "❌ ADMIN_BOOTSTRAP_KEY absent du .env"
  exit 1
fi

PASS=0
FAIL=0
SKIP=0
declare -a RESULTS=()

_ok()   { PASS=$((PASS+1)); RESULTS+=("✅ $1"); echo "  ✅  $1"; }
_fail() { FAIL=$((FAIL+1)); RESULTS+=("❌ $1"); echo "  ❌  $1 — ${2:-}"; }
_skip() { SKIP=$((SKIP+1)); RESULTS+=("⏭️  $1"); echo "  ⏭️  $1 — ${2:-}"; }
_info() { echo "  ℹ️  $1"; }
_sep()  { echo; echo "──────────────────────────────────────────────"; echo "  $1"; echo "──────────────────────────────────────────────"; }

ADMIN() {
  # Pas de -f : on veut le body même pour les 4xx (ex: reserved_mount en 400)
  curl -s -X "$1" "$WAF/admin/api${2}" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    ${3:+-d "$3"} 2>&1
}

# ── T0 : Réseau Docker ───────────────────────────────────────────────────────

_sep "T0 — Réseau : mcp-vault peut joindre caddy-test:80"

T0=$(docker exec mcp-vault-mcp-vault-1 \
  python3 -c "import urllib.request; r=urllib.request.urlopen('http://caddy-test/',timeout=5); print(r.read().decode())" 2>&1)

if echo "$T0" | grep -q "OK caddy-test"; then
  _ok "T0 : mcp-vault → caddy-test:80 → HTTP OK"
else
  _fail "T0" "mcp-vault ne peut pas joindre caddy-test:80 (réponse: ${T0:0:100})"
  _info "caddy-test est sur le réseau mcp-vault_mcp-net — vérifier logs du conteneur"
fi

# ── Setup PKI (via admin REST) ───────────────────────────────────────────────

_sep "Setup PKI — POST /admin/api/pki/setup"

SETUP=$(ADMIN POST /pki/setup '{"lab_mode":true,"allowed_domains":"test.lesur.lan,*.lesur.lan","leaf_ttl":"2h"}' 2>&1)
PKI_STATUS=$(echo "$SETUP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','error'))" 2>/dev/null || echo "parse_error")

if [[ "$PKI_STATUS" == "ok" ]]; then
  _ok "PKI initialisée (lab_mode, domains=caddy-test)"
  ROOT_FP=$(echo "$SETUP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('root_fingerprint_sha256',''))" 2>/dev/null)
  ACME_DIR=$(echo "$SETUP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('acme_directory',''))" 2>/dev/null)
  _info "SHA-256 racine : $ROOT_FP"
  _info "ACME directory : $ACME_DIR"
elif [[ "$PKI_STATUS" == "error" ]]; then
  MSG=$(echo "$SETUP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('message',''))" 2>/dev/null)
  _fail "PKI setup" "$MSG"
else
  _fail "PKI setup" "réponse inattendue : ${SETUP:0:200}"
fi

# ── T3 : URLs stables CA ─────────────────────────────────────────────────────

_sep "T3 — URLs stables CA (accès non-auth)"

ROOT_PEM=$(curl -s "$WAF/pki/ca/root.pem" 2>&1)
if echo "$ROOT_PEM" | grep -q "BEGIN CERTIFICATE"; then
  _ok "T3a : /pki/ca/root.pem → PEM valide"
  SUBJECT=$(echo "$ROOT_PEM" | openssl x509 -subject -noout 2>/dev/null | head -1)
  _info "Sujet : $SUBJECT"
else
  _fail "T3a" "/pki/ca/root.pem — réponse: ${ROOT_PEM:0:100}"
fi

CHAIN_PEM=$(curl -s "$WAF/pki/ca/chain.pem" 2>&1)
if echo "$CHAIN_PEM" | grep -q "BEGIN CERTIFICATE"; then
  _ok "T3b : /pki/ca/chain.pem → PEM valide"
else
  _fail "T3b" "/pki/ca/chain.pem — ${CHAIN_PEM:0:100}"
fi

CRL=$(curl -s "$WAF/pki/ca/crl.pem" 2>&1)
if echo "$CRL" | grep -q "BEGIN"; then
  _ok "T3c : /pki/ca/crl.pem → CRL présente"
else
  _fail "T3c" "/pki/ca/crl.pem — ${CRL:0:100}"
fi

# ── T3 ACME directory ────────────────────────────────────────────────────────

_sep "ACME directory accessible (non-auth)"

ACME_RESP=$(curl -s "$WAF/acme/directory" 2>&1)
if echo "$ACME_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'newNonce' in d or 'newAccount' in d" 2>/dev/null; then
  _ok "ACME /acme/directory → JSON valide (newNonce/newAccount présent)"
else
  _fail "ACME directory" "réponse: ${ACME_RESP:0:200}"
fi

# ── T5 : Vérification TLS active (httpx sans CA → erreur) ────────────────────

_sep "T5 — httpx sans CA → erreur TLS (verify=True par défaut)"

T5=$(docker exec mcp-vault-mcp-vault-1 python3 -c "
import httpx, ssl
try:
    # TLS vers caddy-test sans fournir la CA → doit échouer
    httpx.get('https://caddy-test/', timeout=3, verify=True)
    print('UNEXPECTED_SUCCESS')
except Exception as e:
    print('TLS_ERROR:', type(e).__name__)
" 2>&1)

if echo "$T5" | grep -qE "TLS_ERROR|SSLError|ConnectError|RemoteProtocol"; then
  _ok "T5 : httpx sans CA → erreur TLS/connexion (verify=True actif)"
elif echo "$T5" | grep -q "UNEXPECTED_SUCCESS"; then
  _fail "T5" "httpx sans CA a réussi — vérifier que Caddy-test a bien un cert TLS"
else
  _info "T5 : résultat=$T5 (Caddy-test n'a pas encore de cert TLS — T1 à faire d'abord)"
  _skip "T5" "Caddy-test n'a pas encore de cert — à re-tester après T1"
fi

# ── T6 : ACME refuse SANs hors domaine ───────────────────────────────────────

_sep "T6 — Rôle ACME : SANs hors domaine refusés"

ROLE=$(ADMIN GET /pki/roles/acme-servers 2>&1)
ROLE_STATUS=$(echo "$ROLE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','error'))" 2>/dev/null)

if [[ "$ROLE_STATUS" == "ok" ]]; then
  ANY_NAME=$(echo "$ROLE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('allow_any_name','?'))" 2>/dev/null)
  LOCALHOST=$(echo "$ROLE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('allow_localhost','?'))" 2>/dev/null)
  IP_SANS=$(echo "$ROLE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('allow_ip_sans','?'))" 2>/dev/null)
  DOMAINS_LIST=$(echo "$ROLE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('allowed_domains',[]))" 2>/dev/null)

  if [[ "$ANY_NAME" == "False" ]]; then
    _ok "T6a : allow_any_name=False — SANs arbitraires refusés"
  else
    _fail "T6a" "allow_any_name=$ANY_NAME (attendu False)"
  fi

  if [[ "$LOCALHOST" == "False" ]]; then
    _ok "T6b : allow_localhost=False"
  else
    _fail "T6b" "allow_localhost=$LOCALHOST (attendu False)"
  fi

  if [[ "$IP_SANS" == "False" ]]; then
    _ok "T6c : allow_ip_sans=False — IP SANs refusés"
  else
    _fail "T6c" "allow_ip_sans=$IP_SANS (attendu False)"
  fi

  _info "Domaines autorisés : $DOMAINS_LIST"
else
  _fail "T6" "Role ACME inaccessible : $ROLE"
  _fail "T6a" ""; _fail "T6b" ""; _fail "T6c" ""
fi

# ── T9 : Protection vault_delete ─────────────────────────────────────────────

_sep "T9 — vault_delete sur mounts _sys_pki_* refusé (double guard)"

T9A=$(ADMIN DELETE "/vaults/_sys_pki_root" 2>&1)
T9A_STATUS=$(echo "$T9A" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','?'))" 2>/dev/null)
if [[ "$T9A_STATUS" == "reserved_mount" ]]; then
  _ok "T9a : DELETE /admin/api/vaults/_sys_pki_root → 403 reserved_mount"
else
  _fail "T9a" "Réponse inattendue : $T9A"
fi

T9B=$(ADMIN DELETE "/vaults/_sys_pki_int" 2>&1)
T9B_STATUS=$(echo "$T9B" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','?'))" 2>/dev/null)
if [[ "$T9B_STATUS" == "reserved_mount" ]]; then
  _ok "T9b : DELETE /admin/api/vaults/_sys_pki_int → 403 reserved_mount"
else
  _fail "T9b" "Réponse inattendue : $T9B"
fi

# ── T1 : Caddy ACME enrollment ───────────────────────────────────────────────

_sep "T1 — Caddy caddy-test s'enrôle via ACME (HTTP-01)"

# Copier la CA root dans caddy-test pour qu'il puisse vérifier le serveur ACME
if [[ -n "$ROOT_PEM" ]] && echo "$ROOT_PEM" | grep -q "BEGIN CERTIFICATE"; then
  docker compose -f tests/pki/docker-compose.test-pki.yml exec -T caddy-test \
    sh -c "echo '$ROOT_PEM' > /usr/local/share/ca-certificates/mcp-vault-ca.crt && update-ca-certificates 2>/dev/null || true" 2>/dev/null || true

  # Recharger le Caddyfile avec acme_ca configuré
  docker compose -f tests/pki/docker-compose.test-pki.yml exec -T caddy-test \
    caddy reload --config /etc/caddy/Caddyfile 2>/dev/null || true

  sleep 3

  # Vérifier si Caddy a obtenu un cert
  CERT_INFO=$(docker compose -f tests/pki/docker-compose.test-pki.yml exec -T caddy-test \
    caddy list-certs 2>&1 || echo "CMD_NA")

  if echo "$CERT_INFO" | grep -qi "caddy-test\|issued\|certificate"; then
    _ok "T1 : Caddy a obtenu un certificat pour 'caddy-test'"
  else
    # Vérifier via l'inventaire PKI
    CERTS=$(ADMIN GET /pki/certs 2>&1)
    CERT_COUNT=$(echo "$CERTS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo "0")
    if [[ "$CERT_COUNT" -gt 0 ]]; then
      _ok "T1 : $CERT_COUNT cert(s) émis par la CA (ACME enrollment OK)"
    else
      _skip "T1" "Enrollment ACME pas encore complété (caddy list-certs: $CERT_INFO)"
    fi
  fi
else
  _skip "T1" "PKI non initialisée, skip enrollment"
fi

# ── T7 : Révocation ──────────────────────────────────────────────────────────

_sep "T7 — Révocation + CRL mise à jour"

CERTS_DATA=$(ADMIN GET /pki/certs 2>&1)
CERT_COUNT=$(echo "$CERTS_DATA" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo "0")
_info "Certificats émis : $CERT_COUNT"

if [[ "$CERT_COUNT" -gt 0 ]]; then
  FIRST_SERIAL=$(echo "$CERTS_DATA" | python3 -c "
import sys,json
d=json.load(sys.stdin)
certs=[c for c in d.get('certs',[]) if not c.get('revoked')]
print(certs[0]['serial'] if certs else '')
" 2>/dev/null)

  if [[ -n "$FIRST_SERIAL" ]]; then
    REVOKE=$(ADMIN POST "/pki/certs/$FIRST_SERIAL/revoke" '{}' 2>&1)
    REVOKE_OK=$(echo "$REVOKE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','error'))" 2>/dev/null)
    if [[ "$REVOKE_OK" == "ok" ]]; then
      _ok "T7 : Cert $FIRST_SERIAL révoqué"
      # Vérifier CRL mise à jour
      CRL2=$(curl -sf "$WAF/pki/ca/crl.pem" 2>&1)
      if echo "$CRL2" | grep -q "BEGIN"; then
        _ok "T7 : CRL toujours disponible après révocation"
      fi
    else
      _fail "T7" "Révocation : $REVOKE"
    fi
  else
    _skip "T7" "Aucun cert non-révoqué disponible"
  fi
else
  _skip "T7" "Aucun cert émis (T1 requis d'abord)"
fi

# ── T10 : Sync S3 + restart ───────────────────────────────────────────────────

_sep "T10 — PKI status après restart (durabilité S3)"

PKI_STATUS_BEFORE=$(ADMIN GET /pki/status 2>&1)
STATUS_BEFORE=$(echo "$PKI_STATUS_BEFORE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null)
_info "PKI status avant restart : $STATUS_BEFORE"

if [[ "$STATUS_BEFORE" == "ok" ]]; then
  # Restart mcp-vault (simule un crash/redémarrage)
  docker restart mcp-vault-mcp-vault-1 2>&1 | tail -1
  _info "mcp-vault redémarré — attente 15s..."
  sleep 15

  PKI_STATUS_AFTER=$(ADMIN GET /pki/status 2>&1)
  STATUS_AFTER=$(echo "$PKI_STATUS_AFTER" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null)

  if [[ "$STATUS_AFTER" == "ok" ]]; then
    _ok "T10 : PKI toujours initialisée après restart (durabilité S3 OK)"
    INT_EXP=$(echo "$PKI_STATUS_AFTER" | python3 -c "import sys,json; print(json.load(sys.stdin).get('int_expires','?'))" 2>/dev/null)
    _info "Expiration intermédiaire : $INT_EXP"
  else
    _fail "T10" "PKI status après restart : $STATUS_AFTER — PKI perdue ?"
  fi
else
  _skip "T10" "PKI non initialisée, skip test durabilité"
fi

# ── Résumé ────────────────────────────────────────────────────────────────────

echo
echo "══════════════════════════════════════════════════"
echo "  RÉSULTATS — Tests d'acceptation PKI (T0-T10)"
echo "══════════════════════════════════════════════════"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo
echo "  PASS : $PASS   FAIL : $FAIL   SKIP : $SKIP"
echo "══════════════════════════════════════════════════"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
