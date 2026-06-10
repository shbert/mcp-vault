# -*- coding: utf-8 -*-
"""
Validateur JWT mission_token (ES256/JWKS) — Issue #26, anti-confused-deputy C18.

Usage :
    from mcp_vault.auth.jwt_validator import MissionTokenValidator, MissionTokenError

    validator = MissionTokenValidator(
        jwks_url="https://mcp-mission/.well-known/jwks.json",
        expected_aud="mcp-vault:prod:v1",
    )
    try:
        claims = validator.validate(token_compact)
    except MissionTokenError as e:
        # e.reason = code d'erreur ("invalid_signature", "token_expired", ...)
        # Jamais le token compact dans e.reason ni dans les logs

Sécurité :
    - ES256 uniquement (ECDSA P-256)
    - Cache JWKS TTL-borné (60s par défaut) + refresh sur kid inconnu
    - Rate-limit sur refresh (3/min par défaut) — anti-DoS JWKS
    - kid absent du JWKS après refresh = token rejeté (révocation implicite)
    - Jamais le token compact dans les messages d'erreur ni les logs
    - Thread-safe via threading.Lock

Standalone (sans mcp-mission) :
    Quand MISSION_JWKS_URL est vide, MissionTokenValidator n'est pas instancié
    et secret_consume fonctionne en mode non-enforced (log warning si ENFORCE=false,
    hard-reject si ENFORCE=true).
"""

import logging
import threading
import time
from typing import Optional

import httpx
import jwt
from jwt import PyJWKSet

logger = logging.getLogger("mcp-vault.jwt-validator")


class MissionTokenError(Exception):
    """
    Erreur de validation JWT — ne contient JAMAIS le token compact.

    Attributes:
        reason: Code d'erreur lisible machine (ex: "invalid_signature",
                "token_expired", "kid_unknown_or_revoked", "invalid_audience").
                Ne jamais inclure le token compact ou des données sensibles.
    """

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class MissionTokenValidator:
    """
    Validateur JWT ES256 avec cache JWKS TTL-borné et rate-limit.

    Thread-safe. Instancier une fois au démarrage (lifecycle.py ou settings).
    """

    def __init__(
        self,
        jwks_url: str,
        expected_iss: str = "mcp-mission",
        expected_aud: str = "",
        cache_ttl: int = 60,
        max_refresh_per_min: int = 3,
        leeway_seconds: int = 10,
    ):
        if not jwks_url:
            raise ValueError("jwks_url requis pour MissionTokenValidator")
        self._jwks_url = jwks_url
        self._expected_iss = expected_iss
        self._expected_aud = expected_aud
        self._cache_ttl = cache_ttl
        self._max_refresh_per_min = max_refresh_per_min
        self._leeway = leeway_seconds

        self._jwks: Optional[PyJWKSet] = None
        self._jwks_fetched_at: float = 0.0
        self._refresh_count: int = 0
        self._refresh_window_start: float = 0.0
        self._lock = threading.Lock()

    def _fetch_jwks_from_url(self) -> PyJWKSet:
        """Fetch JWKS depuis l'URL avec rate-limit."""
        now = time.monotonic()
        if now - self._refresh_window_start > 60.0:
            self._refresh_count = 0
            self._refresh_window_start = now

        if self._refresh_count >= self._max_refresh_per_min:
            logger.warning("⚠️ JWKS rate-limit atteint — refresh refusé")
            raise MissionTokenError("jwks_refresh_rate_limited")

        self._refresh_count += 1
        try:
            resp = httpx.get(self._jwks_url, timeout=5.0, follow_redirects=False)
            resp.raise_for_status()
            return PyJWKSet.from_dict(resp.json())
        except MissionTokenError:
            raise
        except Exception as e:
            logger.error(f"❌ Fetch JWKS échoué ({self._jwks_url}) : {type(e).__name__}")
            raise MissionTokenError("jwks_unavailable")

    def _get_jwks(self, force_refresh: bool = False) -> PyJWKSet:
        """Retourne le JWKS (cache ou fetch)."""
        now = time.monotonic()
        with self._lock:
            if force_refresh or self._jwks is None or (now - self._jwks_fetched_at) > self._cache_ttl:
                self._jwks = self._fetch_jwks_from_url()
                self._jwks_fetched_at = now
            return self._jwks

    @staticmethod
    def _find_key_in_jwks(jwks: PyJWKSet, kid: str):
        """Cherche une clé par kid dans un PyJWKSet (itération sur .keys)."""
        for key in jwks.keys:
            if key.key_id == kid:
                return key
        return None

    def _get_signing_key(self, kid: str):
        """Retourne la clé de signature pour kid, avec refresh si kid inconnu."""
        try:
            jwks = self._get_jwks()
            key = self._find_key_in_jwks(jwks, kid)
        except MissionTokenError:
            raise
        except Exception:
            key = None

        if key is None:
            # kid inconnu → refresh unique
            logger.info(f"kid '{kid}' inconnu — refresh JWKS")
            try:
                jwks = self._get_jwks(force_refresh=True)
                key = self._find_key_in_jwks(jwks, kid)
            except MissionTokenError:
                raise
            except Exception:
                raise MissionTokenError("jwks_unavailable")

            if key is None:
                # kid toujours absent après refresh = révoqué ou invalide
                raise MissionTokenError("kid_unknown_or_revoked")

        return key

    def validate(self, token_compact: str) -> dict:
        """
        Valide un JWT mission_token ES256.

        Args:
            token_compact: JWT compact (jamais loggué ni inclus dans les erreurs).

        Returns:
            dict des claims si valide : iss, aud, exp, mission_id, sub?, tenant_id?

        Raises:
            MissionTokenError: reason = code d'erreur machine (sans le token).
        """
        # Extraire le header sans vérification
        try:
            header = jwt.get_unverified_header(token_compact)
        except Exception:
            raise MissionTokenError("invalid_token_format")

        kid = header.get("kid", "")
        alg = header.get("alg", "")

        if alg != "ES256":
            raise MissionTokenError(f"unsupported_algorithm:{alg or 'missing'}")

        signing_key = self._get_signing_key(kid)

        # Décoder et valider
        try:
            decode_kwargs: dict = {
                "algorithms": ["ES256"],
                "issuer": self._expected_iss,
                "options": {
                    "require": ["exp", "iss", "mission_id"],
                    "leeway": self._leeway,
                    "verify_exp": True,
                    "verify_iss": True,
                },
            }
            if self._expected_aud:
                decode_kwargs["audience"] = self._expected_aud

            claims = jwt.decode(
                token_compact,
                signing_key.key,
                **decode_kwargs,
            )
        except jwt.ExpiredSignatureError:
            raise MissionTokenError("token_expired")
        except jwt.InvalidIssuerError:
            raise MissionTokenError("invalid_issuer")
        except jwt.InvalidAudienceError:
            raise MissionTokenError("invalid_audience")
        except jwt.InvalidSignatureError:
            raise MissionTokenError("invalid_signature")
        except jwt.MissingRequiredClaimError as e:
            raise MissionTokenError(f"missing_claim:{getattr(e, 'claim', 'unknown')}")
        except jwt.DecodeError:
            raise MissionTokenError("decode_error")
        except Exception:
            raise MissionTokenError("validation_failed")

        return claims
