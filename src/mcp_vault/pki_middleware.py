# -*- coding: utf-8 -*-
"""
PkiMiddleware ASGI — Proxy non-authentifié pour les endpoints PKI/ACME.

Intercepte AVANT le middleware d'auth MCP (couche la plus externe dans create_app).
Ces routes sont délibérément non-authentifiées : c'est le standard PKI/ACME.

Routes interceptées :
    /acme/*        → proxy transparent vers OpenBao /v1/_sys_pki_int/acme/*
    /pki/ca/root.pem  → OpenBao /v1/_sys_pki_root/ca/pem
    /pki/ca/chain.pem → OpenBao /v1/_sys_pki_int/ca_chain
    /pki/ca/crl.pem   → OpenBao /v1/_sys_pki_int/crl
"""

import logging

import httpx

from .config import get_settings
from .vault.pki_ca import _INT_MOUNT as _PKI_INT_MOUNT, _ROOT_MOUNT as _PKI_ROOT_MOUNT

logger = logging.getLogger("mcp-vault.pki-middleware")

# Headers de réponse à propager vers le client ACME
_ACME_RESPONSE_HEADERS = frozenset({
    "content-type",
    "replay-nonce",
    "location",
    "link",
    "retry-after",
    "cache-control",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
})


class PkiMiddleware:
    """
    Middleware ASGI outermost — proxy transparent ACME + distribution CA.

    Monté après AdminMiddleware dans create_app() (donc couche la plus externe).
    Les requêtes /acme/* et /pki/ca/* ne traversent JAMAIS AuthMiddleware.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")

        if path.startswith("/acme/") or path in ("/acme", "/acme/"):
            return await self._proxy_acme(scope, receive, send, path)

        if path in ("/pki/ca/root.pem", "/pki/ca/chain.pem", "/pki/ca/crl.pem"):
            return await self._proxy_pki_ca(scope, receive, send, path)

        return await self.app(scope, receive, send)

    async def _proxy_acme(self, scope, receive, send, path: str) -> None:
        settings = get_settings()
        acme_suffix = path[len("/acme"):]  # /directory, /new-nonce, ...
        target = f"{settings.openbao_addr}/v1/{_PKI_INT_MOUNT}/acme{acme_suffix}"

        query = scope.get("query_string", b"")
        if query:
            target += f"?{query.decode()}"

        await self._proxy_request(scope, receive, send, target)

    async def _proxy_pki_ca(self, scope, receive, send, path: str) -> None:
        settings = get_settings()
        path_map = {
            "/pki/ca/root.pem":  f"{settings.openbao_addr}/v1/{_PKI_ROOT_MOUNT}/ca/pem",
            "/pki/ca/chain.pem": f"{settings.openbao_addr}/v1/{_PKI_INT_MOUNT}/ca_chain",
            "/pki/ca/crl.pem":   f"{settings.openbao_addr}/v1/{_PKI_INT_MOUNT}/crl",
        }
        target = path_map.get(path)
        if not target:
            return await self._error(send, 404, "Not found")
        await self._proxy_request(scope, receive, send, target)

    async def _proxy_request(self, scope, receive, send, target: str) -> None:
        method = scope.get("method", "GET")

        body = b""
        more = True
        while more:
            event = await receive()
            body += event.get("body", b"")
            more = event.get("more_body", False)

        req_headers = {}
        for name_b, value_b in scope.get("headers", []):
            name = name_b.decode().lower()
            if name in ("content-type", "accept", "user-agent"):
                req_headers[name] = value_b.decode()

        try:
            async with httpx.AsyncClient(timeout=30.0) as http_client:
                resp = await http_client.request(
                    method=method,
                    url=target,
                    content=body,
                    headers=req_headers,
                    follow_redirects=True,
                )
        except Exception as e:
            logger.error(f"❌ PkiMiddleware : connexion OpenBao échouée ({target}) : {e}")
            return await self._error(send, 502, "PKI backend unavailable")

        resp_headers = []
        for name, value in resp.headers.items():
            if name.lower() in _ACME_RESPONSE_HEADERS:
                resp_headers.append((name.lower().encode(), value.encode()))

        content = resp.content
        resp_headers.append((b"content-length", str(len(content)).encode()))

        await send({
            "type": "http.response.start",
            "status": resp.status_code,
            "headers": resp_headers,
        })
        await send({"type": "http.response.body", "body": content})

    async def _error(self, send, status: int, message: str) -> None:
        body = f'{{"status":"error","message":"{message}"}}'.encode()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})
