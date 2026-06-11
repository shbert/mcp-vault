# -*- coding: utf-8 -*-
"""
Helpers défensifs pour les retours hvac (issue #38).

hvac `client.list(path)` retourne `None` quand le chemin ne contient aucune
entrée (ex : PKI/SSH fraîchement initialisée — état nominal). Accéder
directement à `.get("data")` lève alors un `AttributeError` qui fait passer un
état sain pour une erreur. `safe_list_keys` normalise ce cas en liste vide.
"""

from typing import Optional


def safe_list_keys(list_response: Optional[dict]) -> list:
    """
    Extrait `data.keys` d'une réponse `client.list()` de façon défensive.

    Retourne une liste vide si la réponse est None (chemin vide), ou si
    `data`/`keys` sont absents. Ne masque PAS les autres erreurs (le caller
    garde son try/except autour de l'appel réseau).
    """
    return ((list_response or {}).get("data") or {}).get("keys", []) or []
