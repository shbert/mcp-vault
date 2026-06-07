# -*- coding: utf-8 -*-
"""
Fixtures pytest pour les tests CLI.

Problème corrigé : la fonction check() dans __init__.py incrémentait FAIL
mais ne levait jamais d'exception, donc pytest considérait tous les tests
CLI comme réussis même si des assertions échouaient.

Fix : fixture autouse qui remet les compteurs à zéro avant chaque test
et assert FAIL == 0 après — toute assertion check() qui échoue fait maintenant
échouer le test pytest correspondant.
"""

import pytest
from . import reset_counters, get_counters


@pytest.fixture(autouse=True)
def assert_no_cli_failures():
    """Remet les compteurs à zéro et assert FAIL == 0 après chaque test CLI."""
    reset_counters()
    yield
    _, fail = get_counters()
    if fail:
        pytest.fail(f"{fail} assertion(s) CLI ont échoué — voir les ❌ ci-dessus")
