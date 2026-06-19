#!/usr/bin/env python
"""Utilitaire en ligne de commande de Django pour les tâches d'administration.

Lancé depuis la racine du dépôt : ``uv run python webapp/manage.py <commande>``.
Le dossier ``webapp/`` devient ``sys.path[0]``, donc ``anssi_web`` et
``vulnerabilities`` sont importables ; le package ``anssi_cve`` (étapes 1-4)
provient de l'installation editable du venv.
"""

import os
import sys


def main():
    """Point d'entrée des commandes d'administration Django."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "anssi_web.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Django est introuvable. Installe-le avec `uv add django` puis "
            "lance la commande via `uv run`."
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
