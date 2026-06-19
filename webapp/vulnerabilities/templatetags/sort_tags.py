"""Filtres de template pour les en-têtes de colonnes triables (listes CVE/bulletins)."""

from django import template

register = template.Library()


@register.filter
def toggle_sort(current: str, field: str) -> str:
    """Valeur du paramètre ``sort`` à utiliser au clic sur la colonne ``field``.

    Premier clic sur une colonne → tri décroissant (le plus pertinent en
    premier pour des scores/dates) ; un second clic inverse vers croissant.
    """
    if current == field:
        return f"-{field}"
    if current == f"-{field}":
        return field
    return f"-{field}"


@register.filter
def sort_arrow(current: str, field: str) -> str:
    """Indicateur visuel (▲/▼) du tri actif sur la colonne ``field``."""
    if current == field:
        return "▲"
    if current == f"-{field}":
        return "▼"
    return ""
