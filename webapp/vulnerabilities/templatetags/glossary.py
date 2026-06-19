"""Glossaire pédagogique : termes techniques expliqués en langage courant.

Permet d'écrire ``{% term "cvss" %}`` dans un template pour afficher le sigle
avec une infobulle de définition (rendue par Bootstrap). Objectif : rendre la
veille CVE compréhensible par un public non expert sans alourdir les pages.
"""

from django.template import Library
from django.utils.html import escape, format_html

register = Library()

# {clé: (libellé affiché par défaut, définition grand public)}
GLOSSARY: dict[str, tuple[str, str]] = {
    "cve": (
        "CVE",
        "Identifiant unique mondial attribué à chaque faille de sécurité "
        "connue (ex. CVE-2024-1234).",
    ),
    "cvss": (
        "CVSS",
        "Note de gravité de 0 à 10. Plus le score est élevé, plus la faille "
        "est dangereuse si elle est exploitée.",
    ),
    "epss": (
        "EPSS",
        "Probabilité (de 0 à 100 %) qu'une faille soit réellement exploitée "
        "par des attaquants dans les 30 prochains jours.",
    ),
    "cwe": (
        "CWE",
        "Catégorie décrivant le type de faiblesse technique à l'origine de la "
        "faille (ex. injection SQL, débordement mémoire).",
    ),
    "certfr": (
        "CERT-FR",
        "Centre gouvernemental français de veille et de réponse aux attaques "
        "informatiques, rattaché à l'ANSSI.",
    ),
    "anssi": (
        "ANSSI",
        "Agence nationale de la sécurité des systèmes d'information : "
        "l'autorité française en cybersécurité.",
    ),
    "bulletin": (
        "bulletin",
        "Publication du CERT-FR (avis ou alerte) décrivant une ou plusieurs "
        "failles et les produits concernés.",
    ),
}


@register.simple_tag
def term(key: str, label: str | None = None):
    """Affiche un terme du glossaire avec son infobulle de définition.

    Usage : ``{% term "cvss" %}`` ou ``{% term "cvss" "score CVSS" %}``.
    """
    entry = GLOSSARY.get(key)
    if entry is None:
        return label or key
    default_label, definition = entry
    return format_html(
        '<abbr class="glossary-term" tabindex="0" role="button" '
        'data-bs-toggle="tooltip" data-bs-placement="top" '
        'data-bs-title="{}">{}</abbr>',
        definition,
        escape(label or default_label),
    )
