"""Étape 1 : extraction des flux RSS des avis et alertes ANSSI."""

import re
from typing import Optional

import feedparser

from . import config

# Identifiant ANSSI dans une URL, ex. CERTFR-2024-ALE-001 ou CERTFR-2024-AVI-0012.
_ID_PATTERN = re.compile(r"(CERTFR-\d{4}-(?:ALE|AVI)-\d+)", re.IGNORECASE)


def _extract_id(link: str) -> Optional[str]:
    """Extrait l'identifiant ANSSI depuis le lien du bulletin."""
    match = _ID_PATTERN.search(link or "")
    return match.group(1).upper() if match else None


def json_url(link: str) -> str:
    """Construit l'URL du JSON d'un bulletin (ajout de ``json/`` au lien)."""
    return link.rstrip("/") + "/json/"


def _parse_feed(url: str, bulletin_type: str) -> list[dict]:
    """Parse un flux RSS et renvoie la liste des bulletins normalisés."""
    feed = feedparser.parse(url)
    bulletins: list[dict] = []
    for entry in feed.entries:
        link = entry.get("link", "")
        bulletin_id = _extract_id(link)
        if bulletin_id is None:
            # Entrée sans identifiant exploitable : on l'ignore proprement.
            continue
        bulletins.append(
            {
                "id_anssi": bulletin_id,
                "titre_anssi": entry.get("title", ""),
                "type_bulletin": bulletin_type,
                "date_publication": entry.get("published", ""),
                "lien_bulletin": link,
                "json_url": json_url(link),
            }
        )
    return bulletins


def fetch_bulletins() -> list[dict]:
    """Récupère tous les bulletins des flux avis + alertes ANSSI."""
    bulletins = _parse_feed(config.FEED_AVIS, "Avis")
    bulletins += _parse_feed(config.FEED_ALERTE, "Alerte")
    return bulletins
