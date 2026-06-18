"""Étape 2 : identification des CVE référencées dans un bulletin ANSSI."""

import json
import re

from . import config
from .http_client import get_json

# Identifiant CVE : CVE-AAAA-NNNN (4 à 7 chiffres pour le numéro).
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


def _cache_path(bulletin_id: str):
    return config.CACHE_BULLETIN_DIR / f"{bulletin_id}.json"


def fetch_bulletin_json(bulletin: dict) -> dict | None:
    """Télécharge (ou lit en cache) le JSON détaillé d'un bulletin."""
    return get_json(bulletin["json_url"], _cache_path(bulletin["id_anssi"]))


def extract_cves(bulletin_json: dict) -> list[str]:
    """Extrait la liste dédoublonnée des CVE d'un bulletin.

    Combine deux sources pour la robustesse :
    - la clé ``cves`` (liste de dicts ``name``/``url``) ;
    - un repli par regex sur l'ensemble du JSON sérialisé.
    """
    cves: set[str] = set()

    for item in bulletin_json.get("cves", []) or []:
        name = item.get("name") if isinstance(item, dict) else None
        if name and _CVE_PATTERN.fullmatch(name):
            cves.add(name)

    # Repli regex : capture d'éventuelles CVE mentionnées ailleurs dans le JSON.
    cves.update(_CVE_PATTERN.findall(json.dumps(bulletin_json)))

    return sorted(cves)
