"""Étape 1 (variante locale) : lecture des bulletins ANSSI déjà téléchargés.

Le sujet (section 8) fournit un dump local des avis/alertes CERT-FR sous
``data/Avis/`` et ``data/alertes/`` : un fichier par bulletin, sans extension,
contenant exactement le JSON détaillé qu'on obtiendrait via
``<lien_bulletin>/json/``. On n'a donc plus besoin du flux RSS (qui ne donne
que les bulletins les plus récents) ni d'une requête réseau séparée pour le
détail : chaque fichier local fait à la fois office d'étape 1 (métadonnées)
et d'étape 2 (CVE listées dans ``cves``).
"""

import json
import re

from . import config

_BASE_URLS = {"Avis": "https://www.cert.ssi.gouv.fr/avis/", "Alerte": "https://www.cert.ssi.gouv.fr/alerte/"}

# Année dans un identifiant ANSSI, ex. CERTFR-2024-AVI-0012 -> 2024.
_YEAR_PATTERN = re.compile(r"CERTFR-(\d{4})-")


def _year_of(bulletin_id: str):
    """Renvoie l'année (int) d'un identifiant ANSSI, ou None si introuvable."""
    match = _YEAR_PATTERN.search(bulletin_id or "")
    return int(match.group(1)) if match else None


def _load_bulletin(path, bulletin_type: str) -> dict | None:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    bulletin_id = data.get("reference") or path.name
    revisions = data.get("revisions") or []
    # Date de publication = date de la première révision ("Version initiale").
    # Défensif : une révision peut être malformée (clé absente).
    date_publication = ""
    if revisions and isinstance(revisions[0], dict):
        date_publication = revisions[0].get("revision_date", "")
    link = f"{_BASE_URLS[bulletin_type]}{bulletin_id}/"

    return {
        "id_anssi": bulletin_id,
        "titre_anssi": data.get("title", ""),
        "type_bulletin": bulletin_type,
        "date_publication": date_publication,
        "lien_bulletin": link,
        "bulletin_json": data,
    }


def fetch_bulletins(years=None) -> list[dict]:
    """Charge les avis et alertes depuis le dump local fourni.

    ``years`` : itérable d'années à conserver (ex. ``(2024, 2025, 2026)``) pour
    borner le périmètre et la taille du CSV. ``None`` = tous les bulletins.
    """
    allowed = set(years) if years is not None else None
    bulletins: list[dict] = []
    for directory, bulletin_type in (
        (config.LOCAL_AVIS_DIR, "Avis"),
        (config.LOCAL_ALERTES_DIR, "Alerte"),
    ):
        for path in sorted(directory.iterdir()):
            if not path.is_file():
                continue
            if allowed is not None and _year_of(path.name) not in allowed:
                continue
            bulletin = _load_bulletin(path, bulletin_type)
            if bulletin is not None:
                bulletins.append(bulletin)
    return bulletins
