"""Étape 3 : enrichissement des CVE via les API MITRE (CVSS, CWE) et EPSS.

Toutes les extractions sont défensives : un champ absent ne casse pas le
pipeline mais renvoie ``None`` (numérique) ou ``"Non disponible"`` (texte).

Le dump local fourni (section 8 du sujet) contient déjà les réponses MITRE et
EPSS pour chaque CVE sous ``data/mitre/<cve_id>`` et ``data/first/<cve_id>``
(sans extension). On les lit en priorité ; le réseau ne sert que de repli
pour une CVE absente du dump.
"""

import json
from typing import Optional

from . import config
from .http_client import get_json

UNAVAILABLE = "Non disponible"


def _read_local(directory, cve_id: str) -> Optional[dict]:
    path = directory / cve_id
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _clean(value: Optional[str]) -> str:
    """Normalise une valeur texte ; ``"n/a"`` et vide deviennent UNAVAILABLE."""
    if not value or str(value).strip().lower() in {"n/a", "na", "unknown", "none"}:
        return UNAVAILABLE
    return str(value).strip()


def _mitre_cache(cve_id: str):
    return config.CACHE_MITRE_DIR / f"{cve_id}.json"


def _first_cache(cve_id: str):
    return config.CACHE_FIRST_DIR / f"{cve_id}.json"


def _iter_metrics(data: dict):
    """Génère tous les blocs ``metrics`` présents (conteneurs cna et adp)."""
    containers = data.get("containers", {}) or {}
    cna = containers.get("cna", {}) or {}
    for metric in cna.get("metrics", []) or []:
        yield metric
    for adp in containers.get("adp", []) or []:
        for metric in adp.get("metrics", []) or []:
            yield metric


def _extract_cvss(data: dict) -> Optional[float]:
    """Cherche un baseScore CVSS, quelle que soit la version (v3.1, v3.0, v4, v2)."""
    cvss_keys = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV3", "cvssV2_0", "cvssV2")
    for metric in _iter_metrics(data):
        for key in cvss_keys:
            block = metric.get(key)
            if isinstance(block, dict) and "baseScore" in block:
                try:
                    return float(block["baseScore"])
                except (TypeError, ValueError):
                    continue
    return None


def _extract_cwe(data: dict) -> tuple[str, str]:
    """Renvoie (cweId, description) du premier problemType exploitable."""
    cna = (data.get("containers", {}) or {}).get("cna", {}) or {}
    for problem in cna.get("problemTypes", []) or []:
        for desc in problem.get("descriptions", []) or []:
            cwe_id = desc.get("cweId")
            description = desc.get("description")
            if cwe_id:
                return cwe_id, _clean(description)
    return UNAVAILABLE, UNAVAILABLE


def _extract_description(data: dict) -> str:
    cna = (data.get("containers", {}) or {}).get("cna", {}) or {}
    for desc in cna.get("descriptions", []) or []:
        value = desc.get("value")
        if value:
            return _clean(value)
    return UNAVAILABLE


def _extract_affected(data: dict) -> list[dict]:
    """Liste des produits affectés : vendor, product, versions affectées."""
    cna = (data.get("containers", {}) or {}).get("cna", {}) or {}
    affected: list[dict] = []
    for product in cna.get("affected", []) or []:
        versions = [
            v.get("version")
            for v in (product.get("versions", []) or [])
            if v.get("status") == "affected" and v.get("version")
        ]
        affected.append(
            {
                "vendor": _clean(product.get("vendor")),
                "product": _clean(product.get("product")),
                "versions": versions,
            }
        )
    return affected


def enrich_mitre(cve_id: str) -> dict:
    """Enrichit une CVE via le dump local MITRE, ou l'API en repli."""
    data = _read_local(config.LOCAL_MITRE_DIR, cve_id)
    if data is None and not config.OFFLINE_ONLY:
        data = get_json(config.MITRE_API.format(cve_id=cve_id), _mitre_cache(cve_id))
    if not data:
        return {
            "description": UNAVAILABLE,
            "cvss_score": None,
            "cwe": UNAVAILABLE,
            "cwe_desc": UNAVAILABLE,
            "affected": [],
        }
    cwe, cwe_desc = _extract_cwe(data)
    return {
        "description": _extract_description(data),
        "cvss_score": _extract_cvss(data),
        "cwe": cwe,
        "cwe_desc": cwe_desc,
        "affected": _extract_affected(data),
    }


def enrich_epss(cve_id: str) -> Optional[float]:
    """Renvoie le score EPSS (probabilité d'exploitation) ou ``None``."""
    data = _read_local(config.LOCAL_FIRST_DIR, cve_id)
    if data is None and not config.OFFLINE_ONLY:
        data = get_json(config.EPSS_API.format(cve_id=cve_id), _first_cache(cve_id))
    if not data:
        return None
    epss_data = data.get("data", []) or []
    if not epss_data:
        return None
    try:
        return float(epss_data[0]["epss"])
    except (KeyError, TypeError, ValueError):
        return None
